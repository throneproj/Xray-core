//go:build !go1.27

package xdrive

import (
	"context"
	gotls "crypto/tls"
	stderrors "errors"
	"net/http"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
)

var errNotH2 = stderrors.New("the server did not pick h2")

// Before Go 1.27, http.Transport reads the ALPN of a *crypto/tls.Conn only and
// speaks h1 on the uTLS and Xray conns of dialTLS even after the server picked
// h2, so h2 goes through x/net, which takes any conn, and other hosts to h1
func newSecureTransport(secure func(connsPerHost int) *http.Transport, dialTLS func(ctx context.Context, network, addr string) (net.Conn, error),
	keepAlive time.Duration, maxConns int, h1Hosts *sync.Map) http.RoundTripper {
	h2 := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *gotls.Config) (net.Conn, error) {
			conn, err := dialTLS(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if conn.(tls.Interface).NegotiatedProtocol() != http2.NextProtoTLS {
				conn.Close()
				return nil, errNotH2
			}
			return conn, nil
		},
		IdleConnTimeout: net.ConnIdleTimeout,
		ReadIdleTimeout: keepAlive,
	}
	return &legacySecureTransport{h2: h2, h1: secure(maxConns), h1Hosts: h1Hosts}
}

type legacySecureTransport struct {
	h2, h1  http.RoundTripper
	h1Hosts *sync.Map
}

func (t *legacySecureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if _, ok := t.h1Hosts.Load(r.URL.Host); ok {
		return t.h1.RoundTrip(r)
	}
	resp, err := t.h2.RoundTrip(r)
	// the refused dial left the request unsent
	if stderrors.Is(err, errNotH2) {
		t.h1Hosts.Store(r.URL.Host, true)
		return t.h1.RoundTrip(r)
	}
	return resp, err
}
