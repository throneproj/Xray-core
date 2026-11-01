//go:build go1.27

package xdrive

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/net"
)

func newSecureTransport(secure func(connsPerHost int) *http.Transport, _ func(ctx context.Context, network, addr string) (net.Conn, error),
	_ time.Duration, maxConns int, h1Hosts *sync.Map) http.RoundTripper {
	return &secureTransport{h2: secure(1), h1: secure(maxConns), h1Hosts: h1Hosts}
}
