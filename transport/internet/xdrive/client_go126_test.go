//go:build !go1.27

package xdrive

import (
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

// before Go 1.27 an h1 response over a uTLS or Xray conn has no TLS state
func echAccepted(resp *http.Response) (accepted, ok bool) {
	if resp.TLS == nil {
		return false, false
	}
	return resp.TLS.ECHAccepted, true
}

func h2PingTimeout(client *http.Client) time.Duration {
	return client.Transport.(*serviceTransport).secure.(*legacySecureTransport).h2.(*http2.Transport).ReadIdleTimeout
}
