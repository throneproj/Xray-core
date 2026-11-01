//go:build go1.27

package xdrive

import (
	"net/http"
	"time"
)

func echAccepted(resp *http.Response) (accepted, ok bool) {
	return resp.TLS.ECHAccepted, true
}

func h2PingTimeout(client *http.Client) time.Duration {
	return client.Transport.(*serviceTransport).secure.(*secureTransport).h2.(*http.Transport).HTTP2.SendPingTimeout
}
