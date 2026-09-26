package internet

import (
	"context"
	"slices"
	"testing"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
)

func TestIsLoopbackAddrPort(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:443":     true,
		"127.1.1.1:53":      true,
		"[::1]:443":         true,
		"127.0.0.1":         true,
		"::1":               true,
		"1.2.3.4:443":       false,
		"[2001:db8::1]:443": false,
		"example.com:443":   false,
		"":                  false,
	}
	for address, want := range cases {
		if got := IsLoopbackAddrPort(address); got != want {
			t.Errorf("IsLoopbackAddrPort(%q) = %v, want %v", address, got, want)
		}
	}
}

type answerDNSClient struct{ ips []net.IP }

func (c *answerDNSClient) Type() interface{} { return dns.ClientType() }
func (c *answerDNSClient) Start() error      { return nil }
func (c *answerDNSClient) Close() error      { return nil }
func (c *answerDNSClient) LookupIP(string, dns.IPOption) ([]net.IP, uint32, error) {
	return c.ips, 0, nil
}

type stubConn struct{ net.Conn }

type recordingDialer struct {
	fail   map[string]bool
	dialed []string
}

func (d *recordingDialer) Dial(_ context.Context, _ net.Address, dest net.Destination, _ *SocketConfig) (net.Conn, error) {
	address := dest.Address.String()
	d.dialed = append(d.dialed, address)
	if d.fail[address] {
		return nil, errors.New("unreachable ", address)
	}
	return stubConn{}, nil
}

func (d *recordingDialer) DestIpAddress() net.IP { return nil }

// #1892: a throne-dns answer is dialed in order, so connections stay on its first address.
func TestThroneResolvedDialKeepsAnswerOrder(t *testing.T) {
	prev := effectiveSystemDialer
	t.Cleanup(func() { effectiveSystemDialer = prev })

	w := &ThroneWiring{}
	w.SetDNS(&answerDNSClient{ips: []net.IP{
		net.ParseIP("192.0.2.1"),
		net.ParseIP("192.0.2.2"),
		net.ParseIP("192.0.2.3"),
	}}, DomainStrategy_USE_IP)
	ctx := ContextWithThroneWiring(context.Background(), w)
	dest := net.TCPDestination(net.DomainAddress("example.com"), 443)

	cases := []struct {
		name   string
		dials  int
		fail   []string
		dialed []string
		err    bool
	}{
		{"stays on the first address", 8, nil, slices.Repeat([]string{"192.0.2.1"}, 8), false},
		{"falls back in order", 1, []string{"192.0.2.1", "192.0.2.2"}, []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}, false},
		{"all fail", 1, []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}, []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}, true},
	}
	for _, c := range cases {
		d := &recordingDialer{fail: make(map[string]bool)}
		for _, address := range c.fail {
			d.fail[address] = true
		}
		UseAlternativeSystemDialer(d)
		var err error
		for range c.dials {
			_, err = DialSystem(ctx, dest, nil)
		}
		if (err != nil) != c.err || !slices.Equal(d.dialed, c.dialed) {
			t.Errorf("%s: dialed %v, err %v; want %v, err = %v", c.name, d.dialed, err, c.dialed, c.err)
		}
	}
}
