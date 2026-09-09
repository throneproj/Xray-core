package internet

import "testing"

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
