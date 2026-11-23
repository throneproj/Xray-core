package internet_test

import (
	"context"
	"errors"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

func TestProbeCancellationClosesDetachedDial(t *testing.T) {
	listener, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	owner, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := internet.ContextWithThroneWiring(context.Background(), &internet.ThroneWiring{Lifetime: owner})
	dest := net.TCPDestination(net.LocalHostIP, net.Port(listener.Addr().(*stdnet.TCPAddr).Port))
	conn, err := internet.DialSystem(ctx, dest, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	cancel()

	// A blocked handshake on an already connected socket must see the close.
	if err := peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	if _, err := peer.Read(buf[:]); err == nil {
		t.Fatal("expected the probe socket to close")
	} else if timeout, ok := err.(stdnet.Error); ok && timeout.Timeout() {
		t.Fatal("probe socket remained open")
	}
	if again, err := internet.DialSystem(ctx, dest, nil); !errors.Is(err, context.Canceled) {
		if again != nil {
			again.Close()
		}
		t.Fatalf("dial after probe cancellation: got %v", err)
	}
}
