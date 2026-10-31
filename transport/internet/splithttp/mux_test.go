package splithttp_test

import (
	"context"
	"testing"

	. "github.com/xtls/xray-core/transport/internet/splithttp"
)

type fakeRoundTripper struct{}

func (f *fakeRoundTripper) IsClosed() bool {
	return false
}

func TestMaxConnections(t *testing.T) {
	xmuxConfig := XmuxConfig{
		MaxConnections: &RangeConfig{From: 4, To: 4},
	}

	xmuxManager := NewXmuxManager(xmuxConfig, func() XmuxConn {
		return &fakeRoundTripper{}
	})

	xmuxClients := make(map[interface{}]struct{})
	for i := 0; i < 8; i++ {
		xmuxClients[xmuxManager.GetXmuxClient(context.Background())] = struct{}{}
	}

	if len(xmuxClients) != 4 {
		t.Error("did not get 4 distinct clients, got ", len(xmuxClients))
	}
}

func TestCMaxReuseTimes(t *testing.T) {
	xmuxConfig := XmuxConfig{
		CMaxReuseTimes: &RangeConfig{From: 2, To: 2},
	}

	xmuxManager := NewXmuxManager(xmuxConfig, func() XmuxConn {
		return &fakeRoundTripper{}
	})

	xmuxClients := make(map[interface{}]struct{})
	for i := 0; i < 64; i++ {
		xmuxClients[xmuxManager.GetXmuxClient(context.Background())] = struct{}{}
	}

	if len(xmuxClients) != 32 {
		t.Error("did not get 32 distinct clients, got ", len(xmuxClients))
	}
}

func TestMaxConcurrency(t *testing.T) {
	xmuxConfig := XmuxConfig{
		MaxConcurrency: &RangeConfig{From: 2, To: 2},
	}

	xmuxManager := NewXmuxManager(xmuxConfig, func() XmuxConn {
		return &fakeRoundTripper{}
	})

	xmuxClients := make(map[interface{}]struct{})
	for i := 0; i < 64; i++ {
		xmuxClient := xmuxManager.GetXmuxClient(context.Background())
		xmuxClient.AddRunning()
		xmuxClients[xmuxClient] = struct{}{}
	}

	if len(xmuxClients) != 32 {
		t.Error("did not get 32 distinct clients, got ", len(xmuxClients))
	}
}

func TestDefault(t *testing.T) {
	xmuxConfig := XmuxConfig{}

	xmuxManager := NewXmuxManager(xmuxConfig, func() XmuxConn {
		return &fakeRoundTripper{}
	})

	xmuxClients := make(map[interface{}]struct{})
	for i := 0; i < 64; i++ {
		xmuxClient := xmuxManager.GetXmuxClient(context.Background())
		xmuxClient.AddRunning()
		xmuxClients[xmuxClient] = struct{}{}
	}

	if len(xmuxClients) != 1 {
		t.Error("did not get 1 distinct clients, got ", len(xmuxClients))
	}
}

func TestGetExistingXmuxClient(t *testing.T) {
	xmuxConfig := XmuxConfig{
		MaxConnections: &RangeConfig{From: 2, To: 2},
	}

	xmuxManager := NewXmuxManager(xmuxConfig, func() XmuxConn {
		return &fakeRoundTripper{}
	})

	if xmuxManager.GetExistingXmuxClient(context.Background()) != nil {
		t.Error("got a client without creating one")
	}
	xmuxClient := xmuxManager.GetXmuxClient(context.Background())
	for i := 0; i < 4; i++ {
		if xmuxManager.GetExistingXmuxClient(context.Background()) != xmuxClient {
			t.Error("did not reuse the existing client")
		}
	}
}

type closeCounter struct {
	closed int
}

func (c *closeCounter) IsClosed() bool {
	return false
}

func (c *closeCounter) Close() error {
	c.closed++
	return nil
}

func TestClose(t *testing.T) {
	xmuxConfig := XmuxConfig{
		MaxConnections: &RangeConfig{From: 2, To: 2},
	}

	xmuxManager := NewXmuxManager(xmuxConfig, func() XmuxConn {
		return &closeCounter{}
	})

	idle := xmuxManager.GetXmuxClient(context.Background())
	running := xmuxManager.GetXmuxClient(context.Background())
	running.AddRunning()

	xmuxManager.Close()

	if closed := idle.XmuxConn.(*closeCounter).closed; closed != 1 {
		t.Error("idle client closed ", closed, " times, want 1")
	}
	if closed := running.XmuxConn.(*closeCounter).closed; closed != 0 {
		t.Error("running client closed before its request was done")
	}
	running.DoneRunning()
	if closed := running.XmuxConn.(*closeCounter).closed; closed != 1 {
		t.Error("running client closed ", closed, " times after its request was done, want 1")
	}
	if xmuxManager.GetExistingXmuxClient(context.Background()) != nil {
		t.Error("got a client from a closed manager")
	}
}
