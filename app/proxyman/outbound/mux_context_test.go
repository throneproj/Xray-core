package outbound

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type muxContextProbe func(context.Context)

func (p muxContextProbe) Process(ctx context.Context, _ *transport.Link, _ internet.Dialer) error {
	p(ctx)
	return nil
}

func TestMuxWorkerKeepsInstance(t *testing.T) {
	instance := new(core.Instance)
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), core.XrayKey(1), instance))
	got := make(chan bool, 1)
	manager := new(Handler).newMuxClient(ctx, muxContextProbe(func(ctx context.Context) {
		got <- core.FromContext(ctx) == instance && ctx.Err() == nil
	}), 8, 0)
	cancel() // The shared worker must not inherit a request's cancellation.
	worker, err := manager.Picker.PickAvailable()
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	select {
	case ok := <-got:
		if !ok {
			t.Fatal("worker lost the outbound instance or inherited cancellation")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not start")
	}
}
