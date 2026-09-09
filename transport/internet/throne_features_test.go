package internet

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
)

// Guards the per-instance feature lookup against a regression to the process-global
// dnsClient/obm: Throne runs a second Xray instance for every URL-test batch, and
// core.New overwrites those globals, so a dial that reads them resolves through
// whichever instance was built last (and through a closed one after the test ends).

type fakeDNSClient struct{ id string }

func (c *fakeDNSClient) Type() interface{} { return dns.ClientType() }
func (c *fakeDNSClient) Start() error      { return nil }
func (c *fakeDNSClient) Close() error      { return nil }
func (c *fakeDNSClient) LookupIP(string, dns.IPOption) ([]net.IP, uint32, error) {
	return nil, 0, nil
}

type fakeOutboundManager struct{ id string }

func (m *fakeOutboundManager) Type() interface{}                                  { return outbound.ManagerType() }
func (m *fakeOutboundManager) Start() error                                       { return nil }
func (m *fakeOutboundManager) Close() error                                       { return nil }
func (m *fakeOutboundManager) GetHandler(string) outbound.Handler                 { return nil }
func (m *fakeOutboundManager) GetDefaultHandler() outbound.Handler                { return nil }
func (m *fakeOutboundManager) AddHandler(context.Context, outbound.Handler) error { return nil }
func (m *fakeOutboundManager) RemoveHandler(context.Context, string) error        { return nil }
func (m *fakeOutboundManager) ListHandlers(context.Context) []outbound.Handler    { return nil }

type instanceKey struct{}

// restores the package state the test mutates, so ordering with other tests in this
// package cannot leak.
func withResolver(t *testing.T, f func(context.Context) (dns.Client, outbound.Manager)) {
	t.Helper()
	prevResolver := instanceFeatureResolver
	prevClient, prevManager := systemDialerFeatures()
	t.Cleanup(func() {
		instanceFeatureResolver = prevResolver
		InitSystemDialer(prevClient, prevManager)
	})
	instanceFeatureResolver = f
}

func TestInstanceFeaturesPreferInstanceOverGlobals(t *testing.T) {
	globalClient := &fakeDNSClient{id: "global"}
	globalManager := &fakeOutboundManager{id: "global"}
	instClient := &fakeDNSClient{id: "instance"}
	instManager := &fakeOutboundManager{id: "instance"}

	withResolver(t, func(ctx context.Context) (dns.Client, outbound.Manager) {
		if ctx.Value(instanceKey{}) == nil {
			return nil, nil
		}
		return instClient, instManager
	})
	InitSystemDialer(globalClient, globalManager)

	client, manager := instanceFeatures(context.WithValue(context.Background(), instanceKey{}, true))
	if client != dns.Client(instClient) {
		t.Errorf("dns client = %v, want the instance's", client)
	}
	if manager != outbound.Manager(instManager) {
		t.Errorf("outbound manager = %v, want the instance's", manager)
	}

	// A context carrying no instance (config validation, standalone helpers) keeps
	// the pre-existing global behavior.
	client, manager = instanceFeatures(context.Background())
	if client != dns.Client(globalClient) {
		t.Errorf("fallback dns client = %v, want the global", client)
	}
	if manager != outbound.Manager(globalManager) {
		t.Errorf("fallback outbound manager = %v, want the global", manager)
	}
}

func TestInstanceFeaturesFallBackPerFeature(t *testing.T) {
	globalClient := &fakeDNSClient{id: "global"}
	globalManager := &fakeOutboundManager{id: "global"}
	instClient := &fakeDNSClient{id: "instance"}

	// An instance can carry one feature and not the other; the missing one must not
	// drag the present one down to the global.
	withResolver(t, func(context.Context) (dns.Client, outbound.Manager) {
		return instClient, nil
	})
	InitSystemDialer(globalClient, globalManager)

	client, manager := instanceFeatures(context.Background())
	if client != dns.Client(instClient) {
		t.Errorf("dns client = %v, want the instance's", client)
	}
	if manager != outbound.Manager(globalManager) {
		t.Errorf("outbound manager = %v, want the global", manager)
	}
}

func TestInstanceFeaturesWithoutResolver(t *testing.T) {
	globalClient := &fakeDNSClient{id: "global"}
	globalManager := &fakeOutboundManager{id: "global"}

	// package core registers the resolver at init; a build without it must still dial.
	withResolver(t, nil)
	InitSystemDialer(globalClient, globalManager)

	client, manager := instanceFeatures(context.Background())
	if client != dns.Client(globalClient) || manager != outbound.Manager(globalManager) {
		t.Errorf("got (%v, %v), want the globals", client, manager)
	}
}
