package core

import (
	"context"

	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport/internet"
)

// outboundDNSInstanceAware is implemented by throne-dns resolvers that need a
// context carrying this Instance. Xray's app/dns nameservers require the Instance
// in the query context (toDnsContext -> ToBackgroundDetachedContext ->
// MustFromContext); a resolver built outside the instance (throne.NewResolver)
// cannot obtain it on its own, so SetOutboundDNS injects one. It is declared as a
// local interface so core need not import the throne package, which would be an
// import cycle via app/dns.
type outboundDNSInstanceAware interface {
	SetInstanceContext(ctx context.Context)
}

func init() {
	// Let transport/internet recover an instance's egress wiring from the Instance
	// carried in a dial context. This is the robust fallback for when the directly
	// seeded wiring context value has been dropped — e.g. app/dns rebuilds a
	// background-detached context (ToBackgroundDetachedContext) keeping only the
	// Instance. It holds for any custom-config shape because the Instance is always
	// present in these contexts (Xray relies on it itself).
	internet.SetInstanceWiringResolver(func(ctx context.Context) *internet.ThroneWiring {
		if inst := FromContext(ctx); inst != nil {
			return inst.throneWiring
		}
		return nil
	})

	// Same inversion for the two features the dial path needs. Reading them off the
	// instance keeps a second instance (Throne builds one per URL-test batch) from
	// taking over resolution and dialerProxy lookups for the one already running,
	// which is what the InitSystemDialer globals did.
	internet.SetInstanceFeatureResolver(func(ctx context.Context) (dns.Client, outbound.Manager) {
		inst := FromContext(ctx)
		if inst == nil {
			return nil, nil
		}
		client, _ := inst.GetFeature(dns.ClientType()).(dns.Client)
		manager, _ := inst.GetFeature(outbound.ManagerType()).(outbound.Manager)
		return client, manager
	})
}

// SetEgressInterface binds this instance's outbound egress sockets to the named
// physical interface. Call it after New (before or after Start) and again
// whenever the default route moves — new dials pick up the change. Passing ""
// reports that no default interface is available, which makes non-loopback dials
// fail rather than leak onto the default route (the tun, under TUN). The bind is
// written onto each outbound's SocketConfig, so it is honored on every dial path.
// Instances left unwired (e.g. latency/URL tests) keep the default un-bound
// behavior.
func (s *Instance) SetEgressInterface(name string) {
	if s.throneWiring != nil {
		s.throneWiring.SetEgressInterface(name)
	}
}

// SetOutboundDNS wires the resolver and strategy used to resolve outbound server
// domains (Throne's "throne-dns"). Build the resolver with throne.NewResolver.
// Passing a nil resolver disables outbound resolution, so the instance behaves
// as if no domain strategy were set — the fallback used by test instances.
func (s *Instance) SetOutboundDNS(resolver dns.Client, strategy internet.DomainStrategy) {
	if s.throneWiring == nil {
		return
	}
	// Hand the resolver a context carrying this Instance, which app/dns needs to
	// build its query context. Without it, the first outbound-domain lookup panics.
	if aware, ok := resolver.(outboundDNSInstanceAware); ok {
		aware.SetInstanceContext(toContext(context.Background(), s))
	}
	s.throneWiring.SetDNS(resolver, strategy)
}

// ClearThroneWiring removes all Throne egress wiring from this instance.
func (s *Instance) ClearThroneWiring() {
	if s.throneWiring != nil {
		s.throneWiring.Clear()
	}
}
