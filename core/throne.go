package core

import (
	"context"

	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/transport/internet"
)

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

// SetEgress binds this instance's outbound egress sockets to the named physical
// interface and stamps them with the given fwmark. Call it after New (before or
// after Start) and again whenever the default route moves — new dials pick up the
// change. Passing "" for name reports that no default interface is available,
// which makes non-loopback dials fail rather than leak onto the default route (the
// tun, under TUN); passing 0 for mark leaves each outbound's own sockopt.mark
// alone. Both are written onto each outbound's SocketConfig, so they are honored
// on every dial path. Under a sing-box TUN the mark is what exempts egress from
// auto_redirect's nftables OUTPUT chain, which interface binding does not affect —
// see ThroneWiring. Instances left unwired (e.g. latency/URL tests) keep the
// default unbound, unmarked behavior.
func (s *Instance) SetEgress(name string, mark uint32) {
	if s.throneWiring != nil {
		s.throneWiring.SetEgress(name, mark)
	}
}

// A nil resolver disables outbound resolution, so the instance behaves as if no domain strategy were set.
func (s *Instance) SetOutboundDNS(resolver dns.Client, strategy internet.DomainStrategy) {
	if s.throneWiring == nil {
		return
	}
	s.throneWiring.SetDNS(resolver, strategy)
}

// ClearThroneWiring removes all Throne egress wiring from this instance.
func (s *Instance) ClearThroneWiring() {
	if s.throneWiring != nil {
		s.throneWiring.Clear()
	}
}
