package internet

import (
	"context"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"google.golang.org/protobuf/proto"
)

// ThroneWiring carries per-instance egress wiring that Throne injects onto a Xray
// instance after core.New (before Start): the egress conditions outbound sockets
// dial under — the physical network interface they bind to and the fwmark they
// carry — plus a dedicated DNS resolver ("throne-dns") and a domain strategy used
// to resolve outbound server domains. A pointer to this struct is seeded into the
// Xray instance context (see core.initInstanceWithConfig) so it can be read
// without importing core, which would be an import cycle.
//
// Interface and mark are two halves of one thing and are always set together
// (SetEgress). Under a sing-box TUN the interface alone is not enough: binding
// picks the NIC a packet leaves on, but sing-tun's auto_redirect installs an
// nftables OUTPUT chain that rewrites by destination address without ever looking
// at the outgoing interface, and whose only exemption is a socket mark equal to
// tun.DefaultAutoRedirectOutputMark. sing-box marks its own dialers with it; egress
// that is bound but unmarked is DNAT'd straight back into the TUN, handed to the
// proxy outbound and dialed again, which loops. Mark 0 means "nothing to exempt
// from" and leaves a config's own sockopt.mark untouched.
//
// Both are written straight onto each outbound handler's SocketConfig
// (RegisterOutbound), where Xray's native, per-OS socket-option apply consumes
// them side by side (applyOutboundSocketOptions), so they are honored on EVERY
// dial path — including ones that build and dial the socket themselves, such as
// the Happy Eyeballs racer, and transports that carry their own stream settings,
// such as gRPC and splithttp's download config. This is deliberately not done by
// intercepting the shared dial choke point (DialSystem), whose branches can
// return before such a step would run and so would silently miss those paths (and
// any new dial path Xray adds later).
//
// The wiring is changeable at runtime (SetEgress): when the default route moves to
// another NIC, new dials pick up the change; existing connections are not
// migrated, matching sing-box's auto_detect_interface.
//
// All wiring is optional. Instances that never register an outbound or set egress
// (validation, latency/URL tests) simply dial unbound and unmarked, exactly as
// before this mechanism existed.
type ThroneWiring struct {
	mu           sync.RWMutex
	iface        string
	mark         uint32
	bindActive   bool
	boundStreams []*MemoryStreamConfig
	dnsResolver  dns.Client
	dnsStrategy  DomainStrategy
}

// RegisterOutbound records an outbound handler's stream settings so its egress
// socket takes the wiring's interface and mark. Called once per outbound when the
// handler is built. If egress is already set it is applied immediately; otherwise
// it is applied on the next SetEgress.
func (w *ThroneWiring) RegisterOutbound(mss *MemoryStreamConfig) {
	if mss == nil {
		return
	}
	w.mu.Lock()
	w.boundStreams = append(w.boundStreams, mss)
	if w.bindActive {
		bindStreamEgress(mss, w.iface, w.mark)
	}
	w.mu.Unlock()
}

// SetEgress sets the interface every registered outbound binds its egress to and
// the fwmark that egress carries, and marks binding active. Passing "" for name
// reports that no default interface is currently available: outbounds are left
// unbound and DialSystem refuses non-loopback dials (see bindState) instead of
// leaking egress onto the default route — which, under TUN, is the tun itself.
// Passing 0 for mark leaves each outbound's own sockopt.mark alone. Safe to call
// at runtime as the default route changes.
func (w *ThroneWiring) SetEgress(name string, mark uint32) {
	w.mu.Lock()
	w.iface = name
	w.mark = mark
	w.bindActive = true
	for _, mss := range w.boundStreams {
		bindStreamEgress(mss, name, mark)
	}
	w.mu.Unlock()
}

// bindStreamEgress points mss.SocketSettings at a copy that carries iface and
// mark, leaving every other socket option intact. The whole *SocketConfig pointer
// is replaced in a single write rather than mutating the live config's fields in
// place, so a concurrent dial reading mss.SocketSettings observes either the old
// config or the new one as a whole, never a half-updated one.
//
// A zero mark is not written: there is then no auto_redirect to be exempted from,
// and a custom config's own sockopt.mark must survive. A non-zero one does
// overwrite it, matching sing-box, which rejects a config combining routing_mark
// with tun.auto_redirect outright rather than honoring both.
func bindStreamEgress(mss *MemoryStreamConfig, iface string, mark uint32) {
	var sc *SocketConfig
	if mss.SocketSettings != nil {
		sc = proto.Clone(mss.SocketSettings).(*SocketConfig)
	} else {
		sc = &SocketConfig{}
	}
	sc.Interface = iface
	if mark != 0 {
		sc.Mark = int32(mark)
	}
	mss.SocketSettings = sc
}

// SetDNS sets (a nil resolver clears) the outbound domain resolver and strategy.
func (w *ThroneWiring) SetDNS(resolver dns.Client, strategy DomainStrategy) {
	w.mu.Lock()
	w.dnsResolver = resolver
	w.dnsStrategy = strategy
	w.mu.Unlock()
}

// Clear resets the DNS wiring and marks binding inactive. It does not rewrite
// already-registered outbounds; it is used only on teardown.
func (w *ThroneWiring) Clear() {
	w.mu.Lock()
	w.iface = ""
	w.mark = 0
	w.bindActive = false
	w.dnsResolver = nil
	w.dnsStrategy = DomainStrategy_AS_IS
	w.mu.Unlock()
}

// bindState reports the current egress interface and whether binding is active,
// for the DialSystem no-interface guard. active is true once SetEgress has been
// called; a "" name then means "no default interface right now".
func (w *ThroneWiring) bindState() (iface string, active bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.iface, w.bindActive
}

// dnsResolution returns the configured outbound resolver and strategy.
func (w *ThroneWiring) dnsResolution() (dns.Client, DomainStrategy) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.dnsResolver, w.dnsStrategy
}

type throneWiringKey struct{}

// ContextWithThroneWiring returns a context carrying the given wiring pointer.
func ContextWithThroneWiring(ctx context.Context, w *ThroneWiring) context.Context {
	return context.WithValue(ctx, throneWiringKey{}, w)
}

// instanceWiringResolver recovers a *ThroneWiring from the Xray Instance carried
// in a context. Package core registers it at init via SetInstanceWiringResolver;
// this package cannot import core (import cycle), so the dependency is inverted.
//
// It makes wiring lookup robust for ANY config shape: the directly-seeded context
// value (see initInstanceWithConfig) is only the fast path and can be dropped by
// context detachment — e.g. app/dns rebuilds a background context via
// core.ToBackgroundDetachedContext, keeping only the Instance, so DNS-driven
// dials (routing domainStrategy, a config `dns` section, arbitrary transports)
// would otherwise lose the wiring and leak onto the default route (the tun,
// under TUN). The Instance, by contrast, is a reliable carrier: Xray itself
// requires it in these contexts (it panics in MustFromContext otherwise), so
// resolving the wiring from the Instance works regardless of what a custom
// config triggers.
var instanceWiringResolver func(context.Context) *ThroneWiring

// SetInstanceWiringResolver registers the instance-based wiring fallback used by
// ThroneWiringFromContext. It is called once by package core at init.
func SetInstanceWiringResolver(f func(context.Context) *ThroneWiring) {
	instanceWiringResolver = f
}

// ThroneWiringFromContext returns the egress wiring for ctx: the directly-seeded
// context value when present (fast path), otherwise the wiring carried by the
// Xray Instance in ctx via the registered resolver. It returns nil only when ctx
// carries no Xray instance at all (e.g. a fully detached dial unrelated to any
// instance), where there is nothing to bind to anyway.
func ThroneWiringFromContext(ctx context.Context) *ThroneWiring {
	if w, ok := ctx.Value(throneWiringKey{}).(*ThroneWiring); ok {
		return w
	}
	if resolve := instanceWiringResolver; resolve != nil {
		return resolve(ctx)
	}
	return nil
}

// instanceFeatureResolver recovers the DNS client and outbound manager belonging to
// the Xray Instance carried in a dial context. Package core registers it at init via
// SetInstanceFeatureResolver; this package cannot import core (import cycle), so the
// dependency is inverted exactly as it is for instanceWiringResolver.
//
// The dial path used to read both from process globals that InitSystemDialer
// overwrites on every core.New. Throne builds a second instance for each URL-test
// batch, so those globals described the test instance while a profile was already
// running — and kept pointing at its features after it was closed. Reading them off
// the instance in ctx makes each instance resolve and dial through its own.
var instanceFeatureResolver func(context.Context) (dns.Client, outbound.Manager)

// SetInstanceFeatureResolver registers the instance-based feature lookup used by
// instanceFeatures. It is called once by package core at init.
func SetInstanceFeatureResolver(f func(context.Context) (dns.Client, outbound.Manager)) {
	instanceFeatureResolver = f
}

// instanceFeatures returns the DNS client and outbound manager to use for ctx.
// Either falls back to the InitSystemDialer globals on its own, so a context with
// no instance (config validation, tests) behaves as it did before.
func instanceFeatures(ctx context.Context) (dns.Client, outbound.Manager) {
	var (
		client  dns.Client
		manager outbound.Manager
	)
	if resolve := instanceFeatureResolver; resolve != nil {
		client, manager = resolve(ctx)
	}
	if client != nil && manager != nil {
		return client, manager
	}
	fallbackClient, fallbackManager := systemDialerFeatures()
	if client == nil {
		client = fallbackClient
	}
	if manager == nil {
		manager = fallbackManager
	}
	return client, manager
}

// isLoopbackDestination reports whether dest is a resolved loopback IP. Egress
// interface binding must be skipped for such destinations (e.g. the 127.x
// loopback SOCKS bridges between sing-box and Xray), because binding a loopback
// dial to a physical interface breaks the connection.
func isLoopbackDestination(dest net.Destination) bool {
	addr := dest.Address
	if addr == nil || addr.Family().IsDomain() {
		return false
	}
	return addr.IP().IsLoopback()
}

// ParseDomainStrategy maps an Xray-style domainStrategy string (e.g. "UseIP",
// "UseIPv4v6", "ForceIPv4") to the DomainStrategy enum. Unknown or empty values
// default to USE_IP, matching Throne's historical outbound-resolution default.
func ParseDomainStrategy(s string) DomainStrategy {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "asis":
		return DomainStrategy_AS_IS
	case "useip":
		return DomainStrategy_USE_IP
	case "useipv4", "useip4":
		return DomainStrategy_USE_IP4
	case "useipv6", "useip6":
		return DomainStrategy_USE_IP6
	case "useipv4v6", "useip46":
		return DomainStrategy_USE_IP46
	case "useipv6v4", "useip64":
		return DomainStrategy_USE_IP64
	case "forceip":
		return DomainStrategy_FORCE_IP
	case "forceipv4", "forceip4":
		return DomainStrategy_FORCE_IP4
	case "forceipv6", "forceip6":
		return DomainStrategy_FORCE_IP6
	case "forceipv4v6", "forceip46":
		return DomainStrategy_FORCE_IP46
	case "forceipv6v4", "forceip64":
		return DomainStrategy_FORCE_IP64
	default:
		return DomainStrategy_USE_IP
	}
}
