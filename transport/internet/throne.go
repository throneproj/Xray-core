package internet

import (
	"context"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"google.golang.org/protobuf/proto"
)

// ThroneWiring carries per-instance egress wiring that Throne injects onto a Xray
// instance after core.New (before Start): the physical network interface that
// outbound sockets bind their egress to, and a dedicated DNS resolver
// ("throne-dns") plus a domain strategy used to resolve outbound server domains.
// A pointer to this struct is seeded into the Xray instance context (see
// core.initInstanceWithConfig) so it can be read without importing core, which
// would be an import cycle.
//
// The egress interface is written straight onto each outbound handler's
// SocketConfig (RegisterOutbound), so Xray's native, per-OS socket-option apply
// binds it on EVERY dial path — including ones that build and dial the socket
// themselves, such as the Happy Eyeballs racer. This is deliberately not done by
// intercepting the shared dial choke point (DialSystem), whose branches can
// return before a bind step would run and so would silently miss such paths (and
// any new dial path Xray adds later).
//
// The bound interface is changeable at runtime (SetEgressInterface): when the
// default route moves to another NIC, new dials pick up the change; existing
// connections are not migrated, matching sing-box's auto_detect_interface.
//
// All wiring is optional. Instances that never register an outbound or set an
// interface (validation, latency/URL tests) simply dial unbound, exactly as
// before this mechanism existed.
type ThroneWiring struct {
	mu           sync.RWMutex
	iface        string
	bindActive   bool
	boundStreams []*MemoryStreamConfig
	dnsResolver  dns.Client
	dnsStrategy  DomainStrategy
}

// RegisterOutbound records an outbound handler's stream settings so its egress
// socket is bound to the wiring's interface. Called once per outbound when the
// handler is built. If an interface is already set it is applied immediately;
// otherwise it is applied on the next SetEgressInterface.
func (w *ThroneWiring) RegisterOutbound(mss *MemoryStreamConfig) {
	if mss == nil {
		return
	}
	w.mu.Lock()
	w.boundStreams = append(w.boundStreams, mss)
	if w.bindActive {
		bindStreamInterface(mss, w.iface)
	}
	w.mu.Unlock()
}

// SetEgressInterface sets the interface every registered outbound binds its
// egress to, and marks binding active. Passing "" reports that no default
// interface is currently available: outbounds are left unbound and DialSystem
// refuses non-loopback dials (see bindState) instead of leaking egress onto the
// default route — which, under TUN, is the tun itself. Safe to call at runtime
// as the default route changes.
func (w *ThroneWiring) SetEgressInterface(name string) {
	w.mu.Lock()
	w.iface = name
	w.bindActive = true
	for _, mss := range w.boundStreams {
		bindStreamInterface(mss, name)
	}
	w.mu.Unlock()
}

// bindStreamInterface points mss.SocketSettings at a copy that carries iface,
// leaving every other socket option intact. The whole *SocketConfig pointer is
// replaced in a single write rather than mutating the live config's Interface
// string in place, so a concurrent dial reading mss.SocketSettings observes
// either the old config or the new one as a whole, never a half-updated one.
func bindStreamInterface(mss *MemoryStreamConfig, iface string) {
	var sc *SocketConfig
	if mss.SocketSettings != nil {
		sc = proto.Clone(mss.SocketSettings).(*SocketConfig)
	} else {
		sc = &SocketConfig{}
	}
	sc.Interface = iface
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
	w.bindActive = false
	w.dnsResolver = nil
	w.dnsStrategy = DomainStrategy_AS_IS
	w.mu.Unlock()
}

// bindState reports the current egress interface and whether binding is active,
// for the DialSystem no-interface guard. active is true once SetEgressInterface
// has been called; a "" name then means "no default interface right now".
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
