// Package throne provides the glue Throne uses to wire a Xray instance's egress
// after core.New: an outbound DNS resolver ("throne-dns") that resolves proxy
// server domains through sing-box's loopback DNS, and helpers for the dynamic
// interface finder. It lives outside package core (which cannot import app/dns
// without an import cycle) and is imported only by the embedding application.
package throne

import (
	"context"
	"sync"
	"time"

	dnsapp "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	dnsfeature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/pipe"
)

// lookupTimeout bounds a single outbound-domain resolution against the throne
// DNS. sing-box's loopback DNS answers promptly; a lost datagram must not hang
// the egress dial.
const lookupTimeout = 5 * time.Second

// resolveTTLCap bounds how long a resolved outbound server address is reused.
// This cache only exists to keep the per-dial cost down; sing-box's own DNS
// cache stays the authoritative one, and proxy server addresses do move.
const resolveTTLCap = 5 * time.Minute

// directDispatcher is a minimal routing.Dispatcher that dials the destination
// straight through the system dialer, bypassing the instance router. It backs
// the throne-dns resolver so DNS queries reach sing-box's loopback DNS-in port
// directly, replacing the freedom outbound + routing rule the config used to
// carry. It is only ever asked to reach that loopback address.
type directDispatcher struct{}

func (directDispatcher) Type() interface{} { return routing.DispatcherType() }
func (directDispatcher) Start() error      { return nil }
func (directDispatcher) Close() error      { return nil }

func (directDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	conn, err := internet.DialSystem(ctx, dest, nil)
	if err != nil {
		return nil, err
	}

	// link.Writer receives the DNS query and is drained into conn; conn's
	// replies are pumped into link.Reader.
	queryReader, queryWriter := pipe.New(pipe.OptionsFromContext(ctx)...)
	replyReader, replyWriter := pipe.New(pipe.OptionsFromContext(ctx)...)

	go func() {
		defer conn.Close()
		buf.Copy(queryReader, buf.NewWriter(conn))
	}()
	go func() {
		defer common.Close(replyWriter)
		buf.Copy(buf.NewReader(conn), replyWriter)
	}()

	return &transport.Link{Reader: replyReader, Writer: queryWriter}, nil
}

func (directDispatcher) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	conn, err := internet.DialSystem(ctx, dest, nil)
	if err != nil {
		return err
	}
	go func() {
		defer conn.Close()
		buf.Copy(link.Reader, buf.NewWriter(conn))
	}()
	go func() {
		defer common.Close(link.Writer)
		buf.Copy(buf.NewReader(conn), link.Writer)
	}()
	return nil
}

// resolver adapts a Xray UDP name server into a dns.Client used solely for
// resolving outbound server domains.
//
// It caches successful lookups itself and runs the underlying name server with
// app/dns caching switched off, because that cache also stores negative answers:
// an empty (NOERROR, no records) reply is kept for dns.DefaultTTL - 300s - and
// then replayed straight from cache, so no further query is ever sent. sing-box
// returns NOERROR/empty for ordinary reasons (a query type its strategy rejects,
// a censor injecting empty answers, a blip while the machine idles), and a single
// one of those used to wedge every outbound dial for five minutes with no way out
// short of rebuilding the instance.
type resolver struct {
	server dnsapp.Server
	// instanceCtx carries the owning Xray Instance. Xray's app/dns nameservers
	// derive their query context from it (toDnsContext -> ToBackgroundDetachedContext
	// -> MustFromContext), so it MUST be present or QueryIP panics with
	// "X is not in context.". It is injected by core.SetOutboundDNS (which knows
	// the instance) via SetInstanceContext when the resolver is attached, mirroring
	// how app/dns.(*DNS) keeps its construction context for QueryIP.
	instanceCtx context.Context

	cacheAccess sync.Mutex
	cache       map[resolveKey]resolveEntry
}

// resolveKey separates the A-only, AAAA-only and dual lookups of one domain: the
// requested address families decide what a cached answer is allowed to contain.
type resolveKey struct {
	domain string
	v4, v6 bool
}

type resolveEntry struct {
	ips    []net.IP
	expire time.Time
}

// SetInstanceContext receives a context carrying the owning Xray Instance,
// injected by core when this resolver is attached to an instance (see
// core.(*Instance).SetOutboundDNS). It must be called before LookupIP.
func (r *resolver) SetInstanceContext(ctx context.Context) {
	r.instanceCtx = ctx
}

// NewResolver builds a throne-dns resolver that resolves outbound server
// domains by querying the given UDP DNS address (sing-box's loopback DNS-in,
// e.g. "127.0.0.1:15353") directly. It reuses Xray's ClassicNameServer for the
// DNS protocol and a direct dialer so the query never traverses the proxy
// chain nor gets bound to the egress interface.
func NewResolver(address string) (dnsfeature.Client, error) {
	dest, err := net.ParseDestination("udp:" + address)
	if err != nil {
		return nil, err
	}
	server := dnsapp.NewClassicNameServer(dest, directDispatcher{}, true, false, 0, nil)
	return &resolver{server: server, cache: make(map[resolveKey]resolveEntry)}, nil
}

func (*resolver) Type() interface{} { return dnsfeature.ClientType() }
func (*resolver) Start() error      { return nil }
func (*resolver) Close() error      { return nil }

// LookupIP implements dns.Client.
func (r *resolver) LookupIP(domain string, option dnsfeature.IPOption) ([]net.IP, uint32, error) {
	key := resolveKey{domain: domain, v4: option.IPv4Enable, v6: option.IPv6Enable}
	if ips, ttl, ok := r.load(key); ok {
		return ips, ttl, nil
	}

	// The base context must carry the Xray Instance (app/dns requires it). It is
	// injected via SetInstanceContext; fall back to Background only defensively —
	// that path would panic inside app/dns, so a missing instance context is a
	// wiring bug, not a runtime condition.
	base := r.instanceCtx
	if base == nil {
		base = context.Background()
	}
	ctx, cancel := context.WithTimeout(base, lookupTimeout)
	defer cancel()

	ips, ttl, err := r.server.QueryIP(ctx, domain, option)
	// Only answers that resolved to something are kept. Failures - including an
	// empty response - are deliberately left uncached so the next dial retries.
	if err == nil && len(ips) > 0 {
		r.store(key, ips, ttl)
	}
	return ips, ttl, err
}

// load returns the cached addresses for key and their remaining TTL, if any is
// still live.
func (r *resolver) load(key resolveKey) ([]net.IP, uint32, bool) {
	r.cacheAccess.Lock()
	defer r.cacheAccess.Unlock()

	entry, ok := r.cache[key]
	if !ok {
		return nil, 0, false
	}
	remaining := time.Until(entry.expire)
	if remaining <= 0 {
		delete(r.cache, key)
		return nil, 0, false
	}
	ttl := uint32(remaining / time.Second)
	if ttl == 0 {
		ttl = 1
	}
	return append([]net.IP(nil), entry.ips...), ttl, true
}

func (r *resolver) store(key resolveKey, ips []net.IP, ttl uint32) {
	lifetime := time.Duration(ttl) * time.Second
	if lifetime <= 0 {
		return
	}
	if lifetime > resolveTTLCap {
		lifetime = resolveTTLCap
	}

	r.cacheAccess.Lock()
	defer r.cacheAccess.Unlock()

	if r.cache == nil {
		r.cache = make(map[resolveKey]resolveEntry)
	}
	// One entry per outbound server domain, so sweeping the whole map on write is
	// cheaper than carrying a cleanup task.
	now := time.Now()
	for k, e := range r.cache {
		if !e.expire.After(now) {
			delete(r.cache, k)
		}
	}
	r.cache[key] = resolveEntry{ips: append([]net.IP(nil), ips...), expire: now.Add(lifetime)}
}
