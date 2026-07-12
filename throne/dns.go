// Package throne provides the glue Throne uses to wire a Xray instance's egress
// after core.New: an outbound DNS resolver ("throne-dns") that resolves proxy
// server domains through sing-box's loopback DNS, and helpers for the dynamic
// interface finder. It lives outside package core (which cannot import app/dns
// without an import cycle) and is imported only by the embedding application.
package throne

import (
	"context"
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
type resolver struct {
	server dnsapp.Server
	// instanceCtx carries the owning Xray Instance. Xray's app/dns nameservers
	// derive their query context from it (toDnsContext -> ToBackgroundDetachedContext
	// -> MustFromContext), so it MUST be present or QueryIP panics with
	// "X is not in context.". It is injected by core.SetOutboundDNS (which knows
	// the instance) via SetInstanceContext when the resolver is attached, mirroring
	// how app/dns.(*DNS) keeps its construction context for QueryIP.
	instanceCtx context.Context
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
	server := dnsapp.NewClassicNameServer(dest, directDispatcher{}, false, false, 0, nil)
	return &resolver{server: server}, nil
}

func (*resolver) Type() interface{} { return dnsfeature.ClientType() }
func (*resolver) Start() error      { return nil }
func (*resolver) Close() error      { return nil }

// LookupIP implements dns.Client.
func (r *resolver) LookupIP(domain string, option dnsfeature.IPOption) ([]net.IP, uint32, error) {
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
	return r.server.QueryIP(ctx, domain, option)
}
