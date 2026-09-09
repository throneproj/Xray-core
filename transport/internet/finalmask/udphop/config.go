package udphop

import (
	"context"
	"net"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
)

func (c *Config) WrapPacketConnClient(raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	return c.WrapPacketConnClientContext(context.Background(), raw, level, levelCount)
}

// WrapPacketConnClientContext implements finalmask's dialingUdpmask: each hop opens
// a new socket, so the dial context has to reach it or the hop dials outside the
// instance's Throne egress wiring.
func (c *Config) WrapPacketConnClientContext(ctx context.Context, raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	_, ok1 := raw.(*internet.FakePacketConn)
	if level != 0 || ok1 {
		return nil, errors.New("udphop requires being at the outermost level")
	}
	return NewUDPHopConn(ctx, c, raw)
}

func (c *Config) WrapPacketConnServer(raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	return nil, errors.New("udphop: client only")
}
