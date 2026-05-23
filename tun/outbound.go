package tun

import (
	"context"
	"net"

	M "github.com/sagernet/sing/common/metadata"
	singHTTP "github.com/sagernet/sing/protocol/http"
)

type outboundDialer interface {
	DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
	Tag() string
}

type directOutbound struct {
	tag    string
	dialer *directDialer
}

func (d *directOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, destination)
}

func (d *directOutbound) Tag() string { return d.tag }

type httpOutbound struct {
	tag    string
	client *singHTTP.Client
}

func (h *httpOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return h.client.DialContext(ctx, network, destination)
}

func (h *httpOutbound) Tag() string { return h.tag }
