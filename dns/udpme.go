package dns

import (
	"context"
	"net"
	"time"

	D "github.com/miekg/dns"
)

type udpmeClient struct {
	addr     string
	upstream *udpmeUpstream
}

var _ dnsClient = (*udpmeClient)(nil)

func (c *udpmeClient) Address() string {
	return c.addr
}

func (c *udpmeClient) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	ch := make(chan struct {
		msg *D.Msg
		err error
	}, 1)
	go func() {
		resp, err := c.upstream.Exchange(m)
		ch <- struct {
			msg *D.Msg
			err error
		}{resp, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.msg, r.err
	}
}

func (c *udpmeClient) ResetConnection() {}

func newUdpmeClient(addr string) *udpmeClient {
	return &udpmeClient{
		addr:     "udpme://" + addr,
		upstream: newUpstream(addr),
	}
}

type udpmeUpstream struct {
	Addr string
}

func tryAddPort(addr string, port string) string {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, port)
	}
	return addr
}

func newUpstream(addr string) *udpmeUpstream {
	return &udpmeUpstream{Addr: tryAddPort(addr, "53")}
}

func (u *udpmeUpstream) Exchange(m *D.Msg) (*D.Msg, error) {
	if m.IsEdns0() != nil {
		return u.exchangeOPTM(m)
	}
	mc := m.Copy()
	mc.SetEdns0(512, false)
	r, err := u.exchangeOPTM(mc)
	if err != nil {
		return nil, err
	}
	removeEDNS0(r)
	return r, nil
}
func (u *udpmeUpstream) exchangeOPTM(m *D.Msg) (*D.Msg, error) {
	c, err := D.Dial("udp", u.Addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second * 3))
	if opt := m.IsEdns0(); opt != nil {
		c.UDPSize = opt.UDPSize()
	}
	if err := c.WriteMsg(m); err != nil {
		return nil, err
	}
	for {
		r, err := c.ReadMsg()
		if err != nil {
			return nil, err
		}
		if r.IsEdns0() == nil {
			continue
		}
		return r, nil
	}
}

func removeEDNS0(m *D.Msg) {
	for i := len(m.Extra) - 1; i >= 0; i-- {
		if m.Extra[i].Header().Rrtype == D.TypeOPT {
			m.Extra = append(m.Extra[:i], m.Extra[i+1:]...)
			return
		}
	}
	return
}
