package dns

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	D "github.com/miekg/dns"
)

type udpmeClient struct {
	port   string
	host   string
	dialer *dnsDialer
}

var _ dnsClient = (*udpmeClient)(nil)

func (c *udpmeClient) Address() string {
	return fmt.Sprintf("%s://%s", "udpme", net.JoinHostPort(c.host, c.port))
}

func (c *udpmeClient) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	network := "udp"
	addr := net.JoinHostPort(c.host, c.port)
	query := m
	addedEDNS := false
	if m.IsEdns0() == nil {
		mc := m.Copy()
		mc.SetEdns0(4096, false)
		query = mc
		addedEDNS = true
	}

	conn, err := c.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	udpConn := &D.Conn{Conn: conn, UDPSize: 4096}
	_ = udpConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := udpConn.WriteMsg(query); err != nil {
		return nil, err
	}
	for {
		r, err := udpConn.ReadMsg()
		if err != nil {
			return nil, err
		}
		if r.Truncated {
			log.Debugln("[DNS] Truncated reply from %s:%s for %s over UDP, retrying over TCP", c.host, c.port, m.Question[0].String())
			tcpConn, err := c.dialer.DialContext(ctx, "tcp", addr)
			if err != nil {
				return nil, err
			}
			defer tcpConn.Close()
			dClient := &D.Client{Timeout: 5 * time.Second}
			dConn := &D.Conn{Conn: tcpConn}
			msg, _, err := dClient.ExchangeWithConn(query, dConn)
			if err != nil {
				return nil, err
			}
			if addedEDNS {
				removeEDNS0(msg)
			}
			return msg, nil
		}
		if r.IsEdns0() == nil {
			continue
		}
		if addedEDNS {
			removeEDNS0(r)
		}
		return r, nil
	}
}

func (c *udpmeClient) ResetConnection() {}

func newUdpmeClient(addr string, resolver resolver.Resolver, params map[string]string, proxyAdapter C.ProxyAdapter, proxyName string) *udpmeClient {
	host, port, _ := net.SplitHostPort(addr)
	return &udpmeClient{
		port:   port,
		host:   host,
		dialer: newDNSDialer(resolver, proxyAdapter, proxyName),
	}
}

func removeEDNS0(m *D.Msg) {
	for i := len(m.Extra) - 1; i >= 0; i-- {
		if m.Extra[i].Header().Rrtype == D.TypeOPT {
			m.Extra = append(m.Extra[:i], m.Extra[i+1:]...)
			return
		}
	}
}
