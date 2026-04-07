package dns

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/dhcp"
	"github.com/metacubex/mihomo/component/iface"
	"github.com/metacubex/mihomo/log"
	D "github.com/miekg/dns"
)

const (
	IfaceTTL    = time.Second * 20
	DHCPTTL     = time.Hour
	DHCPTimeout = time.Minute
)

type dhcpClient struct {
	ifaceName string

	lock            sync.Mutex
	ifaceInvalidate time.Time
	dnsInvalidate   time.Time

	ifaceAddr netip.Prefix
	done      chan struct{}
	clients   []dnsClient
	err       error
}

var _ dnsClient = (*dhcpClient)(nil)

// Address implements dnsClient
func (d *dhcpClient) Address() string {
	addrs := make([]string, 0)
	for _, c := range d.clients {
		addrs = append(addrs, c.Address())
	}
	return strings.Join(addrs, ",")
}

func (d *dhcpClient) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	clients, err := d.resolve(ctx)
	if err != nil {
		return nil, err
	}

	msg, _, err = batchExchange(ctx, clients, m)
	return
}

func (d *dhcpClient) ResetConnection() {
	for _, client := range d.clients {
		client.ResetConnection()
	}
}

func (d *dhcpClient) resolve(ctx context.Context) ([]dnsClient, error) {
	d.lock.Lock()

	invalidated, err := d.invalidate()
	if err != nil {
		d.err = err
	} else if invalidated {
		done := make(chan struct{})

		d.done = done

		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), DHCPTimeout)
			defer cancel()

			var res []dnsClient
			dns, err := dhcp.ResolveDNSFromDHCP(ctx, d.ifaceName)
			// dns never empty if err is nil
			if err == nil {
				nameserver := make([]NameServer, 0, len(dns))
				for _, item := range dns {
					nameserver = append(nameserver, NameServer{
						Addr:      net.JoinHostPort(item.String(), "53"),
						ProxyName: d.ifaceName,
					})
				}

				res = transform(nameserver, nil)
			}

			d.lock.Lock()
			defer d.lock.Unlock()

			close(done)

			d.done = nil
			d.clients = res
			d.err = err
		}()
	}

	d.lock.Unlock()

	for {
		d.lock.Lock()

		res, err, done := d.clients, d.err, d.done

		d.lock.Unlock()

		// initializing
		if res == nil && err == nil {
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		// dirty return
		return res, err
	}
}

func (d *dhcpClient) invalidate() (bool, error) {
	if time.Now().Before(d.ifaceInvalidate) {
		return false, nil
	}

	d.ifaceInvalidate = time.Now().Add(IfaceTTL)

	ifaceObj, err := iface.ResolveInterface(d.ifaceName)
	if err != nil {
		return false, err
	}

	addr, err := ifaceObj.PickIPv4Addr(netip.Addr{})
	if err != nil {
		return false, err
	}

	if time.Now().Before(d.dnsInvalidate) && d.ifaceAddr == addr {
		return false, nil
	}

	d.dnsInvalidate = time.Now().Add(DHCPTTL)
	d.ifaceAddr = addr

	return d.done == nil, nil
}

func newDHCPClient(ifaceName string) *dhcpClient {
	return &dhcpClient{ifaceName: ifaceName}
}

// --- dhcp://auto: auto-detect default interface ---

const DHCPTimeoutAuto = 5 * time.Second

type autoDHCPClient struct {
	lock         sync.RWMutex
	updatedAt    time.Time
	lastError    error
	clients      []dnsClient
	currentIface string
	unregister   func()
}

var (
	_ dnsClient = (*autoDHCPClient)(nil)
	_ io.Closer = (*autoDHCPClient)(nil)
)

func (d *autoDHCPClient) Address() string {
	if name, err := iface.GetDefaultInterfaceName(); err == nil {
		return "dhcp://auto(" + name + ")"
	}
	return "dhcp://auto"
}

func (d *autoDHCPClient) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	clients, err := d.fetch()
	if err != nil {
		return nil, err
	}
	msg, _, err = batchExchange(ctx, clients, m)
	return
}

func (d *autoDHCPClient) ResetConnection() {
	d.lock.Lock()
	for _, client := range d.clients {
		client.ResetConnection()
	}
	d.updatedAt = time.Time{}
	d.lock.Unlock()
}

func (d *autoDHCPClient) Close() error {
	if d.unregister != nil {
		d.unregister()
		d.unregister = nil
	}
	return nil
}

func (d *autoDHCPClient) interfaceUpdated() {
	go func() {
		d.lock.Lock()
		defer d.lock.Unlock()
		d.updatedAt = time.Time{}
		d.lastError = nil
		if err := d.updateServers(); err != nil {
			log.Warnln("[DHCP] update servers on interface change: %v", err)
		}
	}()
}

func (d *autoDHCPClient) fetch() ([]dnsClient, error) {
	d.lock.RLock()
	updatedAt, lastError, clients := d.updatedAt, d.lastError, d.clients
	d.lock.RUnlock()

	if lastError != nil {
		return nil, lastError
	}
	if time.Since(updatedAt) < DHCPTTL {
		return clients, nil
	}

	d.lock.Lock()
	defer d.lock.Unlock()

	if d.lastError != nil {
		return nil, d.lastError
	}
	if time.Since(d.updatedAt) < DHCPTTL {
		return d.clients, nil
	}

	if err := d.updateServers(); err != nil {
		return clients, err
	}
	return d.clients, nil
}

func (d *autoDHCPClient) updateServers() error {
	name, err := iface.GetDefaultInterfaceName()
	if err != nil {
		d.updatedAt = time.Now()
		d.lastError = err
		return err
	}
	d.currentIface = name

	ctx, cancel := context.WithTimeout(context.Background(), DHCPTimeoutAuto)
	defer cancel()

	dnsAddrs, err := dhcp.ResolveDNSFromDHCP(ctx, name)
	d.updatedAt = time.Now()
	if err != nil {
		d.lastError = err
		return err
	}
	if len(dnsAddrs) == 0 {
		d.lastError = dhcp.ErrNotFound
		return d.lastError
	}

	nameserver := make([]NameServer, 0, len(dnsAddrs))
	for _, item := range dnsAddrs {
		nameserver = append(nameserver, NameServer{
			Addr:      net.JoinHostPort(item.String(), "53"),
			ProxyName: name,
		})
	}
	d.clients = transform(nameserver, nil)
	d.lastError = nil
	return nil
}

func newAutoDHCPClient() *autoDHCPClient {
	c := &autoDHCPClient{}
	c.unregister = iface.RegisterDefaultInterfaceChanged(c.interfaceUpdated)
	go func() {
		c.lock.Lock()
		defer c.lock.Unlock()
		if err := c.updateServers(); err != nil {
			log.Warnln("[DHCP] initial fetch: %v", err)
		}
	}()
	return c
}
