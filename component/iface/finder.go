package iface

import (
	"net"
	"net/netip"

	"github.com/metacubex/sing/common/control"
)

// FinderBridge bridges iface.Interface and control.Interface
// for use with sing-tun's DefaultInterfaceMonitor.
// The two struct types have identical fields, so direct pointer cast works.
type FinderBridge struct{}

var _ control.InterfaceFinder = (*FinderBridge)(nil)

func (f *FinderBridge) Update() error {
	FlushCache()
	_, err := Interfaces()
	return err
}

func (f *FinderBridge) Interfaces() []control.Interface {
	ifaces, err := Interfaces()
	if err != nil {
		return nil
	}
	interfaces := make([]control.Interface, 0, len(ifaces))
	for _, ifc := range ifaces {
		interfaces = append(interfaces, control.Interface(*ifc))
	}
	return interfaces
}

func (f *FinderBridge) ByName(name string) (*control.Interface, error) {
	netInterface, err := ResolveInterface(name)
	if err == nil {
		return (*control.Interface)(netInterface), nil
	}
	if _, err2 := net.InterfaceByName(name); err2 == nil {
		if err3 := f.Update(); err3 != nil {
			return nil, err3
		}
		netInterface, err = ResolveInterface(name)
		if err == nil {
			return (*control.Interface)(netInterface), nil
		}
	}
	return nil, err
}

func (f *FinderBridge) ByIndex(index int) (*control.Interface, error) {
	ifaces, err := Interfaces()
	if err != nil {
		return nil, err
	}
	for _, netInterface := range ifaces {
		if netInterface.Index == index {
			return (*control.Interface)(netInterface), nil
		}
	}
	if _, err2 := net.InterfaceByIndex(index); err2 == nil {
		if err3 := f.Update(); err3 != nil {
			return nil, err3
		}
		ifaces, err = Interfaces()
		if err != nil {
			return nil, err
		}
		for _, netInterface := range ifaces {
			if netInterface.Index == index {
				return (*control.Interface)(netInterface), nil
			}
		}
	}
	return nil, ErrIfaceNotFound
}

func (f *FinderBridge) ByAddr(addr netip.Addr) (*control.Interface, error) {
	netInterface, err := ResolveInterfaceByAddr(addr)
	if err != nil {
		return nil, err
	}
	return (*control.Interface)(netInterface), nil
}
