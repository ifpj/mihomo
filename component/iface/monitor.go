package iface

import (
	"errors"
	"sync"

	mihomoLog "github.com/metacubex/mihomo/log"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/control"
	"github.com/metacubex/sing/common/logger"
)

var (
	monitorMu      sync.Mutex
	networkMonitor tun.NetworkUpdateMonitor
	ifaceMonitor   tun.DefaultInterfaceMonitor
)

// StartDefaultInterfaceMonitor creates and starts a global DefaultInterfaceMonitor
// using sing-tun library. This monitor tracks the OS default route interface
// independently of TUN. OverrideAndroidVPN is set to false so DHCP always
// sees the physical interface (WiFi/mobile), not VPN/TUN.
// The onChange callback is invoked on every interface change (for resolver.ResetConnection etc).
func StartDefaultInterfaceMonitor(log logger.Logger, onChange func()) error {
	monitorMu.Lock()
	defer monitorMu.Unlock()

	if ifaceMonitor != nil {
		return nil // already started
	}

	networkMon, err := tun.NewNetworkUpdateMonitor(log)
	if err != nil {
		return err
	}
	if err = networkMon.Start(); err != nil {
		_ = networkMon.Close()
		return err
	}

	ifaceMon, err := tun.NewDefaultInterfaceMonitor(networkMon, log, tun.DefaultInterfaceMonitorOptions{
		InterfaceFinder:    &FinderBridge{},
		OverrideAndroidVPN: false,
	})
	if err != nil {
		_ = networkMon.Close()
		return err
	}

	ifaceMon.RegisterCallback(func(defaultInterface *control.Interface, flags int) {
		if defaultInterface != nil {
			mihomoLog.Infoln("[DHCP] default interface changed, => %s", defaultInterface.Name)
		} else {
			mihomoLog.Warnln("[DHCP] default interface lost")
		}
		FlushCache()
		if onChange != nil {
			onChange()
		}
	})

	if err = ifaceMon.Start(); err != nil {
		_ = networkMon.Close()
		return err
	}

	networkMonitor = networkMon
	ifaceMonitor = ifaceMon
	return nil
}

// StopDefaultInterfaceMonitor stops and cleans up the global interface monitor.
func StopDefaultInterfaceMonitor() {
	monitorMu.Lock()
	defer monitorMu.Unlock()

	if ifaceMonitor != nil {
		_ = ifaceMonitor.Close()
		ifaceMonitor = nil
	}
	if networkMonitor != nil {
		_ = networkMonitor.Close()
		networkMonitor = nil
	}
}

// GetDefaultInterfaceName returns the current default network interface name
// detected by the global monitor.
func GetDefaultInterfaceName() (string, error) {
	monitorMu.Lock()
	monitor := ifaceMonitor
	monitorMu.Unlock()

	if monitor == nil {
		return "", errors.New("default interface monitor not started, check if dhcp://auto is supported on this platform")
	}

	ifc := monitor.DefaultInterface()
	if ifc == nil {
		return "", errors.New("no default interface detected")
	}

	return ifc.Name, nil
}

// RegisterDefaultInterfaceChanged registers a callback that is called when the
// default interface changes. Returns an unregister function.
// If the monitor is not started, returns a no-op unregister function.
func RegisterDefaultInterfaceChanged(fn func()) func() {
	monitorMu.Lock()
	monitor := ifaceMonitor
	monitorMu.Unlock()

	if monitor == nil {
		return func() {}
	}

	element := monitor.RegisterCallback(func(_ *control.Interface, _ int) {
		fn()
	})

	return func() {
		monitor.UnregisterCallback(element)
	}
}
