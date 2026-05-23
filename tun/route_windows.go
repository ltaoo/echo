//go:build windows

package tun

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	tun "github.com/sagernet/sing-tun"

	"github.com/sagernet/sing/common/logger"
)

// addTunRoutes adds split routes (0.0.0.0/1 + 128.0.0.0/1) to the TUN interface.
func addTunRoutes(tunName string, log logger.Logger) {
	iface, err := net.InterfaceByName(tunName)
	if err != nil {
		log.Warn("Cannot find TUN interface: ", err)
		return
	}
	for _, dest := range []string{"0.0.0.0", "128.0.0.0"} {
		psCmd := fmt.Sprintf(
			"$ifIdx=%d; $dest='%s/1'; Remove-NetRoute -DestinationPrefix $dest -Confirm:$false -ErrorAction SilentlyContinue; New-NetRoute -DestinationPrefix $dest -InterfaceIndex $ifIdx -RouteMetric 0 -PolicyStore ActiveStore",
			iface.Index, dest,
		)
		cmd := exec.Command("powershell", "-NoProfile", "-Command", psCmd)
		if out, err := cmd.CombinedOutput(); err != nil {
			exec.Command("route", "delete", dest, "mask", "128.0.0.0").Run()
			routeCmd := exec.Command("route", "add", dest, "mask", "128.0.0.0", "0.0.0.0",
				"metric", "0", "if", strconv.Itoa(iface.Index))
			if out2, err2 := routeCmd.CombinedOutput(); err2 != nil {
				log.Debug("TUN route failed: ", dest, " /1 — ", strings.TrimSpace(string(out2)))
				dumpRoutes()
			} else {
				log.Info("TUN route added: ", dest, " /1 via ", tunName)
			}
		} else {
			log.Info("TUN route added: ", dest, " /1 via ", tunName)
			_ = out
		}
	}
}

// removeTunRoutes removes the split routes on shutdown.
func removeTunRoutes() {
	for _, dest := range []string{"0.0.0.0", "128.0.0.0"} {
		exec.Command("powershell", "-NoProfile", "-Command",
			fmt.Sprintf("Remove-NetRoute -DestinationPrefix '%s/1' -Confirm:$false -ErrorAction SilentlyContinue", dest)).Run()
		exec.Command("route", "delete", dest, "mask", "128.0.0.0").Run()
	}
}

// startRouteMonitor sets up a network change callback and periodic fallback
// to re-add TUN routes.
func startRouteMonitor(networkMonitor tun.NetworkUpdateMonitor, tunName string, log logger.Logger) (stop chan struct{}) {
	stop = make(chan struct{})
	var routeMu sync.Mutex

	networkMonitor.RegisterCallback(func() {
		select {
		case <-stop:
			return
		default:
		}
		routeMu.Lock()
		defer routeMu.Unlock()
		log.Info("Route/network change detected, re-adding TUN routes...")
		addTunRoutes(tunName, log)
	})

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
			}
			routeMu.Lock()
			addTunRoutes(tunName, log)
			routeMu.Unlock()
		}
	}()

	return stop
}

// dumpRoutes prints active /1 and /0 routes for diagnostics.
func dumpRoutes() {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-NetRoute -DestinationPrefix '0.0.0.0/0','0.0.0.0/1','128.0.0.0/1' | Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric | Format-Table -AutoSize | Out-String -Width 200").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[debug] route dump failed: %v\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, "[debug] Active default routes:\n%s\n", string(out))
}

// detectDefaultGateway returns the first non-zero default gateway for IPv4.
func detectDefaultGateway() string {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object {$_.NextHop -ne '0.0.0.0'} | Select-Object -First 1).NextHop").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
