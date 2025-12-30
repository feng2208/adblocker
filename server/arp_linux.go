//go:build linux

package server

import (
	"bufio"
	"net/netip"
	"os"
	"strings"
)

func resolveARP(ip netip.Addr) string {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return ""
	}
	defer f.Close()

	targetIP := ip.String()
	scanner := bufio.NewScanner(f)
	// Skip header
	// IP address       HW type     Flags       HW address            Mask     Device
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		if fields[0] == targetIP {
			// Check flags? 0x2 is complete. 0x0 is incomplete.
			return fields[3]
		}
	}

	return ""
}
