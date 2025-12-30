//go:build !windows && !linux

package server

import (
	"net/netip"
)

func resolveARP(ip netip.Addr) string {
	return ""
}
