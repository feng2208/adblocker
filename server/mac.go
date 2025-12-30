package server

import (
	"net/netip"
	"sync"
	"time"
)

// MacResolver resolves IPs to MAC addresses using system ARP table.
type MacResolver struct {
	cache   map[netip.Addr]cachedMac
	cacheMu sync.RWMutex
	ttl     time.Duration
}

type cachedMac struct {
	mac       string
	expiresAt time.Time
}

func NewMacResolver(ttl time.Duration) *MacResolver {
	return &MacResolver{
		cache: make(map[netip.Addr]cachedMac),
		ttl:   ttl,
	}
}

// GetMAC returns the MAC address for the given IP.
// Returns empty string if not found.
func (mr *MacResolver) GetMAC(ip netip.Addr) string {
	if ip.IsLoopback() {
		return "" // Loopback usually has no specific MAC or is irrelevant config-wise
	}

	// 1. Check Cache
	mr.cacheMu.RLock()
	entry, ok := mr.cache[ip]
	mr.cacheMu.RUnlock()

	if ok && time.Now().Before(entry.expiresAt) {
		return entry.mac
	}

	// 2. Resolve (Platform Specific)
	mac := resolveARP(ip)

	// 3. Update Cache
	mr.cacheMu.Lock()
	mr.cache[ip] = cachedMac{
		mac:       mac,
		expiresAt: time.Now().Add(mr.ttl),
	}
	mr.cacheMu.Unlock()

	return mac
}
