package engine

import (
	"adblocker/config"
	"fmt"
	"net/netip"
)

// UserMatcher identifies a user based on IP or MAC.
type UserMatcher struct {
	// Maps for O(1) lookup
	byIP  map[netip.Addr]*config.User
	byMAC map[string]*config.User

	// List for CIDR lookups (O(N))
	cidrs []cidrMapping

	defaultUserGroup string
}

type cidrMapping struct {
	prefix netip.Prefix
	user   *config.User
}

// NewUserMatcher builds a matcher from the configuration.
func NewUserMatcher(cfg *config.Config) (*UserMatcher, error) {
	um := &UserMatcher{
		byIP:             make(map[netip.Addr]*config.User),
		byMAC:            make(map[string]*config.User),
		defaultUserGroup: cfg.Defaults.UserGroup,
	}

	for i := range cfg.Users {
		user := &cfg.Users[i]

		// Index IPs
		for _, ipStr := range user.IPs {
			// Try parsing as CIDR first
			if prefix, err := netip.ParsePrefix(ipStr); err == nil {
				um.cidrs = append(um.cidrs, cidrMapping{prefix: prefix, user: user})
				continue
			}

			// Try as single IP
			if addr, err := netip.ParseAddr(ipStr); err == nil {
				um.byIP[addr] = user
				continue
			}

			return nil, fmt.Errorf("invalid IP/CIDR '%s' for user '%s'", ipStr, user.Name)
		}

		// Index MACs
		for _, mac := range user.MACs {
			// Normalize MAC string if needed (e.g. lowercase)
			um.byMAC[mac] = user
		}
	}

	return um, nil
}

// Match returns the UserConfig for a given client IP and MAC.
// Returns nil if no user is found (caller should use default group).
func (um *UserMatcher) Match(ip netip.Addr, mac string) *config.User {
	// 1. MAC Match (Highest priority in local networks usually)
	if mac != "" {
		if u, ok := um.byMAC[mac]; ok {
			return u
		}
	}

	// 2. Exact IP Match
	if u, ok := um.byIP[ip]; ok {
		return u
	}

	// 3. CIDR Match
	for _, mapping := range um.cidrs {
		if mapping.prefix.Contains(ip) {
			return mapping.user
		}
	}

	return nil
}

// Post-Validation: Ensure default user group exists?
// That logic belongs in validation, not here directly.
