package parser

import "net/netip"

// RuleType distinguishes the matching strategy required for a rule.
type RuleType int

const (
	RuleTypeUnknown     RuleType = iota
	RuleTypeExact                // exact match: example.com
	RuleTypeDistinguish          // domain + subdomains: ||example.com^
	RuleTypeRegex                // regex: /example.*/
	RuleTypeGeneric              // keyword match (rare in DNS, mostly for hosts)
)

// Modifiers holds the parsed rule modifiers.
type Modifiers struct {
	Client      []string // $client='...'
	DenyAllow   []string // $denyallow='...'
	DNSType     []string // $dnstype='AAAA'
	DNSRewrite  string   // $dnsrewrite='...'
	Important   bool     // $important
	BadFilter   bool     // $badfilter
	ContentType []string // Ignored, but kept for parsing safety
}

// Rule represents a parsed AdGuard filtering rule.
type Rule struct {
	Text        string     // Original rule text
	Pattern     string     // Extracted pattern (e.g., "example.com")
	Type        RuleType   // Type of matching
	IsWhitelist bool       // True if it starts with @@
	Modifiers   Modifiers  // Parsed modifiers
	IP          netip.Addr // For /etc/hosts style rules (0.0.0.0 example.com)
	GroupID     int        // ID of the RuleGroup this rule belongs to
}
