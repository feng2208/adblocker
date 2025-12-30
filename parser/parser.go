package parser

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// ParseRule parses a single line of AdGuard rule text.
// Returns nil if the line is empty or a comment.
func ParseRule(text string) (*Rule, error) {
	text = strings.TrimSpace(text)
	if text == "" || strings.HasPrefix(text, "!") || strings.HasPrefix(text, "#") {
		return nil, nil // Comment or empty
	}

	rule := &Rule{
		Text: text,
		Type: RuleTypeUnknown,
	}

	// 1. Check for whitelist
	if strings.HasPrefix(text, "@@") {
		rule.IsWhitelist = true
		text = text[2:]
	}

	// 2. Check for modifiers
	// Modifiers are at the end, starting with $
	if idx := strings.LastIndex(text, "$"); idx != -1 {
		// Check if $ is escaped? AdGuard docs say $ is separator.
		// There might be cases where $ is part of URL, but for domain rules it's usually clear.
		// A rudimentary check: ensure it's not part of domain chars like example$com (invalid).
		modifiersStr := text[idx+1:]
		if err := parseModifiers(modifiersStr, &rule.Modifiers); err != nil {
			return nil, fmt.Errorf("failed to parse modifiers: %w", err)
		}
		text = text[:idx]
	}

	rule.Pattern = text

	// 3. Determine Type
	if strings.HasPrefix(text, "/") && strings.HasSuffix(text, "/") {
		rule.Type = RuleTypeRegex
		rule.Pattern = text[1 : len(text)-1]
	} else if strings.HasPrefix(text, "||") && strings.HasSuffix(text, "^") {
		rule.Type = RuleTypeDistinguish
		rule.Pattern = text[2 : len(text)-1]
	} else if strings.HasPrefix(text, "||") {
		rule.Type = RuleTypeDistinguish
		rule.Pattern = text[2:]
	} else {
		// Check for Hosts syntax: IP Domain
		// e.g. 127.0.0.1 example.com
		// e.g. 0.0.0.0 example.com
		parts := strings.Fields(text)
		if len(parts) >= 2 {
			// Try parsing first part as IP
			if ip, err := netip.ParseAddr(parts[0]); err == nil {
				// Valid IP found at start
				rule.IP = ip
				rule.Pattern = parts[1]   // The domain
				rule.Type = RuleTypeExact // User requested exact match for hosts syntax (no wildcards)

				// If IP is 0.0.0.0 or 127.0.0.1 or ::1 or ::, it's a block.
				// If it's another IP, it might be a rewrite?
				// AdGuard: "1.2.3.4 example.com" -> $dnsrewrite=1.2.3.4
				if !ip.IsLoopback() && !ip.IsUnspecified() {
					rule.Modifiers.DNSRewrite = ip.String()
				}
				// If it's a block, we just leave it as is, Engine treats default rule as block.
			} else {
				// Not an IP, normal rule
				rule.Type = RuleTypeExact
			}
		} else {
			rule.Type = RuleTypeExact
		}
	}

	// Cleanup pattern
	rule.Pattern = strings.TrimSuffix(rule.Pattern, "^")

	// 4. Convert wildcard patterns to regex
	// If pattern contains * and is not already a regex, convert it
	if rule.Type != RuleTypeRegex && strings.Contains(rule.Pattern, "*") {
		originalType := rule.Type
		rule.Type = RuleTypeRegex
		// Escape regex special chars except *, then replace * with .*
		escaped := regexp.QuoteMeta(rule.Pattern)
		// QuoteMeta escapes * to \*, so we need to replace \* back to .*
		regexPattern := strings.ReplaceAll(escaped, `\*`, `.*`)

		if originalType == RuleTypeDistinguish {
			// ||pattern -> match domain and all subdomains
			// Regex: (^|\.)pattern$
			rule.Pattern = `(^|\.)` + regexPattern + `$`
		} else {
			// Exact match with wildcard
			// Regex: ^pattern$
			rule.Pattern = "^" + regexPattern + "$"
		}
	}

	return rule, nil
}

func parseModifiers(raw string, m *Modifiers) error {
	parts := strings.Split(raw, ",")
	for _, p := range parts {
		kv := strings.SplitN(p, "=", 2)
		key := strings.TrimSpace(kv[0])
		val := ""
		if len(kv) > 1 {
			val = kv[1]
		}

		switch key {
		case "client":
			m.Client = append(m.Client, val) // Logic needed to handle exclusionary 'client=~name' later
		case "denyallow":
			m.DenyAllow = append(m.DenyAllow, val)
		case "dnstype":
			m.DNSType = append(m.DNSType, val) // Split by | if needed, but handled at runtime?
		case "dnsrewrite":
			m.DNSRewrite = val
		case "important":
			m.Important = true
		case "badfilter":
			m.BadFilter = true
		// Ignored modifiers:
		case "image", "script", "third-party", "xmlhttprequest", "popup", "generichide":
			// ignore
		default:
			// log.Printf("Unknown modifier: %s", key)
		}
	}
	return nil
}
