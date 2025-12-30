package engine

import (
	"fmt"
	"log"
	"net/netip"
	"strings"
	"sync"
	"time"

	"adblocker/config"
	"adblocker/parser"

	"regexp"

	"github.com/miekg/dns"
)

// RegexRule compiled wrapper
type RegexRule struct {
	Rule  *parser.Rule
	Regex *regexp.Regexp
}

// Engine combines User, Schedule, and Trie matching to make filtering decisions.
type Engine struct {
	cfg             *config.Config
	userMatcher     *UserMatcher
	scheduleMatcher *ScheduleMatcher
	// Trie protection
	trieMu sync.RWMutex
	trie   *DomainTrie

	// Regex Rules
	regexRules []RegexRule

	// File Rule Cache: Path -> Rules
	fileRuleCache map[string][]*parser.Rule

	// Map RuleGroup Name -> GroupID
	groupIDs map[string]int

	// Default default user group Name
	defaultUserGroupName string
}

// NewEngine initializes the matching engine.
func NewEngine(cfg *config.Config) (*Engine, error) {
	um, err := NewUserMatcher(cfg)
	if err != nil {
		return nil, fmt.Errorf("user matcher init failed: %w", err)
	}

	sm, err := NewScheduleMatcher(cfg)
	if err != nil {
		return nil, fmt.Errorf("schedule matcher init failed: %w", err)
	}

	e := &Engine{
		cfg:                  cfg,
		userMatcher:          um,
		scheduleMatcher:      sm,
		trie:                 NewDomainTrie(),
		fileRuleCache:        make(map[string][]*parser.Rule),
		groupIDs:             make(map[string]int),
		defaultUserGroupName: cfg.Defaults.UserGroup,
	}

	// 1. Assign IDs to RuleGroups
	for i, rg := range cfg.RuleGroups {
		e.groupIDs[rg.Name] = i + 1 // 1-based index
	}

	return e, nil
}

// GetUser identifies the user based on IP and MAC.
func (e *Engine) GetUser(clientIP netip.Addr, clientMAC string) *config.User {
	return e.userMatcher.Match(clientIP, clientMAC)
}

// ReloadRules reloads all regulations and atomically swaps the trie.
func (e *Engine) ReloadRules(loader *parser.Loader) {
	var wg sync.WaitGroup
	var mu sync.Mutex

	newTrie := NewDomainTrie()
	var newRegexRules []RegexRule

	log.Printf("Reloading rules for %d groups...", len(e.cfg.RuleGroups))

	for _, rg := range e.cfg.RuleGroups {
		groupID := e.groupIDs[rg.Name]

		for _, source := range rg.Sources {
			wg.Add(1)
			go func(src config.Source, gid int) {
				defer wg.Done()

				var rules []*parser.Rule
				var err error

				if src.Path != "" {
					// Check Cache
					e.trieMu.RLock()
					cached, ok := e.fileRuleCache[src.Path]
					e.trieMu.RUnlock()

					if ok {
						rules = cached
						// log.Printf("Using cached rules for '%s'", src.Name)
					} else {
						rules, err = loader.LoadFromPath(src.Path)
						if err == nil {
							// Update Cache
							e.trieMu.Lock()
							e.fileRuleCache[src.Path] = rules
							e.trieMu.Unlock()
						}
					}
				} else if src.URL != "" {
					rules, err = loader.LoadFromURLWithCache(src.URL)
				}

				if err != nil {
					log.Printf("Failed to load source '%s': %v", src.Name, err)
					return
				}

				// Insert into New Trie or Regex List
				mu.Lock()
				for _, r := range rules {
					r.GroupID = gid
					switch r.Type {
					case parser.RuleTypeExact, parser.RuleTypeDistinguish:
						newTrie.Insert(r)
					case parser.RuleTypeRegex:
						re, err := regexp.Compile(r.Pattern)
						if err == nil {
							newRegexRules = append(newRegexRules, RegexRule{Rule: r, Regex: re})
						}
					}
				}
				mu.Unlock()

				log.Printf("Loaded %d rules from '%s'", len(rules), src.Name)
			}(source, groupID)
		}
	}

	wg.Wait()

	// Atomic Swap
	e.trieMu.Lock()
	e.trie = newTrie
	e.regexRules = newRegexRules
	e.trieMu.Unlock()

	log.Printf("Rules reloaded and trie updated.")
}

// ResolveResult contains the decision for a DNS query.
type ResolveResult struct {
	Blocked    bool
	Reason     string
	Rule       *parser.Rule // The rule that caused the block
	User       *config.User
	DNSRewrite string // Rewrite destination (IP or CNAME)
}

// Resolve processes a DNS question.
func (e *Engine) Resolve(qName string, qType uint16, clientIP netip.Addr, clientMAC string) *ResolveResult {
	// 1. Identify User
	user := e.userMatcher.Match(clientIP, clientMAC)

	// 2. Determine UserGroup
	var userGroupName string
	if user != nil {
		userGroupName = user.UserGroup
	} else {
		userGroupName = e.defaultUserGroupName
	}

	// 3. Get Active Policies (ordered by config)
	activeGroupIDs := e.getActiveGroupIDs(userGroupName)

	if len(activeGroupIDs) == 0 {
		return &ResolveResult{Blocked: false, Reason: "No active rules", User: user}
	}

	// 4. Query Trie & Regex
	e.trieMu.RLock()
	allMatches := e.trie.SearchTrace(qName)
	// Check Regex
	for _, rr := range e.regexRules {
		if rr.Regex.MatchString(qName) {
			allMatches = append(allMatches, rr.Rule)
		}
	}
	e.trieMu.RUnlock()

	// 5. Evaluate Matches in Group Order (first match wins)
	// Iterate through groups in priority order (as defined in config.yaml policies)
	for _, gid := range activeGroupIDs {
		// Filter matches for this group
		var blockRule *parser.Rule
		var whitelistRule *parser.Rule
		var importantBlockRule *parser.Rule
		var importantWhitelistRule *parser.Rule

		for _, r := range allMatches {
			if r.GroupID != gid {
				continue
			}

			// Enforce Exact Match logic
			if r.Type == parser.RuleTypeExact {
				qCheck := strings.TrimSuffix(qName, ".")
				if r.Pattern != qCheck {
					continue
				}
			}

			// Modifier Checks
			if !e.checkModifiers(r, user, qType, clientIP, qName) {
				continue
			}

			if r.IsWhitelist {
				if r.Modifiers.Important {
					importantWhitelistRule = r
				} else {
					whitelistRule = r
				}
			} else {
				if r.Modifiers.Important {
					importantBlockRule = r
				} else {
					blockRule = r
				}
			}
		}

		// Check if this group has a decisive result (first match wins)
		if importantWhitelistRule != nil {
			return &ResolveResult{Blocked: false, Reason: "Important Whitelisted", Rule: importantWhitelistRule, User: user}
		}
		if importantBlockRule != nil {
			return &ResolveResult{Blocked: true, Reason: "Important Blocked", Rule: importantBlockRule, User: user}
		}
		if whitelistRule != nil {
			return &ResolveResult{Blocked: false, Reason: "Whitelisted", Rule: whitelistRule, User: user}
		}
		if blockRule != nil {
			res := &ResolveResult{Blocked: true, Reason: "Blocked", Rule: blockRule, User: user}
			if blockRule.Modifiers.DNSRewrite != "" {
				res.Reason = "Rewrite"
				res.DNSRewrite = blockRule.Modifiers.DNSRewrite
			}
			return res
		}
		// No match in this group, continue to next group
	}

	return &ResolveResult{Blocked: false, Reason: "Not found", User: user}
}

// getActiveGroupIDs returns an ordered slice of RuleGroup IDs that are currently active for the given UserGroup.
// Order is preserved from config.yaml policies.
func (e *Engine) getActiveGroupIDs(userGroupName string) []int {
	var activeIDs []int
	seen := make(map[int]bool)

	// Find UserGroup config
	var ug *config.UserGroup
	for i := range e.cfg.UserGroups {
		if e.cfg.UserGroups[i].Name == userGroupName {
			ug = &e.cfg.UserGroups[i]
			break
		}
	}

	if ug == nil {
		return activeIDs
	}

	now := time.Now()

	for _, policy := range ug.Policies {
		// Check Schedule
		// Logic: If a schedule is defined, it acts as a "Pause" or "Exclude" period.
		// If current time IS in the schedule, the rule group is INACTIVE.
		isActive := true
		if e.scheduleMatcher.IsActive(policy.Schedule, now) {
			isActive = false
		}

		if isActive {
			gid := e.groupIDs[policy.RuleGroup]
			if gid != 0 && !seen[gid] {
				activeIDs = append(activeIDs, gid)
				seen[gid] = true
			}
		}
	}

	return activeIDs
}

// checkModifiers evaluates if a rule's modifiers allow it to be applied to the current query.
func (e *Engine) checkModifiers(r *parser.Rule, user *config.User, qType uint16, clientIP netip.Addr, qName string) bool {
	// $badfilter modifier (If rule is marked bad, we ignore it)
	if r.Modifiers.BadFilter {
		return false
	}

	// $client modifier
	// Values are either all inclusions (A|B) OR all exclusions (~A|~B), NOT mixed.
	if len(r.Modifiers.Client) > 0 {
		// Flatten all values
		var targets []string
		for _, raw := range r.Modifiers.Client {
			targets = append(targets, strings.Split(raw, "|")...)
		}
		if len(targets) == 0 {
			return false
		}

		// Determine mode from first value
		isExclusionMode := strings.HasPrefix(strings.TrimSpace(targets[0]), "~")
		matched := false

		for _, p := range targets {
			p = strings.TrimSpace(p)
			target := strings.TrimPrefix(p, "~")

			// Check match
			isMatch := false
			if user != nil && target == user.Name {
				isMatch = true
			} else if ip, err := netip.ParseAddr(target); err == nil {
				if ip == clientIP {
					isMatch = true
				}
			} else if prefix, err := netip.ParsePrefix(target); err == nil {
				if prefix.Contains(clientIP) {
					isMatch = true
				}
			} else if target == clientIP.String() {
				isMatch = true
			}

			if isMatch {
				matched = true
				break
			}
		}

		if isExclusionMode {
			// ~A|~B: Rule applies if client matches NONE
			if matched {
				return false
			}
		} else {
			// A|B: Rule applies if client matches ANY
			if !matched {
				return false
			}
		}
	}

	// $dnstype modifier
	// Values are either all inclusions (A|AAAA) OR all exclusions (~A|~AAAA), NOT mixed.
	if len(r.Modifiers.DNSType) > 0 {
		typeName := dns.TypeToString[qType]

		// Flatten all values
		var targets []string
		for _, raw := range r.Modifiers.DNSType {
			targets = append(targets, strings.Split(raw, "|")...)
		}
		if len(targets) == 0 {
			return false
		}

		// Determine mode from first value
		isExclusionMode := strings.HasPrefix(strings.TrimSpace(targets[0]), "~")
		matched := false

		for _, p := range targets {
			p = strings.TrimSpace(p)
			target := strings.TrimPrefix(p, "~")
			if strings.EqualFold(target, typeName) {
				matched = true
				break
			}
		}

		if isExclusionMode {
			// ~A|~AAAA: Rule applies if type matches NONE
			if matched {
				return false
			}
		} else {
			// A|AAAA: Rule applies if type matches ANY
			if !matched {
				return false
			}
		}
	}

	// $denyallow modifier (Only block if domain is NOT in denyallow list)
	// Usually invalid on whitelist rules, but if present:
	// "If the domain matches the rule pattern, it is blocked EXCEPT if it also matches one of the denyallow domains."
	if len(r.Modifiers.DenyAllow) > 0 {
		isExcluded := false
		domain := strings.TrimSuffix(qName, ".")

		for _, raw := range r.Modifiers.DenyAllow {
			parts := strings.Split(raw, "|")
			for _, da := range parts {
				da = strings.TrimSpace(da)
				// AdGuard: denyallow matches subdomains too? No
				if domain == da {
					isExcluded = true
					break
				}
			}
			if isExcluded {
				break
			}
		}
		if isExcluded {
			return false // Rule ignored because denyallow matched
		}
	}

	return true
}
