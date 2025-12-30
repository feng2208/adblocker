package engine

import (
	"adblocker/parser"
	"strings"
	"sync"
)

// TrieNode represents a node in the domain Trie.
type TrieNode struct {
	children map[string]*TrieNode
	// Rules that specifically match this domain node.
	// For example, "||example.com^" is stored at com->example.
	rules []*parser.Rule
}

// DomainTrie is a thread-safe Trie for domain suffixes.
type DomainTrie struct {
	root *TrieNode
	mu   sync.RWMutex
}

// NewDomainTrie creates a new empty Trie.
func NewDomainTrie() *DomainTrie {
	return &DomainTrie{
		root: &TrieNode{
			children: make(map[string]*TrieNode),
		},
	}
}

// Insert adds a rule to the Trie.
// The domain should be the extracted pattern (e.g. "example.com" for "||example.com^").
func (t *DomainTrie) Insert(rule *parser.Rule) {
	t.mu.Lock()
	defer t.mu.Unlock()

	parts := strings.Split(rule.Pattern, ".")
	node := t.root

	// Insert in reverse order: com -> example
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if node.children == nil {
			node.children = make(map[string]*TrieNode)
		}
		if node.children[part] == nil {
			node.children[part] = &TrieNode{children: make(map[string]*TrieNode)}
		}
		node = node.children[part]
	}

	node.rules = append(node.rules, rule)
}

// SearchTrace collects all rules found along the path of the domain.
// Returns a slice of relevant rules (both whitelist and blocklist).
// Domain should be FQDN (e.g. "ads.example.com").
func (t *DomainTrie) SearchTrace(domain string) []*parser.Rule {
	t.mu.RLock()
	defer t.mu.RUnlock()

	domain = strings.TrimSuffix(domain, ".")
	parts := strings.Split(domain, ".")
	var matchedRules []*parser.Rule

	node := t.root
	// Check matches matching *, or root? AdGuard usually doesn't do global * blocks in this trie way usually.

	// Traverse in reverse: com -> example -> ads
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		node = node.children[part]
		if node == nil {
			break
		}
		// Collect rules at this level
		if len(node.rules) > 0 {
			matchedRules = append(matchedRules, node.rules...)
		}
	}

	return matchedRules
}
