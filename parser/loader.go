package parser

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// CacheEntry stores cached URL data with timestamp.
type CacheEntry struct {
	FetchedAt time.Time `json:"fetched_at"`
	RulesFile string    `json:"rules_file"` // Relative filename for rules data
}

// Loader handles fetching and parsing rules from various sources.
type Loader struct {
	Client  *http.Client
	DataDir string // Directory for caching URL data
}

// NewLoader creates a new Loader with a default HTTP client.
func NewLoader(dataDir string) *Loader {
	return &Loader{
		Client: &http.Client{
			Timeout: 30 * time.Second,
		},
		DataDir: dataDir,
	}
}

// LoadFromPath reads rules from a local file.
func (l *Loader) LoadFromPath(path string) ([]*Rule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var rules []*Rule
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if rule, err := ParseRule(scanner.Text()); err == nil && rule != nil {
			rules = append(rules, rule)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

func (l *Loader) LoadFromURLWithCache(url string) ([]*Rule, error) {
	cacheKey := urlToCacheKey(url)
	metaFile := filepath.Join(l.DataDir, cacheKey+".meta.json")
	rulesFile := filepath.Join(l.DataDir, cacheKey+".rules.txt")

	// 1. Try to load from cache first
	if _, err := os.Stat(rulesFile); err == nil {
		if rules, loadErr := l.LoadFromPath(rulesFile); loadErr == nil {
			log.Printf("Using cached rules for '%s'", url)
			return rules, nil
		}
		log.Printf("Failed to load cache for '%s': %v", url, err)
	}

	// 2. Fallback: Fetch fresh data
	log.Printf("Fetching rules from '%s'...", url)
	resp, err := l.Client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status: %s", resp.Status)
	}

	// Ensure data dir exists
	if err := os.MkdirAll(l.DataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data dir: %w", err)
	}

	// Write rules to cache file
	cacheFile, err := os.Create(rulesFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create cache file: %w", err)
	}
	defer cacheFile.Close()

	var rules []*Rule
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		cacheFile.WriteString(line + "\n")
		if rule, err := ParseRule(line); err == nil && rule != nil {
			rules = append(rules, rule)
		}
	}

	// Write meta file
	meta := CacheEntry{
		FetchedAt: time.Now(),
		RulesFile: cacheKey + ".rules.txt",
	}
	l.writeCacheMeta(metaFile, meta)

	log.Printf("Cached %d rules from '%s'", len(rules), url)
	return rules, nil
}

func (l *Loader) writeCacheMeta(path string, entry CacheEntry) error {
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func urlToCacheKey(url string) string {
	hash := sha256.Sum256([]byte(url))
	return hex.EncodeToString(hash[:8]) // First 8 bytes (16 chars)
}
