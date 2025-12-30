package server

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

// CacheEntry represents a cached DNS response.
type CacheEntry struct {
	Msg       *dns.Msg
	ExpiresAt time.Time
}

// TTLCache is a thread-safe cache with TTL support.
type TTLCache struct {
	items map[string]CacheEntry
	mu    sync.RWMutex
	stop  chan struct{}
}

// NewTTLCache creates a new cache and starts the cleanup goroutine.
func NewTTLCache() *TTLCache {
	c := &TTLCache{
		items: make(map[string]CacheEntry),
		stop:  make(chan struct{}),
	}
	go c.cleanupLoop()
	return c
}

// Set adds a message to the cache with a specific TTL.
func (c *TTLCache) Set(key string, msg *dns.Msg, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Clone message to prevent mutation of cached item
	cachedMsg := msg.Copy()
	c.items[key] = CacheEntry{
		Msg:       cachedMsg,
		ExpiresAt: time.Now().Add(ttl),
	}
}

// Get retrieves a message if it exists and hasn't expired.
func (c *TTLCache) Get(key string) *dns.Msg {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.items[key]
	if !ok {
		return nil
	}

	if time.Now().After(entry.ExpiresAt) {
		return nil
	}

	return entry.Msg.Copy()
}

// Stop stops the background cleanup goroutine.
func (c *TTLCache) Stop() {
	close(c.stop)
}

func (c *TTLCache) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanup()
		case <-c.stop:
			return
		}
	}
}

func (c *TTLCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.items {
		if now.After(entry.ExpiresAt) {
			delete(c.items, key)
		}
	}
}
