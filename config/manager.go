package config

import (
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

// Manager handles thread-safe configuration access and updates.
type Manager struct {
	mu           sync.RWMutex
	current      *Config
	configPath   string
	LoadCallback func(*Config) error // Optional callback after load
}

// NewManager creates a new configuration manager.
func NewManager(path string) *Manager {
	return &Manager{
		configPath: path,
		current:    &Config{}, // Start with empty config
	}
}

// Load reads the configuration file from disk and updates the current state.
func (m *Manager) Load() error {
	data, err := os.ReadFile(m.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var newConfig Config
	if err := yaml.Unmarshal(data, &newConfig); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	// Basic validation could go here

	m.mu.Lock()
	m.current = &newConfig
	m.mu.Unlock()

	if m.LoadCallback != nil {
		if err := m.LoadCallback(&newConfig); err != nil {
			return err
		}
	}

	return nil
}

// Get returns the current configuration safely.
func (m *Manager) Get() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}
