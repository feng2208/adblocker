package config

import (
	"time"
)

// Config represents the top-level configuration structure.
type Config struct {
	Server      ServerConfig  `yaml:"server"`
	Users       []User        `yaml:"users"`
	UserGroups  []UserGroup   `yaml:"user_groups"`
	RuleGroups  []RuleGroup   `yaml:"rule_groups"`
	Schedules   []Schedule    `yaml:"schedules"`
	Defaults    DefaultConfig `yaml:"defaults"`
	URLInterval time.Duration `yaml:"url_interval,omitempty"` // Global refresh interval for all URL sources
}

// ServerConfig holds server-specific settings.
type ServerConfig struct {
	ListenAddr string `yaml:"listen_addr"` // e.g., ":53"
	Upstream   string `yaml:"upstream"`    // e.g., "8.8.8.8:53"
}

// DefaultConfig specifies default fallback behaviors.
type DefaultConfig struct {
	UserGroup string `yaml:"user_group"` // Default UserGroup if no user matches
}

// User represents a network client using the service.
type User struct {
	Name      string   `yaml:"name"`
	IPs       []string `yaml:"ips,omitempty"`  // Individual IPs or CIDRs
	MACs      []string `yaml:"macs,omitempty"` // MAC addresses
	UserGroup string   `yaml:"user_group"`     // The group this user belongs to
}

// UserGroup defines a collection of policies.
type UserGroup struct {
	Name     string   `yaml:"name"`
	Policies []Policy `yaml:"policies"`
}

// Policy binds a RuleGroup to a Schedule.
type Policy struct {
	RuleGroup string `yaml:"rule_group"`
	Schedule  string `yaml:"schedule,omitempty"` // Empty means always active
}

// RuleGroup defines a set of ad-blocking rules from various sources.
type RuleGroup struct {
	Name    string   `yaml:"name"`
	Sources []Source `yaml:"sources"`
}

// Source represents a single source of blocking rules.
type Source struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url,omitempty"`  // Remote URL
	Path string `yaml:"path,omitempty"` // Local file path
}

// Schedule defines time windows when a RuleGroup is active.
type Schedule struct {
	Name  string         `yaml:"name"`
	Items []ScheduleItem `yaml:"items"`
}

type ScheduleItem struct {
	// Days of week: "Mon", "Tue", etc. Empty implies all days.
	Days []string `yaml:"days,omitempty"`
	// Time ranges in "HH:MM" format.
	Ranges []string `yaml:"ranges"`
}
