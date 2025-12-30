package updater

import (
	"log"
	"time"

	"adblocker/config"
	"adblocker/engine"
	"adblocker/parser"
)

// Updater manages periodic updates of rule sources.
type Updater struct {
	cfg    *config.Config
	engine *engine.Engine
	loader *parser.Loader
	stop   chan struct{}
}

// NewUpdater creates a new Updater.
func NewUpdater(cfg *config.Config, eng *engine.Engine, loader *parser.Loader) *Updater {
	return &Updater{
		cfg:    cfg,
		engine: eng,
		loader: loader,
		stop:   make(chan struct{}),
	}
}

func (u *Updater) Stop() {
	close(u.stop)
}

// RunSimple is a simplified version: Reload ALL rules every X minutes (e.g. 1 hour default).
// If any source has interval < 1 hour, use that.
func (u *Updater) RunSimple() {
	minInterval := 24 * time.Hour

	hasRemote := false
	for _, rg := range u.cfg.RuleGroups {
		for _, src := range rg.Sources {
			if src.URL != "" {
				hasRemote = true
				break
			}
		}
		if hasRemote {
			break
		}
	}

	// Use global interval, but enforce minimum 24 hours
	if u.cfg.URLInterval > 0 {
		minInterval = u.cfg.URLInterval
	}
	if minInterval < 24*time.Hour {
		minInterval = 24 * time.Hour
	}

	if !hasRemote {
		log.Println("No remote sources to update.")
		return
	}

	log.Printf("Updater started. Next update in %v", minInterval)

	go func() {
		for {
			select {
			case <-time.After(minInterval):
				log.Println("Updater triggered...")
				u.engine.ReloadRules(u.loader)
				log.Printf("Update complete. Next in %v", minInterval)
			case <-u.stop:
				return
			}
		}
	}()
}
