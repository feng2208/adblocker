package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"adblocker/config"
	"adblocker/engine"
	"adblocker/parser"
	"adblocker/server"
	"adblocker/updater"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	dataDir := flag.String("data", "data", "Path to data directory for caching")
	flag.Parse()

	log.Printf("Starting AdBlocker DNS Server...")

	// 1. Load Config
	cfgMgr := config.NewManager(*configPath)
	if err := cfgMgr.Load(); err != nil {
		log.Printf("Warning: Failed to load config: %v. Using defaults.", err)
	} else {
		log.Printf("Configuration loaded successfully from %s", *configPath)
	}

	cfg := cfgMgr.Get()

	// 2. Initialize Matcher Engine
	eng, err := engine.NewEngine(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize engine: %v", err)
	}

	// 3. Load Rules (Initial)
	loader := parser.NewLoader(*dataDir)
	eng.ReloadRules(loader)

	// 4. Start Updater
	upd := updater.NewUpdater(cfg, eng, loader)
	upd.RunSimple()

	// 5. Start DNS Server
	upstream := cfg.Server.Upstream
	if upstream == "" {
		upstream = "8.8.8.8:53"
	}
	listen := cfg.Server.ListenAddr
	if listen == "" {
		listen = ":53"
	}

	srv := server.NewServer(listen, upstream, eng)

	go func() {
		if err := srv.Start(); err != nil {
			log.Fatalf("DNS Server failed: %v", err)
		}
	}()

	log.Printf("AdBlocker is running on %s", listen)

	// Wait for shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	s := <-sigChan
	log.Printf("Received signal %v, shutting down...", s)

	upd.Stop()
	srv.Stop()
}
