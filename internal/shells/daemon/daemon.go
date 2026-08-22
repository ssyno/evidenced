// Package daemon is the long-running VM/systemd shell: it collects on
// the configured interval until stopped, exporting a bundle after each
// cycle so the newest report is always on disk.
package daemon

import (
	"context"
	"flag"
	"log/slog"
	"os/signal"
	"syscall"
	"time"

	"github.com/ssyno/evidenced/internal/core"
	"github.com/ssyno/evidenced/internal/shells/wiring"
)

type Options struct {
	Factories map[string]wiring.Factory
	Log       *slog.Logger
}

// Run starts the daemon and blocks until SIGINT/SIGTERM or a store
// failure.
func Run(ctx context.Context, args []string, opts Options) error {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/evidenced/config.yaml", "path to config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}

	cfg, err := core.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	engine, err := wiring.Build(cfg, opts.Factories)
	if err != nil {
		return err
	}
	defer engine.Close() //nolint:errcheck
	engine.Scheduler.Log = log

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("evidenced daemon starting",
		"config", *configPath, "store", cfg.StorePath, "interval", cfg.Interval.String(),
		"collectors", len(engine.Registry.All()))

	cycle := func() error {
		if err := engine.Scheduler.RunOnce(ctx); err != nil {
			return err
		}
		dir, err := engine.Exporter.Export(cfg.Export.Dir)
		if err != nil {
			return err
		}
		log.Info("cycle complete", "records", engine.Store.Count(), "bundle", dir)
		return nil
	}

	if err := cycle(); err != nil {
		return err
	}
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info("evidenced daemon stopping")
			return nil
		case <-ticker.C:
			if err := cycle(); err != nil {
				return err
			}
		}
	}
}
