// Package wiring assembles the core engine from a Config: registry of
// enabled collectors, store, framework mapping, and signing key. Every
// shell uses it, so all shells expose identical behavior for the same
// YAML. Platform-specific collector constructors are injected by shells
// via Factories; wiring itself stays importable everywhere.
package wiring

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"maps"
	"os"

	"github.com/ssyno/evidenced/evidence"
	"github.com/ssyno/evidenced/internal/collectors/tlsscan"
	"github.com/ssyno/evidenced/internal/core"
	"github.com/ssyno/evidenced/internal/push"
	"github.com/ssyno/evidenced/mapping"
	"github.com/ssyno/evidenced/mapping/dora"
)

// Factory builds a collector from its settings block in the config.
type Factory func(cfg core.CollectorConfig) (core.Collector, error)

// builtin factories are available in every shell (no platform access
// beyond outbound network needed).
func builtin() map[string]Factory {
	return map[string]Factory{
		"tlsscan": func(cc core.CollectorConfig) (core.Collector, error) {
			var tcfg tlsscan.Config
			if err := cc.DecodeSettings(&tcfg); err != nil {
				return nil, err
			}
			return tlsscan.New(tcfg)
		},
	}
}

// Engine is the assembled, ready-to-run core.
type Engine struct {
	Config    *core.Config
	Registry  *core.Registry
	Store     *core.FileStore
	Mapping   *mapping.Mapping
	Scheduler *core.Scheduler
	Exporter  *core.Exporter
	// Pusher is nil unless the config opts into portal upload.
	Pusher *push.Pusher
}

// ExportAndPush exports a bundle and, when push is configured, uploads
// it. A failed upload is returned alongside the bundle path so callers
// can log it without discarding the export — collection and export
// never depend on portal availability.
func (e *Engine) ExportAndPush(ctx context.Context) (string, error) {
	dir, err := e.Exporter.Export(e.Config.Export.Dir)
	if err != nil {
		return "", err
	}
	if e.Pusher == nil {
		return dir, nil
	}
	if err := e.Pusher.Push(ctx, dir); err != nil {
		return dir, fmt.Errorf("bundle exported to %s but upload failed: %w", dir, err)
	}
	return dir, nil
}

// Build assembles an Engine. extra provides shell-specific collector
// factories (e.g. Kubernetes collectors); it may be nil.
func Build(cfg *core.Config, extra map[string]Factory) (*Engine, error) {
	factories := builtin()
	maps.Copy(factories, extra)

	reg := core.NewRegistry()
	for id, cc := range cfg.Collectors {
		if !cc.Enabled {
			continue
		}
		f, ok := factories[id]
		if !ok {
			return nil, fmt.Errorf("collector %q is enabled but not available in this shell", id)
		}
		c, err := f(cc)
		if err != nil {
			return nil, fmt.Errorf("configure collector %q: %w", id, err)
		}
		if err := reg.Register(c); err != nil {
			return nil, err
		}
	}

	mapping, err := dora.Load()
	if err != nil {
		return nil, fmt.Errorf("load DORA mapping: %w", err)
	}

	store, err := core.OpenFileStore(cfg.StorePath)
	if err != nil {
		return nil, err
	}

	key, err := loadOrCreateKey(cfg.Signing.KeyPath)
	if err != nil {
		_ = store.Close()
		return nil, err
	}

	var pusher *push.Pusher
	if cfg.Push.Enabled() {
		if pusher, err = push.New(cfg.Push); err != nil {
			_ = store.Close()
			return nil, err
		}
	}

	return &Engine{
		Pusher: pusher,
		Config:   cfg,
		Registry: reg,
		Store:    store,
		Mapping:  mapping,
		Scheduler: &core.Scheduler{
			Registry:    reg,
			Store:       store,
			Mapping:     mapping,
			Interval:    cfg.Interval,
			RotateAfter: cfg.StoreRotateAfter,
		},
		Exporter: &core.Exporter{Store: store, Mapping: mapping, Key: key},
	}, nil
}

func (e *Engine) Close() error {
	return e.Store.Close()
}

// loadOrCreateKey loads the signing key, generating it on first run. An
// empty path disables signing (bundles are checksummed only).
func loadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, nil
	}
	key, err := evidence.LoadSigningKey(path)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err = evidence.GenerateSigningKey(path)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	return key, nil
}
