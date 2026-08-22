// Package cli is the one-shot shell: collect once, export, verify. It is
// what CI pipelines and auditors run.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/ssyno/evidenced/bundle"
	"github.com/ssyno/evidenced/internal/core"
	"github.com/ssyno/evidenced/internal/shells/wiring"
)

// Factories lets callers (main) inject platform collector constructors
// so the CLI can also run Kubernetes collectors when a kubeconfig is
// available.
type Options struct {
	Factories map[string]wiring.Factory
	Stdout    io.Writer
}

// Collect runs one collection cycle; with report=true it also exports a
// bundle and prints its path.
func Collect(ctx context.Context, args []string, opts Options) error {
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	configPath := fs.String("config", "evidenced.yaml", "path to config file")
	report := fs.Bool("report", false, "export an evidence bundle after collecting")
	if err := fs.Parse(args); err != nil {
		return err
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

	if err := engine.Scheduler.RunOnce(ctx); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(opts.Stdout, "collected: %d records in store %s\n", engine.Store.Count(), cfg.StorePath)

	if *report {
		dir, err := engine.Exporter.Export(cfg.Export.Dir)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(opts.Stdout, "bundle: %s\n", dir)
	}
	return nil
}

// Export produces a bundle from the existing store without collecting.
func Export(args []string, opts Options) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	configPath := fs.String("config", "evidenced.yaml", "path to config file")
	if err := fs.Parse(args); err != nil {
		return err
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

	dir, err := engine.Exporter.Export(cfg.Export.Dir)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(opts.Stdout, "bundle: %s\n", dir)
	return nil
}

// Verify checks the integrity of the evidence store's hash chain.
func Verify(args []string, opts Options) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	configPath := fs.String("config", "evidenced.yaml", "path to config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := core.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	store, err := core.OpenFileStore(cfg.StorePath)
	if err != nil {
		return fmt.Errorf("store failed verification: %w", err)
	}
	defer store.Close() //nolint:errcheck
	_, _ = fmt.Fprintf(opts.Stdout, "store %s: %d records, chain intact\n", cfg.StorePath, store.Count())
	return nil
}

// VerifyBundle checks an exported bundle's checksums and signature.
func VerifyBundle(args []string, opts Options) error {
	fs := flag.NewFlagSet("verify-bundle", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: evidenced verify-bundle <bundle-dir>")
	}
	dir := fs.Arg(0)
	if err := bundle.Verify(dir); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(opts.Stdout, "bundle %s: checksums and signature valid\n", dir)
	return nil
}
