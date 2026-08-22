// Command evidenced is the single static binary for continuous compliance
// evidence collection. A subcommand selects the deployment shell.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/ssyno/evidenced/internal/shells/cli"
	"github.com/ssyno/evidenced/internal/shells/daemon"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "evidenced: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	ctx := context.Background()
	args := os.Args[2:]
	cliOpts := cli.Options{Stdout: os.Stdout}

	switch os.Args[1] {
	case "collect":
		return cli.Collect(ctx, args, cliOpts)
	case "export":
		return cli.Export(args, cliOpts)
	case "verify":
		return cli.Verify(args, cliOpts)
	case "verify-bundle":
		return cli.VerifyBundle(args, cliOpts)
	case "daemon":
		log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
		return daemon.Run(ctx, args, daemon.Options{Log: log})
	case "operator":
		return fmt.Errorf("operator shell is not implemented yet")
	case "version":
		fmt.Println(version)
		return nil
	default:
		fmt.Fprintf(os.Stderr, "evidenced: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
		return nil
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `Usage: evidenced <command>

Commands:
  collect        run one collection cycle (--report to also export a bundle)
  export         export an evidence bundle from the existing store
  verify         verify the evidence store's hash chain
  verify-bundle  verify an exported bundle's checksums and signature
  daemon         long-running collection on a VM (YAML config)
  operator       Kubernetes operator (CRD-driven config)
  version        print version
`)
}
