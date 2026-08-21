// Command evidenced is the single static binary for continuous compliance
// evidence collection. A subcommand selects the deployment shell.
package main

import (
	"fmt"
	"os"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "collect", "daemon", "operator":
		fmt.Fprintf(os.Stderr, "evidenced: shell %q is not implemented yet\n", os.Args[1])
		os.Exit(1)
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprintf(os.Stderr, "evidenced: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `Usage: evidenced <command>

Commands:
  collect    one-shot collection and report export (CI mode)
  daemon     long-running collection on a VM (YAML config)
  operator   Kubernetes operator (CRD-driven config)
  version    print version
`)
}
