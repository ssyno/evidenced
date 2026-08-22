// Package dora ships the DORA control catalog and collector-to-control
// mapping rules as embedded YAML data. All framework knowledge lives in
// dora.yaml; this file is only glue.
package dora

import (
	_ "embed"

	"github.com/ssyno/evidenced/mapping"
)

//go:embed dora.yaml
var mappingYAML []byte

// Load returns the validated DORA mapping.
func Load() (*mapping.Mapping, error) {
	return mapping.Load(mappingYAML)
}
