// Package cloudconfig reserves the collector slot for cloud provider
// configuration evidence (IAM posture, storage encryption, network
// exposure). Deliberately a stub: out of MVP scope, do not implement yet.
package cloudconfig

import (
	"errors"

	"github.com/ssyno/evidenced/internal/core"
)

// New always fails: the collector exists as an interface reservation
// only. Enabling "cloudconfig" in config surfaces this error clearly.
func New() (core.Collector, error) {
	return nil, errors.New("cloudconfig collector is not implemented (out of MVP scope)")
}
