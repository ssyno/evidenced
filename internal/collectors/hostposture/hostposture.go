// Package hostposture reserves the collector slot for host/VM posture
// evidence (OS patch level, disk encryption, service hardening).
// Deliberately a stub: out of MVP scope, do not implement yet.
package hostposture

import (
	"errors"

	"github.com/ssyno/evidenced/internal/core"
)

// New always fails: the collector exists as an interface reservation
// only. Enabling "hostposture" in config surfaces this error clearly.
func New() (core.Collector, error) {
	return nil, errors.New("hostposture collector is not implemented (out of MVP scope)")
}
