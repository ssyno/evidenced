// Package evidence defines the immutable evidence record and the SHA-256
// hash chain that makes tampering with stored evidence detectable.
package evidence

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// Outcome states whether a collection attempt produced an observation or
// failed. Failures are recorded as evidence, not dropped: an auditor needs
// to know collection did not happen.
type Outcome string

const (
	OutcomeObserved Outcome = "observed"
	OutcomeFailed   Outcome = "collection-failed"
)

// Target identifies what a record is about. It is platform-agnostic; any
// platform-specific identity (namespace, cluster, endpoint) goes into
// Attributes.
type Target struct {
	Type       string            `json:"type"`
	Name       string            `json:"name"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// Record is a single piece of collected evidence. Once sealed into a chain
// it is immutable: any later modification is detected by Verify.
type Record struct {
	ID               string          `json:"id"`
	CollectorID      string          `json:"collectorId"`
	CollectorVersion string          `json:"collectorVersion"`
	Target           Target          `json:"target"`
	CollectedAt      time.Time       `json:"collectedAt"`
	Outcome          Outcome         `json:"outcome"`
	Error            string          `json:"error,omitempty"`
	Observation      json.RawMessage `json:"observation,omitempty"`
	ControlIDs       []string        `json:"controlIds,omitempty"`
	PrevHash         string          `json:"prevHash"`
	Hash             string          `json:"hash"`
}

// computeHash hashes the canonical JSON encoding of the record with the
// Hash field cleared. PrevHash is included, which is what links the chain.
func (r Record) computeHash() (string, error) {
	r.Hash = ""
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// NewID returns a random 128-bit hex identifier for a record.
func NewID() string {
	b := make([]byte, 16)
	// crypto/rand.Read is documented to always fill b and never fail.
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
