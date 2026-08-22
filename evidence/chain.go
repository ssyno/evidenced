package evidence

import (
	"errors"
	"fmt"
)

// ErrTampered is wrapped by every verification failure so callers can
// detect chain integrity errors with errors.Is.
var ErrTampered = errors.New("evidence chain integrity violation")

// ErrAlreadySealed is returned when a record with a non-empty Hash is
// passed to Seal a second time.
var ErrAlreadySealed = errors.New("record is already sealed")

// Chain seals records into a SHA-256 hash chain. The zero value is not
// usable; use NewChain for a fresh chain or Resume to continue one.
type Chain struct {
	lastHash string
}

// NewChain starts a new chain. The first sealed record gets an empty
// PrevHash, which marks it as the genesis record.
func NewChain() *Chain {
	return &Chain{}
}

// Resume continues an existing chain whose last record hash is lastHash,
// e.g. after a process restart with a persisted store.
func Resume(lastHash string) *Chain {
	return &Chain{lastHash: lastHash}
}

// LastHash returns the hash of the most recently sealed record, or "" if
// nothing has been sealed yet.
func (c *Chain) LastHash() string {
	return c.lastHash
}

// Seal links r to the chain and computes its hash. It mutates r (sets ID
// if empty, PrevHash, Hash); after Seal the record must not be modified.
func (c *Chain) Seal(r *Record) error {
	if r.Hash != "" {
		return fmt.Errorf("seal record %s: %w", r.ID, ErrAlreadySealed)
	}
	if r.ID == "" {
		r.ID = NewID()
	}
	r.PrevHash = c.lastHash
	h, err := r.computeHash()
	if err != nil {
		return fmt.Errorf("seal record %s: %w", r.ID, err)
	}
	r.Hash = h
	c.lastHash = h
	return nil
}

// Verify checks that records form an unbroken, untampered chain starting
// at genesis: each record's PrevHash must equal the previous record's
// Hash, and each record's stored Hash must match its recomputed hash.
func Verify(records []Record) error {
	prev := ""
	for i, r := range records {
		if r.PrevHash != prev {
			return fmt.Errorf("record %d (%s): prevHash %q does not match previous record hash %q: %w",
				i, r.ID, r.PrevHash, prev, ErrTampered)
		}
		h, err := r.computeHash()
		if err != nil {
			return fmt.Errorf("record %d (%s): rehash: %w", i, r.ID, err)
		}
		if h != r.Hash {
			return fmt.Errorf("record %d (%s): stored hash %q does not match recomputed hash %q: %w",
				i, r.ID, r.Hash, h, ErrTampered)
		}
		prev = r.Hash
	}
	return nil
}
