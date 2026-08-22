// Package core is the platform-agnostic engine of evidenced: collector
// contract, evidence store, control mapping, scheduling, and export. It
// must never import Kubernetes or cloud SDKs.
package core

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/ssyno/evidenced/internal/evidence"
)

// AccessRequirement declares, in the collector's own vocabulary, what
// read-only access it needs. Shells use this to document and provision
// credentials; nothing in core interprets it.
type AccessRequirement struct {
	System      string `json:"system"`      // e.g. "kubernetes", "network"
	Resource    string `json:"resource"`    // e.g. "cert-manager.io/certificates"
	Access      string `json:"access"`      // e.g. "get,list,watch"
	Description string `json:"description"` // why the collector needs it
}

// Collector is the contract every evidence collector implements.
// Collectors are strictly read-only observers: they must never mutate
// what they observe, and must never place secret values in records.
type Collector interface {
	ID() string
	Version() string
	Description() string
	RequiredAccess() []AccessRequirement
	Collect(ctx context.Context) ([]evidence.Record, error)
}

// Registry holds the collectors a shell has wired up for this process.
type Registry struct {
	mu         sync.RWMutex
	collectors map[string]Collector
}

func NewRegistry() *Registry {
	return &Registry{collectors: map[string]Collector{}}
}

func (r *Registry) Register(c Collector) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.collectors[c.ID()]; exists {
		return fmt.Errorf("collector %q registered twice", c.ID())
	}
	r.collectors[c.ID()] = c
	return nil
}

// All returns registered collectors sorted by ID for deterministic runs.
func (r *Registry) All() []Collector {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Collector, 0, len(r.collectors))
	for _, c := range r.collectors {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

func (r *Registry) Get(id string) (Collector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.collectors[id]
	return c, ok
}
