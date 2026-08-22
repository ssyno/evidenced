package core

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ssyno/evidenced/evidence"
	"github.com/ssyno/evidenced/mapping"
)

// TargetTypeCollectorRun is the target type of records that document a
// collection attempt itself (currently only failures).
const TargetTypeCollectorRun = "evidenced/collector-run"

// Scheduler runs all registered collectors on a fixed interval, maps
// their records to controls, and appends them to the store. A failing
// collector is recorded as evidence and never stops the run.
type Scheduler struct {
	Registry *Registry
	Store    Store
	Mapping  *mapping.Mapping
	Interval time.Duration
	Clock    func() time.Time // defaults to time.Now
	Log      *slog.Logger     // defaults to slog.Default
}

func (s *Scheduler) now() time.Time {
	if s.Clock != nil {
		return s.Clock()
	}
	return time.Now().UTC()
}

func (s *Scheduler) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// RunOnce executes a single collection cycle. Only store failures return
// an error; collector failures are converted into evidence records.
func (s *Scheduler) RunOnce(ctx context.Context) error {
	for _, c := range s.Registry.All() {
		records, err := c.Collect(ctx)
		if err != nil {
			s.log().Warn("collector failed", "collector", c.ID(), "error", err)
			records = []evidence.Record{{
				CollectorID:      c.ID(),
				CollectorVersion: c.Version(),
				Target:           evidence.Target{Type: TargetTypeCollectorRun, Name: c.ID()},
				CollectedAt:      s.now(),
				Outcome:          evidence.OutcomeFailed,
				Error:            err.Error(),
			}}
		}
		for i := range records {
			if records[i].CollectedAt.IsZero() {
				records[i].CollectedAt = s.now()
			}
			if s.Mapping != nil {
				s.Mapping.Apply(&records[i])
			}
			if err := s.Store.Append(&records[i]); err != nil {
				return fmt.Errorf("append record from %s: %w", c.ID(), err)
			}
		}
		s.log().Info("collector run complete", "collector", c.ID(), "records", len(records))
	}
	return nil
}

// Run executes a cycle immediately, then on every interval tick until ctx
// is cancelled.
func (s *Scheduler) Run(ctx context.Context) error {
	if err := s.RunOnce(ctx); err != nil {
		return err
	}
	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := s.RunOnce(ctx); err != nil {
				return err
			}
		}
	}
}
