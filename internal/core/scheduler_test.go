package core

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ssyno/evidenced/internal/evidence"
)

type fakeCollector struct {
	id      string
	records []evidence.Record
	err     error
	calls   int
}

func (f *fakeCollector) ID() string          { return f.id }
func (f *fakeCollector) Version() string     { return "0.0.1" }
func (f *fakeCollector) Description() string { return "fake" }
func (f *fakeCollector) RequiredAccess() []AccessRequirement {
	return nil
}
func (f *fakeCollector) Collect(context.Context) ([]evidence.Record, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	out := make([]evidence.Record, len(f.records))
	copy(out, f.records)
	return out, nil
}

func testScheduler(t *testing.T, collectors ...Collector) (*Scheduler, *FileStore) {
	t.Helper()
	reg := NewRegistry()
	for _, c := range collectors {
		if err := reg.Register(c); err != nil {
			t.Fatal(err)
		}
	}
	store, err := OpenFileStore(filepath.Join(t.TempDir(), "evidence.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() }) //nolint:errcheck
	m, err := LoadMapping([]byte(testMappingYAML))
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 8, 22, 9, 0, 0, 0, time.UTC)
	return &Scheduler{
		Registry: reg,
		Store:    store,
		Mapping:  m,
		Interval: time.Minute,
		Clock:    func() time.Time { return clock },
	}, store
}

func TestRunOnceCollectsMapsAndStores(t *testing.T) {
	c := &fakeCollector{
		id: "certs",
		records: []evidence.Record{{
			CollectorID:      "certs",
			CollectorVersion: "0.0.1",
			Target:           evidence.Target{Type: "tls/certificate", Name: "web"},
			Outcome:          evidence.OutcomeObserved,
		}},
	}
	s, store := testScheduler(t, c)
	if err := s.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	records, err := store.All()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	r := records[0]
	if want := []string{"fw-1", "fw-2"}; len(r.ControlIDs) != 2 || r.ControlIDs[0] != want[0] || r.ControlIDs[1] != want[1] {
		t.Errorf("ControlIDs = %v, want %v", r.ControlIDs, want)
	}
	if r.CollectedAt.IsZero() {
		t.Error("CollectedAt was not defaulted")
	}
	if r.Hash == "" {
		t.Error("record was not sealed")
	}
}

func TestRunOnceRecordsCollectorFailureAsEvidence(t *testing.T) {
	ok := &fakeCollector{
		id: "rbac",
		records: []evidence.Record{{
			CollectorID: "rbac",
			Target:      evidence.Target{Type: "rbac/clusterrole", Name: "admin"},
			Outcome:     evidence.OutcomeObserved,
		}},
	}
	broken := &fakeCollector{id: "certs", err: errors.New("api unreachable")}

	s, store := testScheduler(t, ok, broken)
	if err := s.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce must not fail on collector error, got %v", err)
	}
	records, err := store.All()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2 (failure evidence + rbac observation)", len(records))
	}
	// Registry is sorted by ID, so "certs" (the failure) runs first.
	fail := records[0]
	if fail.Outcome != evidence.OutcomeFailed {
		t.Errorf("failure record outcome = %q", fail.Outcome)
	}
	if fail.Target.Type != TargetTypeCollectorRun {
		t.Errorf("failure record target type = %q", fail.Target.Type)
	}
	if fail.Error != "api unreachable" {
		t.Errorf("failure record error = %q", fail.Error)
	}
	if err := store.Verify(); err != nil {
		t.Errorf("Verify = %v", err)
	}
}

func TestRunLoopsUntilCancelled(t *testing.T) {
	c := &fakeCollector{id: "certs", records: []evidence.Record{{
		CollectorID: "certs",
		Target:      evidence.Target{Type: "tls/certificate", Name: "web"},
		Outcome:     evidence.OutcomeObserved,
	}}}
	s, _ := testScheduler(t, c)
	s.Interval = 10 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := s.Run(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Run = %v, want deadline exceeded", err)
	}
	if c.calls < 2 {
		t.Errorf("collector ran %d times, want at least 2 (initial + tick)", c.calls)
	}
}

func TestRegistryRejectsDuplicate(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(&fakeCollector{id: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(&fakeCollector{id: "x"}); err == nil {
		t.Error("duplicate Register = nil error, want failure")
	}
}
