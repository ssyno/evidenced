package core

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ssyno/evidenced/evidence"
)

func newRecord(name string) evidence.Record {
	return evidence.Record{
		CollectorID:      "test",
		CollectorVersion: "0.1.0",
		Target:           evidence.Target{Type: "test/thing", Name: name},
		CollectedAt:      time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC),
		Outcome:          evidence.OutcomeObserved,
	}
}

func TestFileStoreAppendAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store", "evidence.jsonl")

	s, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b", "c"} {
		r := newRecord(name)
		if err := s.Append(&r); err != nil {
			t.Fatalf("append %s: %v", name, err)
		}
	}
	if s.Count() != 3 {
		t.Errorf("Count() = %d, want 3", s.Count())
	}
	if err := s.Verify(); err != nil {
		t.Errorf("Verify() = %v, want nil", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen: chain must resume, not restart.
	s2, err := OpenFileStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close() //nolint:errcheck
	r := newRecord("d")
	if err := s2.Append(&r); err != nil {
		t.Fatal(err)
	}
	records, err := s2.All()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 4 {
		t.Fatalf("got %d records after reopen, want 4", len(records))
	}
	if records[3].PrevHash != records[2].Hash {
		t.Errorf("resumed chain broken: PrevHash %q != %q", records[3].PrevHash, records[2].Hash)
	}
	if err := evidence.Verify(records); err != nil {
		t.Errorf("Verify after resume = %v, want nil", err)
	}
}

func TestFileStoreRefusesTamperedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	s, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b"} {
		r := newRecord(name)
		if err := s.Append(&r); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(b), `"name":"a"`, `"name":"z"`, 1)
	if tampered == string(b) {
		t.Fatal("tamper substitution did not apply")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := OpenFileStore(path); err == nil {
		t.Fatal("OpenFileStore(tampered) = nil error, want chain verification failure")
	}
}

func TestFileStoreRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.jsonl")
	s, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck

	base := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	for i, name := range []string{"a", "b", "c"} {
		r := newRecord(name)
		r.CollectedAt = base.Add(time.Duration(i) * time.Hour)
		if err := s.Append(&r); err != nil {
			t.Fatal(err)
		}
	}
	oldHead := s.chain.LastHash()

	// Not old enough: no rotation.
	archive, err := s.MaybeRotate(720*time.Hour, base.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if archive != "" {
		t.Fatalf("rotated too early: %s", archive)
	}

	// Old enough: rotate.
	now := base.Add(31 * 24 * time.Hour)
	archive, err = s.MaybeRotate(720*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if archive == "" {
		t.Fatal("expected rotation")
	}

	// Archived segment is intact and verifiable.
	archived, err := ReadStoreRecords(archive)
	if err != nil {
		t.Fatal(err)
	}
	if len(archived) != 3 {
		t.Fatalf("archive has %d records, want 3", len(archived))
	}
	if err := evidence.Verify(archived); err != nil {
		t.Errorf("archived chain broken: %v", err)
	}

	// New chain starts with a rotation record linking to the old head.
	records, err := s.All()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Target.Type != TargetTypeChainRotation {
		t.Fatalf("new chain = %+v, want single rotation record", records)
	}
	if records[0].PrevHash != "" {
		t.Error("rotation record must be the new genesis")
	}
	var obs struct {
		PreviousChainHead    string `json:"previousChainHead"`
		PreviousChainRecords int    `json:"previousChainRecords"`
		ArchivedTo           string `json:"archivedTo"`
	}
	if err := json.Unmarshal(records[0].Observation, &obs); err != nil {
		t.Fatal(err)
	}
	if obs.PreviousChainHead != oldHead || obs.PreviousChainRecords != 3 {
		t.Errorf("rotation observation = %+v, want head %s", obs, oldHead)
	}
	if obs.ArchivedTo != filepath.Base(archive) {
		t.Errorf("archivedTo = %q, want %q", obs.ArchivedTo, filepath.Base(archive))
	}

	// New chain keeps working and verifying after rotation.
	r := newRecord("post-rotation")
	if err := s.Append(&r); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(); err != nil {
		t.Errorf("post-rotation chain: %v", err)
	}

	// Immediate re-check must not rotate again (fresh firstAt).
	archive2, err := s.MaybeRotate(720*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if archive2 != "" {
		t.Error("rotated twice for the same window")
	}
}

func TestSchedulerRotatesBeforeCollecting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	store, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close() //nolint:errcheck

	base := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	r := newRecord("old")
	r.CollectedAt = base
	if err := store.Append(&r); err != nil {
		t.Fatal(err)
	}

	reg := NewRegistry()
	if err := reg.Register(&fakeCollector{id: "certs", records: []evidence.Record{{
		CollectorID: "certs",
		Target:      evidence.Target{Type: "tls/certificate", Name: "web"},
		Outcome:     evidence.OutcomeObserved,
	}}}); err != nil {
		t.Fatal(err)
	}
	sched := &Scheduler{
		Registry:    reg,
		Store:       store,
		Interval:    time.Minute,
		RotateAfter: 720 * time.Hour,
		Clock:       func() time.Time { return base.Add(31 * 24 * time.Hour) },
	}
	if err := sched.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	records, err := store.All()
	if err != nil {
		t.Fatal(err)
	}
	// rotation record + fresh collection; the old record lives in the archive.
	if len(records) != 2 || records[0].Target.Type != TargetTypeChainRotation {
		t.Fatalf("records after rotating cycle = %+v", records)
	}
	if err := evidence.Verify(records); err != nil {
		t.Errorf("chain after rotation: %v", err)
	}
}

func TestFileStoreEmptyFileIsValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	s, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close() //nolint:errcheck
	records, err := s.All()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Errorf("fresh store has %d records, want 0", len(records))
	}
}
