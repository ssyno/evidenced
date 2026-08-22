package core

import (
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
