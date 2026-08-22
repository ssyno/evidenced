package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ssyno/evidenced/internal/evidence"
)

func populatedStore(t *testing.T) *FileStore {
	t.Helper()
	store, err := OpenFileStore(filepath.Join(t.TempDir(), "evidence.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() }) //nolint:errcheck

	m, err := LoadMapping([]byte(testMappingYAML))
	if err != nil {
		t.Fatal(err)
	}
	records := []evidence.Record{
		{
			CollectorID: "certs", CollectorVersion: "1",
			Target:      evidence.Target{Type: "tls/certificate", Name: "web"},
			CollectedAt: time.Date(2026, 8, 22, 9, 0, 0, 0, time.UTC),
			Outcome:     evidence.OutcomeObserved,
			Observation: json.RawMessage(`{"expiry":"2026-12-01T00:00:00Z"}`),
		},
		{
			CollectorID: "certs", CollectorVersion: "1",
			Target:      evidence.Target{Type: "evidenced/collector-run", Name: "certs"},
			CollectedAt: time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC),
			Outcome:     evidence.OutcomeFailed,
			Error:       "timeout",
		},
	}
	for i := range records {
		m.Apply(&records[i])
		if err := store.Append(&records[i]); err != nil {
			t.Fatal(err)
		}
	}
	return store
}

func TestExportAndVerifyBundleSigned(t *testing.T) {
	store := populatedStore(t)
	m, err := LoadMapping([]byte(testMappingYAML))
	if err != nil {
		t.Fatal(err)
	}
	key, err := evidence.GenerateSigningKey(filepath.Join(t.TempDir(), "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	exp := &Exporter{
		Store: store, Mapping: m, Key: key,
		Clock: func() time.Time { return time.Date(2026, 8, 22, 11, 0, 0, 0, time.UTC) },
	}
	dir, err := exp.Export(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"evidence.json", "report.md", "manifest.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("bundle missing %s: %v", f, err)
		}
	}
	if err := VerifyBundle(dir); err != nil {
		t.Errorf("VerifyBundle = %v, want nil", err)
	}

	report, err := os.ReadFile(filepath.Join(dir, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Collection failures",
		"Certificate hygiene", // control title resolved from mapping
		"ed25519 signature",
		"Framework: TESTFW",
	} {
		if !strings.Contains(string(report), want) {
			t.Errorf("report.md missing %q", want)
		}
	}
}

func TestVerifyBundleDetectsTampering(t *testing.T) {
	store := populatedStore(t)
	exp := &Exporter{Store: store}
	dir, err := exp.Export(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(dir, "report.md")
	b, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reportPath, append(b, []byte("\nedited after export\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(dir); err == nil {
		t.Error("VerifyBundle(tampered) = nil error, want checksum failure")
	}
}

func TestExportRefusesTamperedStore(t *testing.T) {
	store := populatedStore(t)
	// Tamper on disk behind the open handle.
	b, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(b), `"name":"web"`, `"name":"evil"`, 1)
	if err := os.WriteFile(store.path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	exp := &Exporter{Store: store}
	if _, err := exp.Export(t.TempDir()); err == nil {
		t.Error("Export(tampered store) = nil error, want refusal")
	}
}

func TestSigningKeyRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	generated, err := evidence.GenerateSigningKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evidence.GenerateSigningKey(path); err == nil {
		t.Error("GenerateSigningKey must refuse to overwrite an existing key")
	}
	loaded, err := evidence.LoadSigningKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !generated.Equal(loaded) {
		t.Error("loaded key differs from generated key")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file permissions = %o, want 600", perm)
	}
}
