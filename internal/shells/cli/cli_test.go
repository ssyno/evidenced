package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// End-to-end through the CLI shell: YAML config -> collect from a live
// TLS endpoint -> signed export -> independent bundle verification.
func TestCollectReportVerifyRoundTrip(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	endpoint := srv.Listener.Addr().String()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "evidenced.yaml")
	config := fmt.Sprintf(`
storePath: %s/evidence.jsonl
interval: 1h
export:
  dir: %s/reports
signing:
  keyPath: %s/signing.pem
collectors:
  tlsscan:
    enabled: true
    settings:
      endpoints: ["%s"]
`, dir, dir, dir, endpoint)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	opts := Options{Stdout: &out}

	if err := Collect(context.Background(), []string{"-config", configPath, "-report"}, opts); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if !strings.Contains(out.String(), "collected: 1 records") {
		t.Errorf("collect output = %q", out.String())
	}

	// The bundle path is the second line: "bundle: <dir>".
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	bundleDir := strings.TrimPrefix(lines[len(lines)-1], "bundle: ")
	if _, err := os.Stat(filepath.Join(bundleDir, "manifest.json")); err != nil {
		t.Fatalf("bundle not written: %v", err)
	}

	// Evidence must be mapped to DORA controls end to end.
	b, err := os.ReadFile(filepath.Join(bundleDir, "evidence.json")) // #nosec G304
	if err != nil {
		t.Fatal(err)
	}
	var bundle struct {
		Framework string `json:"framework"`
		Records   []struct {
			ControlIDs []string `json:"controlIds"`
		} `json:"records"`
	}
	if err := json.Unmarshal(b, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.Framework != "DORA" {
		t.Errorf("framework = %q", bundle.Framework)
	}
	if len(bundle.Records) != 1 || len(bundle.Records[0].ControlIDs) == 0 {
		t.Errorf("record not mapped to controls: %+v", bundle.Records)
	}

	out.Reset()
	if err := Verify([]string{"-config", configPath}, opts); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !strings.Contains(out.String(), "chain intact") {
		t.Errorf("verify output = %q", out.String())
	}

	out.Reset()
	if err := VerifyBundle([]string{bundleDir}, opts); err != nil {
		t.Fatalf("verify-bundle: %v", err)
	}

	// A second cycle plus export must keep extending the same chain.
	out.Reset()
	if err := Collect(context.Background(), []string{"-config", configPath}, opts); err != nil {
		t.Fatalf("second collect: %v", err)
	}
	if !strings.Contains(out.String(), "collected: 2 records") {
		t.Errorf("second collect output = %q", out.String())
	}
	out.Reset()
	if err := Export([]string{"-config", configPath}, opts); err != nil {
		t.Fatalf("export: %v", err)
	}
}

func TestCollectRejectsUnknownCollector(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "evidenced.yaml")
	config := fmt.Sprintf("storePath: %s/e.jsonl\ncollectors:\n  nonexistent:\n    enabled: true\n", dir)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Collect(context.Background(), []string{"-config", configPath}, Options{Stdout: &bytes.Buffer{}})
	if err == nil || !strings.Contains(err.Error(), "not available in this shell") {
		t.Errorf("Collect = %v, want unknown-collector error", err)
	}
}

func TestVerifyBundleUsage(t *testing.T) {
	if err := VerifyBundle(nil, Options{Stdout: &bytes.Buffer{}}); err == nil {
		t.Error("VerifyBundle with no args = nil error, want usage error")
	}
}
