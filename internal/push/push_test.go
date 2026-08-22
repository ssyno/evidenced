package push

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ssyno/evidenced/internal/core"
)

func writeBundle(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"evidence.json": `{"records":[]}`,
		"report.md":     "# report",
		"manifest.json": `{"files":{}}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

type captured struct {
	auth  string
	agent string
	files map[string]string
}

func fakePortal(t *testing.T, status int) (*httptest.Server, *captured) {
	t.Helper()
	got := &captured{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/bundles" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		got.auth = r.Header.Get("Authorization")
		got.agent = r.Header.Get("X-Evidenced-Agent")
		got.files = map[string]string{}
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Errorf("body not gzip: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		tr := tar.NewReader(gz)
		for {
			hdr, err := tr.Next()
			if err != nil {
				break
			}
			b, _ := io.ReadAll(tr)
			got.files[hdr.Name] = string(b)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"id":"x"}`))
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func TestPushUploadsBundle(t *testing.T) {
	srv, got := fakePortal(t, http.StatusCreated)
	t.Setenv("EVD_TEST_TOKEN", "evd_secret")

	p, err := New(core.PushConfig{URL: srv.URL, TokenEnv: "EVD_TEST_TOKEN", Agent: "prod-cluster"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Push(context.Background(), writeBundle(t)); err != nil {
		t.Fatal(err)
	}
	if got.auth != "Bearer evd_secret" {
		t.Errorf("auth header = %q", got.auth)
	}
	if got.agent != "prod-cluster" {
		t.Errorf("agent header = %q", got.agent)
	}
	if len(got.files) != 3 || got.files["report.md"] != "# report" {
		t.Errorf("uploaded files = %v", got.files)
	}
}

func TestPushTokenFromFile(t *testing.T) {
	srv, got := fakePortal(t, http.StatusCreated)
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("evd_filetoken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := New(core.PushConfig{URL: srv.URL, TokenFile: tokenPath})
	if err != nil {
		t.Fatal(err)
	}
	if p.Agent() == "" {
		t.Error("agent should default to hostname")
	}
	if err := p.Push(context.Background(), writeBundle(t)); err != nil {
		t.Fatal(err)
	}
	if got.auth != "Bearer evd_filetoken" {
		t.Errorf("auth header = %q (whitespace not trimmed?)", got.auth)
	}
}

func TestPushPortalRejection(t *testing.T) {
	srv, _ := fakePortal(t, http.StatusUnauthorized)
	t.Setenv("EVD_TEST_TOKEN", "revoked")
	p, err := New(core.PushConfig{URL: srv.URL, TokenEnv: "EVD_TEST_TOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	err = p.Push(context.Background(), writeBundle(t))
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("Push = %v, want portal 401 error", err)
	}
}

func TestPushMissingToken(t *testing.T) {
	srv, _ := fakePortal(t, http.StatusCreated)
	p, err := New(core.PushConfig{URL: srv.URL, TokenEnv: "EVD_UNSET_VAR"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Push(context.Background(), writeBundle(t)); err == nil {
		t.Error("Push with empty token env = nil error, want failure")
	}
}

func TestNewValidation(t *testing.T) {
	tests := []struct {
		name string
		cfg  core.PushConfig
	}{
		{"http to non-loopback", core.PushConfig{URL: "http://portal.example.com", TokenEnv: "X"}},
		{"no token source", core.PushConfig{URL: "https://portal.example.com"}},
		{"both token sources", core.PushConfig{URL: "https://portal.example.com", TokenEnv: "A", TokenFile: "/b"}},
		{"garbage url", core.PushConfig{URL: "://", TokenEnv: "X"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.cfg); err == nil {
				t.Error("New = nil error, want validation failure")
			}
		})
	}
	// https and loopback-http are both fine.
	if _, err := New(core.PushConfig{URL: "https://portal.example.com", TokenEnv: "X"}); err != nil {
		t.Errorf("https url rejected: %v", err)
	}
	if _, err := New(core.PushConfig{URL: "http://127.0.0.1:8090", TokenEnv: "X"}); err != nil {
		t.Errorf("loopback http rejected: %v", err)
	}
}
