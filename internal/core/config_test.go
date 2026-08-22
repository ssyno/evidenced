package core

import (
	"testing"
	"time"
)

func TestParseConfigDefaults(t *testing.T) {
	cfg, err := ParseConfig([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StorePath != "evidence.jsonl" {
		t.Errorf("StorePath = %q", cfg.StorePath)
	}
	if cfg.Interval != time.Hour {
		t.Errorf("Interval = %s, want 1h", cfg.Interval)
	}
	if cfg.Export.Dir != "reports" {
		t.Errorf("Export.Dir = %q", cfg.Export.Dir)
	}
}

func TestParseConfigFull(t *testing.T) {
	cfg, err := ParseConfig([]byte(`
storePath: /var/lib/evidenced/evidence.jsonl
interval: 30m
export:
  dir: /var/lib/evidenced/reports
signing:
  keyPath: /etc/evidenced/signing.pem
collectors:
  tlsscan:
    enabled: true
    settings:
      endpoints: ["example.com:443", "internal.example.com:8443"]
  rbacposture:
    enabled: false
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Interval != 30*time.Minute {
		t.Errorf("Interval = %s", cfg.Interval)
	}
	if !cfg.Enabled("tlsscan") {
		t.Error("tlsscan should be enabled")
	}
	if cfg.Enabled("rbacposture") || cfg.Enabled("missing") {
		t.Error("disabled/unknown collectors must report not enabled")
	}

	var settings struct {
		Endpoints []string `yaml:"endpoints"`
	}
	if err := cfg.Collectors["tlsscan"].DecodeSettings(&settings); err != nil {
		t.Fatal(err)
	}
	if len(settings.Endpoints) != 2 || settings.Endpoints[0] != "example.com:443" {
		t.Errorf("settings = %+v", settings)
	}
}

func TestParseConfigRejects(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{"unknown field", "storPath: typo.jsonl"},
		{"interval too small", "interval: 5s"},
		{"malformed yaml", "storePath: [unterminated"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseConfig([]byte(tt.yaml)); err == nil {
				t.Error("ParseConfig = nil error, want failure")
			}
		})
	}
}

func TestDecodeSettingsMissingBlock(t *testing.T) {
	cfg, err := ParseConfig([]byte("collectors:\n  x:\n    enabled: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		N int `yaml:"n"`
	}
	if err := cfg.Collectors["x"].DecodeSettings(&v); err != nil {
		t.Errorf("DecodeSettings with no settings block = %v, want nil", err)
	}
}
