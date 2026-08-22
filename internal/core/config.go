package core

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the one configuration schema shared by every shell. The
// daemon and CLI read it from a YAML file; the operator translates its
// CRDs into it. Shells must not invent their own knobs.
type Config struct {
	StorePath  string                     `yaml:"storePath"`
	Interval   time.Duration              `yaml:"interval"`
	Export     ExportConfig               `yaml:"export"`
	Signing    SigningConfig              `yaml:"signing"`
	Collectors map[string]CollectorConfig `yaml:"collectors"`
}

type ExportConfig struct {
	Dir string `yaml:"dir"`
}

type SigningConfig struct {
	// KeyPath is an ed25519 private key file. If empty, export bundles
	// are checksummed but not signed.
	KeyPath string `yaml:"keyPath"`
}

// CollectorConfig enables a collector and carries its collector-specific
// settings, which core does not interpret.
type CollectorConfig struct {
	Enabled  bool      `yaml:"enabled"`
	Settings yaml.Node `yaml:"settings"`
}

// DecodeSettings unmarshals the collector-specific settings block into v.
// A missing settings block is not an error; v keeps its zero values.
func (c CollectorConfig) DecodeSettings(v any) error {
	if c.Settings.Kind == 0 {
		return nil
	}
	if err := c.Settings.Decode(v); err != nil {
		return fmt.Errorf("decode collector settings: %w", err)
	}
	return nil
}

// LoadConfig reads and validates a YAML config file, applying defaults.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- path is operator-supplied config
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	return ParseConfig(b)
}

// ParseConfig parses and validates YAML config bytes, applying defaults.
func ParseConfig(b []byte) (*Config, error) {
	cfg := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.StorePath == "" {
		c.StorePath = "evidence.jsonl"
	}
	if c.Interval == 0 {
		c.Interval = time.Hour
	}
	if c.Export.Dir == "" {
		c.Export.Dir = "reports"
	}
	if c.Collectors == nil {
		c.Collectors = map[string]CollectorConfig{}
	}
}

func (c *Config) validate() error {
	if c.Interval < time.Minute {
		return fmt.Errorf("interval %s is below the 1m minimum", c.Interval)
	}
	return nil
}

// Enabled reports whether the named collector is switched on.
func (c *Config) Enabled(collectorID string) bool {
	cc, ok := c.Collectors[collectorID]
	return ok && cc.Enabled
}
