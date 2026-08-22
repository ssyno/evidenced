// Package push uploads exported bundles to an evidenced portal. It is
// strictly opt-in: without a push block in the config the agent makes
// no outbound connection of any kind, and even with one the only
// destination is the customer-configured URL.
package push

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ssyno/evidenced/internal/core"
)

// bundleFiles are the exact files uploaded from a bundle directory.
var bundleFiles = []string{"evidence.json", "report.md", "manifest.json"}

// Pusher uploads bundle directories to the configured portal.
type Pusher struct {
	cfg    core.PushConfig
	client *http.Client
	agent  string
}

// New validates the push configuration. The token source is checked at
// push time, not here, so a daemon can start before its secret mount.
func New(cfg core.PushConfig) (*Pusher, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("push: invalid url %q", cfg.URL)
	}
	if u.Scheme != "https" && !isLoopback(u.Hostname()) {
		return nil, fmt.Errorf("push: url must be https (plain http is allowed only for loopback)")
	}
	if (cfg.TokenEnv == "") == (cfg.TokenFile == "") {
		return nil, fmt.Errorf("push: exactly one of tokenEnv or tokenFile must be set")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile) // #nosec G304 -- operator-supplied config
		if err != nil {
			return nil, fmt.Errorf("push: read caFile: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("push: caFile %s contains no certificates", cfg.CAFile)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}

	agent := cfg.Agent
	if agent == "" {
		if host, err := os.Hostname(); err == nil {
			agent = host
		}
	}
	return &Pusher{
		cfg:    cfg,
		client: &http.Client{Transport: transport, Timeout: 2 * time.Minute},
		agent:  agent,
	}, nil
}

// Agent returns the agent name uploads are attributed to.
func (p *Pusher) Agent() string { return p.agent }

// Push uploads one bundle directory. Failures are returned for the
// caller to log; they must never stop collection.
func (p *Pusher) Push(ctx context.Context, bundleDir string) error {
	token, err := p.token()
	if err != nil {
		return err
	}
	archive, err := tarGzBundle(bundleDir)
	if err != nil {
		return err
	}
	endpoint := strings.TrimSuffix(p.cfg.URL, "/") + "/api/v1/bundles"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(archive))
	if err != nil {
		return fmt.Errorf("push: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/gzip")
	if p.agent != "" {
		req.Header.Set("X-Evidenced-Agent", p.agent)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("push %s: %w", endpoint, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("push %s: portal responded %d: %s", endpoint, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (p *Pusher) token() (string, error) {
	if p.cfg.TokenEnv != "" {
		token := strings.TrimSpace(os.Getenv(p.cfg.TokenEnv))
		if token == "" {
			return "", fmt.Errorf("push: environment variable %s is empty", p.cfg.TokenEnv)
		}
		return token, nil
	}
	b, err := os.ReadFile(p.cfg.TokenFile) // #nosec G304 -- operator-supplied config
	if err != nil {
		return "", fmt.Errorf("push: read token file: %w", err)
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", fmt.Errorf("push: token file %s is empty", p.cfg.TokenFile)
	}
	return token, nil
}

// tarGzBundle archives exactly the three bundle files.
func tarGzBundle(dir string) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, name := range bundleFiles {
		content, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- exporter-produced dir
		if err != nil {
			return nil, fmt.Errorf("push: read %s: %w", name, err)
		}
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o600, Size: int64(len(content)), Typeflag: tar.TypeReg,
			ModTime: time.Now().UTC(),
		}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(content); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
