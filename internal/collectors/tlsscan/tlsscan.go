// Package tlsscan observes the TLS posture of network endpoints from the
// outside: protocol version, certificate validity and chain trust. It
// needs no credentials and no platform access, only outbound TCP.
package tlsscan

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/ssyno/evidenced/internal/core"
	"github.com/ssyno/evidenced/evidence"
)

const (
	collectorID      = "tlsscan"
	collectorVersion = "0.1.0"
	// TargetType is the target type of every record this collector emits.
	TargetType = "tls/endpoint"
)

type Config struct {
	Endpoints []string      `yaml:"endpoints"`
	Timeout   time.Duration `yaml:"timeout"`
}

type Collector struct {
	cfg   Config
	roots *x509.CertPool
	clock func() time.Time
}

func New(cfg Config) (*Collector, error) {
	if len(cfg.Endpoints) == 0 {
		return nil, fmt.Errorf("tlsscan: no endpoints configured")
	}
	for _, e := range cfg.Endpoints {
		if _, _, err := net.SplitHostPort(e); err != nil {
			return nil, fmt.Errorf("tlsscan: endpoint %q is not host:port: %w", e, err)
		}
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &Collector{cfg: cfg, clock: func() time.Time { return time.Now().UTC() }}, nil
}

func (c *Collector) ID() string          { return collectorID }
func (c *Collector) Version() string     { return collectorVersion }
func (c *Collector) Description() string { return "external TLS endpoint posture scanner" }

func (c *Collector) RequiredAccess() []core.AccessRequirement {
	return []core.AccessRequirement{{
		System:      "network",
		Resource:    "configured TLS endpoints",
		Access:      "outbound TCP connect",
		Description: "performs a TLS handshake to observe protocol and certificate posture",
	}}
}

// observation is the structured evidence per endpoint. Only public
// certificate metadata is recorded — never key material.
type observation struct {
	Endpoint         string    `json:"endpoint"`
	TLSVersion       string    `json:"tlsVersion"`
	CipherSuite      string    `json:"cipherSuite"`
	Subject          string    `json:"subject"`
	Issuer           string    `json:"issuer"`
	SerialNumber     string    `json:"serialNumber"`
	NotBefore        time.Time `json:"notBefore"`
	NotAfter         time.Time `json:"notAfter"`
	DaysUntilExpiry  int       `json:"daysUntilExpiry"`
	KeyAlgorithm     string    `json:"keyAlgorithm"`
	KeyStrengthBits  int       `json:"keyStrengthBits"`
	DNSNames         []string  `json:"dnsNames,omitempty"`
	ChainTrusted     bool      `json:"chainTrusted"`
	ChainTrustError  string    `json:"chainTrustError,omitempty"`
	HostnameMatches  bool      `json:"hostnameMatches"`
	MinTLS12Enforced bool      `json:"minTls12Enforced"`
}

// Collect scans every configured endpoint. An unreachable endpoint
// produces a failure record for that endpoint; it never aborts the scan.
func (c *Collector) Collect(ctx context.Context) ([]evidence.Record, error) {
	records := make([]evidence.Record, 0, len(c.cfg.Endpoints))
	for _, endpoint := range c.cfg.Endpoints {
		records = append(records, c.scan(ctx, endpoint))
	}
	return records, nil
}

func (c *Collector) scan(ctx context.Context, endpoint string) evidence.Record {
	rec := evidence.Record{
		CollectorID:      collectorID,
		CollectorVersion: collectorVersion,
		Target:           evidence.Target{Type: TargetType, Name: endpoint},
		CollectedAt:      c.clock(),
	}
	obs, err := c.handshake(ctx, endpoint)
	if err != nil {
		rec.Outcome = evidence.OutcomeFailed
		rec.Error = err.Error()
		return rec
	}
	raw, err := json.Marshal(obs)
	if err != nil {
		rec.Outcome = evidence.OutcomeFailed
		rec.Error = fmt.Sprintf("encode observation: %v", err)
		return rec
	}
	rec.Outcome = evidence.OutcomeObserved
	rec.Observation = raw
	return rec
}

func (c *Collector) handshake(ctx context.Context, endpoint string) (*observation, error) {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint %q: %w", endpoint, err)
	}
	dialCtx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	dialer := &tls.Dialer{Config: &tls.Config{
		ServerName: host,
		// The scanner must observe expired or untrusted certificates too;
		// trust is evaluated manually below and recorded as evidence.
		InsecureSkipVerify: true, // #nosec G402
		MinVersion:         tls.VersionTLS10,
	}}
	conn, err := dialer.DialContext(dialCtx, "tcp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("handshake with %s: %w", endpoint, err)
	}
	defer conn.Close() //nolint:errcheck // read-only observation connection

	state := conn.(*tls.Conn).ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("handshake with %s: no peer certificates", endpoint)
	}
	leaf := state.PeerCertificates[0]

	obs := &observation{
		Endpoint:         endpoint,
		TLSVersion:       tls.VersionName(state.Version),
		CipherSuite:      tls.CipherSuiteName(state.CipherSuite),
		Subject:          leaf.Subject.String(),
		Issuer:           leaf.Issuer.String(),
		SerialNumber:     leaf.SerialNumber.String(),
		NotBefore:        leaf.NotBefore.UTC(),
		NotAfter:         leaf.NotAfter.UTC(),
		DaysUntilExpiry:  int(time.Until(leaf.NotAfter).Hours() / 24),
		DNSNames:         leaf.DNSNames,
		MinTLS12Enforced: state.Version >= tls.VersionTLS12,
		HostnameMatches:  leaf.VerifyHostname(host) == nil,
	}
	obs.KeyAlgorithm, obs.KeyStrengthBits = keyInfo(leaf)

	opts := x509.VerifyOptions{
		DNSName:       host,
		Roots:         c.roots, // nil means system roots
		Intermediates: x509.NewCertPool(),
	}
	for _, ic := range state.PeerCertificates[1:] {
		opts.Intermediates.AddCert(ic)
	}
	if _, err := leaf.Verify(opts); err != nil {
		obs.ChainTrusted = false
		obs.ChainTrustError = err.Error()
	} else {
		obs.ChainTrusted = true
	}
	return obs, nil
}

func keyInfo(cert *x509.Certificate) (string, int) {
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return cert.PublicKeyAlgorithm.String(), 0
	}
}
