package tlsscan

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ssyno/evidenced/internal/evidence"
)

func testServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	return srv, srv.Listener.Addr().String()
}

func TestScanObservesEndpoint(t *testing.T) {
	srv, endpoint := testServer(t)

	c, err := New(Config{Endpoints: []string{endpoint}, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	// Trust the test server's self-signed certificate so chain trust is
	// exercised both ways (see TestScanUntrustedChain).
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	c.roots = pool

	records, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	r := records[0]
	if r.Outcome != evidence.OutcomeObserved {
		t.Fatalf("outcome = %q, error = %q", r.Outcome, r.Error)
	}
	if r.Target.Type != TargetType || r.Target.Name != endpoint {
		t.Errorf("target = %+v", r.Target)
	}

	var obs observation
	if err := json.Unmarshal(r.Observation, &obs); err != nil {
		t.Fatal(err)
	}
	if !obs.MinTLS12Enforced {
		t.Errorf("MinTLS12Enforced = false, version = %s", obs.TLSVersion)
	}
	if !obs.ChainTrusted {
		t.Errorf("ChainTrusted = false with trusted root: %s", obs.ChainTrustError)
	}
	if !obs.HostnameMatches {
		t.Error("HostnameMatches = false for matching IP SAN")
	}
	if obs.KeyAlgorithm == "" || obs.NotAfter.IsZero() {
		t.Errorf("incomplete observation: %+v", obs)
	}
}

func TestScanUntrustedChain(t *testing.T) {
	_, endpoint := testServer(t)
	c, err := New(Config{Endpoints: []string{endpoint}})
	if err != nil {
		t.Fatal(err)
	}
	// Empty (non-nil) root pool: nothing is trusted.
	c.roots = x509.NewCertPool()

	records, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var obs observation
	if err := json.Unmarshal(records[0].Observation, &obs); err != nil {
		t.Fatal(err)
	}
	if obs.ChainTrusted {
		t.Error("ChainTrusted = true for self-signed cert with empty roots")
	}
	if obs.ChainTrustError == "" {
		t.Error("ChainTrustError is empty for untrusted chain")
	}
	if records[0].Outcome != evidence.OutcomeObserved {
		t.Error("untrusted chain must still be an observation, not a failure")
	}
}

func TestScanUnreachableEndpointIsFailureEvidence(t *testing.T) {
	c, err := New(Config{Endpoints: []string{"127.0.0.1:1"}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	records, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect must not error on unreachable endpoint: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	r := records[0]
	if r.Outcome != evidence.OutcomeFailed {
		t.Errorf("outcome = %q, want failed", r.Outcome)
	}
	if r.Error == "" || r.Target.Name != "127.0.0.1:1" {
		t.Errorf("failure record incomplete: %+v", r)
	}
}

func TestNewValidatesConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"no endpoints", Config{}},
		{"missing port", Config{Endpoints: []string{"example.com"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.cfg); err == nil {
				t.Error("New = nil error, want failure")
			}
		})
	}
}

// The observation must only ever contain public certificate metadata.
// This guards against future fields accidentally leaking key material.
func TestObservationContainsOnlyPublicMetadata(t *testing.T) {
	srv, endpoint := testServer(t)
	c, err := New(Config{Endpoints: []string{endpoint}})
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	c.roots = pool

	records, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(records[0].Observation, &fields); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{
		"endpoint": true, "tlsVersion": true, "cipherSuite": true,
		"subject": true, "issuer": true, "serialNumber": true,
		"notBefore": true, "notAfter": true, "daysUntilExpiry": true,
		"keyAlgorithm": true, "keyStrengthBits": true, "dnsNames": true,
		"chainTrusted": true, "chainTrustError": true,
		"hostnameMatches": true, "minTls12Enforced": true,
	}
	for k := range fields {
		if !allowed[k] {
			t.Errorf("unexpected observation field %q — review for secret leakage", k)
		}
	}
}
