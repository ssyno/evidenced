package certlifecycle

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/ssyno/evidenced/internal/evidence"
)

type schemaGVR = schema.GroupVersionResource

func fakeClient(objects ...runtime.Object) *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schemaGVR]string{
		certGVR:          "CertificateList",
		issuerGVR:        "IssuerList",
		clusterIssuerGVR: "ClusterIssuerList",
	}, objects...)
}

func certificate(ns, name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cert-manager.io/v1",
		"kind":       "Certificate",
		"metadata":   map[string]any{"namespace": ns, "name": name},
		"spec": map[string]any{
			"secretName": name + "-tls",
			"dnsNames":   []any{name + ".example.com"},
			"issuerRef":  map[string]any{"kind": "ClusterIssuer", "name": "letsencrypt"},
			"privateKey": map[string]any{"algorithm": "RSA", "size": int64(4096), "rotationPolicy": "Always"},
		},
		"status": map[string]any{
			"notBefore":   "2026-08-01T00:00:00Z",
			"notAfter":    "2026-10-30T00:00:00Z",
			"renewalTime": "2026-10-01T00:00:00Z",
			"revision":    int64(3),
			"conditions": []any{
				map[string]any{"type": "Ready", "status": "True", "reason": "Ready"},
			},
		},
	}}
}

func issuer(ns, name, issuerType string) *unstructured.Unstructured {
	kind, meta := "Issuer", map[string]any{"namespace": ns, "name": name}
	if ns == "" {
		kind, meta = "ClusterIssuer", map[string]any{"name": name}
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cert-manager.io/v1",
		"kind":       kind,
		"metadata":   meta,
		"spec":       map[string]any{issuerType: map[string]any{}},
		"status": map[string]any{"conditions": []any{
			map[string]any{"type": "Ready", "status": "True", "reason": "IsReady"},
		}},
	}}
}

func TestCollectCertificatesAndIssuers(t *testing.T) {
	client := fakeClient(
		certificate("prod", "web"),
		issuer("prod", "internal-ca", "ca"),
		issuer("", "letsencrypt", "acme"),
	)
	c := New(Config{}, client)
	c.clock = func() time.Time { return time.Date(2026, 8, 22, 0, 0, 0, 0, time.UTC) }

	records, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("got %d records, want 3", len(records))
	}

	byTarget := map[string]evidence.Record{}
	for _, r := range records {
		if r.Outcome != evidence.OutcomeObserved {
			t.Errorf("record %s/%s failed: %s", r.Target.Type, r.Target.Name, r.Error)
		}
		byTarget[r.Target.Type+":"+r.Target.Name] = r
	}

	cert, ok := byTarget[TargetTypeCertificate+":prod/web"]
	if !ok {
		t.Fatalf("certificate record missing, got %v", byTarget)
	}
	var obs certObservation
	if err := json.Unmarshal(cert.Observation, &obs); err != nil {
		t.Fatal(err)
	}
	if obs.SecretName != "web-tls" || obs.IssuerName != "letsencrypt" || obs.IssuerKind != "ClusterIssuer" {
		t.Errorf("observation = %+v", obs)
	}
	if obs.DaysUntilExpiry == nil || *obs.DaysUntilExpiry != 69 {
		t.Errorf("DaysUntilExpiry = %v, want 69", obs.DaysUntilExpiry)
	}
	if obs.Ready != "True" || obs.Revision != 3 || obs.KeySize != 4096 || obs.KeyRotationPolicy != "Always" {
		t.Errorf("observation = %+v", obs)
	}

	var iobs issuerObservation
	ci, ok := byTarget[TargetTypeIssuer+":letsencrypt"]
	if !ok {
		t.Fatal("clusterissuer record missing")
	}
	if err := json.Unmarshal(ci.Observation, &iobs); err != nil {
		t.Fatal(err)
	}
	if iobs.Scope != "ClusterIssuer" || iobs.IssuerType != "acme" || iobs.Ready != "True" {
		t.Errorf("clusterissuer observation = %+v", iobs)
	}

	nsIssuer, ok := byTarget[TargetTypeIssuer+":prod/internal-ca"]
	if !ok {
		t.Fatal("namespaced issuer record missing")
	}
	if err := json.Unmarshal(nsIssuer.Observation, &iobs); err != nil {
		t.Fatal(err)
	}
	if iobs.Scope != "Issuer" || iobs.IssuerType != "ca" {
		t.Errorf("issuer observation = %+v", iobs)
	}
}

func TestCollectNamespaceScoped(t *testing.T) {
	client := fakeClient(certificate("prod", "web"), certificate("dev", "test"))
	c := New(Config{Namespaces: []string{"prod"}}, client)

	records, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var certRecords []evidence.Record
	for _, r := range records {
		if r.Target.Type == TargetTypeCertificate {
			certRecords = append(certRecords, r)
		}
	}
	if len(certRecords) != 1 || certRecords[0].Target.Name != "prod/web" {
		t.Errorf("records = %+v", certRecords)
	}
}

// The certificate observation must reference key material (secret name,
// key parameters) without ever containing it.
func TestObservationContainsOnlyPublicMetadata(t *testing.T) {
	client := fakeClient(certificate("prod", "web"))
	c := New(Config{}, client)
	records, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(records[0].Observation, &fields); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{
		"namespace": true, "name": true, "secretName": true,
		"issuerKind": true, "issuerName": true, "dnsNames": true,
		"notBefore": true, "notAfter": true, "renewalTime": true,
		"daysUntilExpiry": true, "revision": true, "ready": true,
		"readyReason": true, "keyAlgorithm": true, "keySize": true,
		"keyRotationPolicy": true,
	}
	for k := range fields {
		if !allowed[k] {
			t.Errorf("unexpected observation field %q — review for secret leakage", k)
		}
	}
}

func TestCollectFailsWithoutCertManager(t *testing.T) {
	client := fakeClient()
	client.PrependReactor("list", "certificates", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewNotFound(certGVR.GroupResource(), "")
	})
	c := New(Config{}, client)
	if _, err := c.Collect(context.Background()); err == nil {
		t.Error("Collect without certificates CRD = nil error, want failure (recorded as evidence by the scheduler)")
	}
}
