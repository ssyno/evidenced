// Package certlifecycle observes cert-manager Certificates and Issuers:
// validity windows, renewal state, issuer configuration and key
// parameters. It reads only cert-manager custom resources — never the
// Secrets holding key material.
package certlifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/ssyno/evidenced/internal/core"
	"github.com/ssyno/evidenced/internal/evidence"
)

const (
	collectorID      = "certlifecycle"
	collectorVersion = "0.1.0"

	TargetTypeCertificate = "cert-manager/certificate"
	TargetTypeIssuer      = "cert-manager/issuer"
)

var (
	certGVR          = schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}
	issuerGVR        = schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "issuers"}
	clusterIssuerGVR = schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "clusterissuers"}
)

type Config struct {
	// Namespaces limits collection; empty means all namespaces.
	Namespaces []string `yaml:"namespaces"`
}

type Collector struct {
	cfg    Config
	client dynamic.Interface
	clock  func() time.Time
}

func New(cfg Config, client dynamic.Interface) *Collector {
	return &Collector{cfg: cfg, client: client, clock: func() time.Time { return time.Now().UTC() }}
}

func (c *Collector) ID() string      { return collectorID }
func (c *Collector) Version() string { return collectorVersion }
func (c *Collector) Description() string {
	return "cert-manager certificate and issuer lifecycle posture"
}

func (c *Collector) RequiredAccess() []core.AccessRequirement {
	return []core.AccessRequirement{
		{
			System: "kubernetes", Resource: "cert-manager.io/certificates", Access: "get,list,watch",
			Description: "observes certificate validity, renewal and key parameters",
		},
		{
			System: "kubernetes", Resource: "cert-manager.io/issuers,clusterissuers", Access: "get,list,watch",
			Description: "observes issuer configuration and readiness",
		},
	}
}

type certObservation struct {
	Namespace         string     `json:"namespace"`
	Name              string     `json:"name"`
	SecretName        string     `json:"secretName"`
	IssuerKind        string     `json:"issuerKind"`
	IssuerName        string     `json:"issuerName"`
	DNSNames          []string   `json:"dnsNames,omitempty"`
	NotBefore         *time.Time `json:"notBefore,omitempty"`
	NotAfter          *time.Time `json:"notAfter,omitempty"`
	RenewalTime       *time.Time `json:"renewalTime,omitempty"`
	DaysUntilExpiry   *int       `json:"daysUntilExpiry,omitempty"`
	Revision          int64      `json:"revision"`
	Ready             string     `json:"ready"` // True/False/Unknown
	ReadyReason       string     `json:"readyReason,omitempty"`
	KeyAlgorithm      string     `json:"keyAlgorithm,omitempty"`
	KeySize           int64      `json:"keySize,omitempty"`
	KeyRotationPolicy string     `json:"keyRotationPolicy,omitempty"`
}

type issuerObservation struct {
	Namespace   string `json:"namespace,omitempty"`
	Name        string `json:"name"`
	Scope       string `json:"scope"` // Issuer or ClusterIssuer
	IssuerType  string `json:"issuerType"`
	Ready       string `json:"ready"`
	ReadyReason string `json:"readyReason,omitempty"`
}

// Collect lists certificates and issuers. A missing cert-manager
// installation surfaces as a collector failure, which the scheduler
// records as evidence.
func (c *Collector) Collect(ctx context.Context) ([]evidence.Record, error) {
	var records []evidence.Record

	certs, err := c.list(ctx, certGVR)
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	for _, item := range certs {
		records = append(records, c.certRecord(item))
	}

	issuers, err := c.list(ctx, issuerGVR)
	if err != nil {
		return nil, fmt.Errorf("list issuers: %w", err)
	}
	for _, item := range issuers {
		records = append(records, c.issuerRecord(item, "Issuer"))
	}

	clusterIssuers, err := c.client.Resource(clusterIssuerGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list clusterissuers: %w", err)
	}
	for _, item := range clusterIssuers.Items {
		records = append(records, c.issuerRecord(item, "ClusterIssuer"))
	}
	return records, nil
}

func (c *Collector) list(ctx context.Context, gvr schema.GroupVersionResource) ([]unstructured.Unstructured, error) {
	if len(c.cfg.Namespaces) == 0 {
		l, err := c.client.Resource(gvr).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return l.Items, nil
	}
	var items []unstructured.Unstructured
	for _, ns := range c.cfg.Namespaces {
		l, err := c.client.Resource(gvr).Namespace(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		items = append(items, l.Items...)
	}
	return items, nil
}

func (c *Collector) certRecord(u unstructured.Unstructured) evidence.Record {
	obs := certObservation{
		Namespace: u.GetNamespace(),
		Name:      u.GetName(),
	}
	obs.SecretName, _, _ = unstructured.NestedString(u.Object, "spec", "secretName")
	obs.IssuerKind, _, _ = unstructured.NestedString(u.Object, "spec", "issuerRef", "kind")
	obs.IssuerName, _, _ = unstructured.NestedString(u.Object, "spec", "issuerRef", "name")
	obs.DNSNames, _, _ = unstructured.NestedStringSlice(u.Object, "spec", "dnsNames")
	obs.KeyAlgorithm, _, _ = unstructured.NestedString(u.Object, "spec", "privateKey", "algorithm")
	obs.KeySize, _, _ = unstructured.NestedInt64(u.Object, "spec", "privateKey", "size")
	obs.KeyRotationPolicy, _, _ = unstructured.NestedString(u.Object, "spec", "privateKey", "rotationPolicy")
	obs.Revision, _, _ = unstructured.NestedInt64(u.Object, "status", "revision")
	obs.NotBefore = nestedTime(u.Object, "status", "notBefore")
	obs.NotAfter = nestedTime(u.Object, "status", "notAfter")
	obs.RenewalTime = nestedTime(u.Object, "status", "renewalTime")
	if obs.NotAfter != nil {
		days := int(obs.NotAfter.Sub(c.clock()).Hours() / 24)
		obs.DaysUntilExpiry = &days
	}
	obs.Ready, obs.ReadyReason = readyCondition(u.Object)

	return c.record(TargetTypeCertificate, u.GetNamespace()+"/"+u.GetName(), map[string]string{
		"namespace": u.GetNamespace(),
	}, obs)
}

func (c *Collector) issuerRecord(u unstructured.Unstructured, scope string) evidence.Record {
	obs := issuerObservation{
		Namespace:  u.GetNamespace(),
		Name:       u.GetName(),
		Scope:      scope,
		IssuerType: issuerType(u.Object),
	}
	obs.Ready, obs.ReadyReason = readyCondition(u.Object)

	name := u.GetName()
	if scope == "Issuer" {
		name = u.GetNamespace() + "/" + u.GetName()
	}
	return c.record(TargetTypeIssuer, name, map[string]string{"scope": scope}, obs)
}

func (c *Collector) record(targetType, name string, attrs map[string]string, obs any) evidence.Record {
	rec := evidence.Record{
		CollectorID:      collectorID,
		CollectorVersion: collectorVersion,
		Target:           evidence.Target{Type: targetType, Name: name, Attributes: attrs},
		CollectedAt:      c.clock(),
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

// issuerType reports which issuer backend is configured (acme, ca,
// vault, selfSigned, venafi) by inspecting which spec key is present.
func issuerType(obj map[string]any) string {
	spec, ok, _ := unstructured.NestedMap(obj, "spec")
	if !ok {
		return "unknown"
	}
	for _, t := range []string{"acme", "ca", "vault", "selfSigned", "venafi"} {
		if _, present := spec[t]; present {
			return t
		}
	}
	return "unknown"
}

func readyCondition(obj map[string]any) (status, reason string) {
	conditions, ok, _ := unstructured.NestedSlice(obj, "status", "conditions")
	if !ok {
		return "Unknown", ""
	}
	for _, c := range conditions {
		cond, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if t, _ := cond["type"].(string); t == "Ready" {
			s, _ := cond["status"].(string)
			r, _ := cond["reason"].(string)
			return s, r
		}
	}
	return "Unknown", ""
}

func nestedTime(obj map[string]any, fields ...string) *time.Time {
	s, ok, _ := unstructured.NestedString(obj, fields...)
	if !ok || s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	t = t.UTC()
	return &t
}
