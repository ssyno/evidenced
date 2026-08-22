// Package provenance observes where running software comes from: workload
// image sources, digest pinning, and whether admission policies that
// gate what may run (including signature verification engines) are
// present.
package provenance

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/ssyno/evidenced/internal/core"
	"github.com/ssyno/evidenced/internal/evidence"
)

const (
	collectorID      = "provenance"
	collectorVersion = "0.1.0"

	TargetTypeWorkloadImage   = "workload/image"
	TargetTypeAdmissionPolicy = "admission/policy"
)

type Config struct {
	// Namespaces limits workload collection; empty means all namespaces.
	Namespaces []string `yaml:"namespaces"`
}

type Collector struct {
	cfg    Config
	client kubernetes.Interface
	clock  func() time.Time
}

func New(cfg Config, client kubernetes.Interface) *Collector {
	return &Collector{cfg: cfg, client: client, clock: func() time.Time { return time.Now().UTC() }}
}

func (c *Collector) ID() string          { return collectorID }
func (c *Collector) Version() string     { return collectorVersion }
func (c *Collector) Description() string { return "workload image provenance and admission policy posture" }

func (c *Collector) RequiredAccess() []core.AccessRequirement {
	return []core.AccessRequirement{
		{
			System: "kubernetes", Resource: "apps/deployments,statefulsets,daemonsets", Access: "get,list,watch",
			Description: "observes container image sources and digest pinning",
		},
		{
			System: "kubernetes", Resource: "admissionregistration.k8s.io/validatingwebhookconfigurations", Access: "get,list,watch",
			Description: "observes which admission control policies gate workloads",
		},
	}
}

type containerImage struct {
	Container    string `json:"container"`
	Image        string `json:"image"`
	Registry     string `json:"registry"`
	DigestPinned bool   `json:"digestPinned"`
	PullPolicy   string `json:"pullPolicy,omitempty"`
}

type workloadObservation struct {
	Kind            string           `json:"kind"`
	Namespace       string           `json:"namespace"`
	Name            string           `json:"name"`
	Images          []containerImage `json:"images"`
	AllDigestPinned bool             `json:"allDigestPinned"`
}

type admissionObservation struct {
	ValidatingWebhookConfigurations []string `json:"validatingWebhookConfigurations"`
	SignatureVerificationDetected   bool     `json:"signatureVerificationDetected"`
	DetectedEngines                 []string `json:"detectedEngines,omitempty"`
}

// signatureEngines are name fragments identifying admission controllers
// known to enforce image signature verification.
var signatureEngines = []string{"kyverno", "cosign", "policy-controller", "sigstore", "connaisseur", "notation", "ratify"}

func (c *Collector) Collect(ctx context.Context) ([]evidence.Record, error) {
	var records []evidence.Record

	for _, ns := range c.namespaces() {
		deps, err := c.client.AppsV1().Deployments(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("list deployments: %w", err)
		}
		for _, d := range deps.Items {
			records = append(records, c.workloadRecord("Deployment", d.Namespace, d.Name, d.Spec.Template.Spec))
		}
		stss, err := c.client.AppsV1().StatefulSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("list statefulsets: %w", err)
		}
		for _, s := range stss.Items {
			records = append(records, c.workloadRecord("StatefulSet", s.Namespace, s.Name, s.Spec.Template.Spec))
		}
		dss, err := c.client.AppsV1().DaemonSets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("list daemonsets: %w", err)
		}
		for _, d := range dss.Items {
			records = append(records, c.workloadRecord("DaemonSet", d.Namespace, d.Name, d.Spec.Template.Spec))
		}
	}

	admission, err := c.admissionRecord(ctx)
	if err != nil {
		return nil, err
	}
	records = append(records, admission)
	return records, nil
}

func (c *Collector) namespaces() []string {
	if len(c.cfg.Namespaces) == 0 {
		return []string{metav1.NamespaceAll}
	}
	return c.cfg.Namespaces
}

func (c *Collector) workloadRecord(kind, namespace, name string, spec corev1.PodSpec) evidence.Record {
	obs := workloadObservation{Kind: kind, Namespace: namespace, Name: name, AllDigestPinned: true}
	for _, ct := range spec.Containers {
		img := containerImage{
			Container:    ct.Name,
			Image:        ct.Image,
			Registry:     registryOf(ct.Image),
			DigestPinned: strings.Contains(ct.Image, "@sha256:"),
			PullPolicy:   string(ct.ImagePullPolicy),
		}
		if !img.DigestPinned {
			obs.AllDigestPinned = false
		}
		obs.Images = append(obs.Images, img)
	}
	return c.record(TargetTypeWorkloadImage, namespace+"/"+name, map[string]string{
		"kind": kind, "namespace": namespace,
	}, obs)
}

func (c *Collector) admissionRecord(ctx context.Context) (evidence.Record, error) {
	hooks, err := c.client.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		return evidence.Record{}, fmt.Errorf("list validatingwebhookconfigurations: %w", err)
	}
	obs := admissionObservation{ValidatingWebhookConfigurations: []string{}}
	seen := map[string]bool{}
	for _, h := range hooks.Items {
		obs.ValidatingWebhookConfigurations = append(obs.ValidatingWebhookConfigurations, h.Name)
		lower := strings.ToLower(h.Name)
		for _, engine := range signatureEngines {
			if strings.Contains(lower, engine) && !seen[engine] {
				seen[engine] = true
				obs.DetectedEngines = append(obs.DetectedEngines, engine)
			}
		}
	}
	obs.SignatureVerificationDetected = len(obs.DetectedEngines) > 0
	return c.record(TargetTypeAdmissionPolicy, "cluster-wide", nil, obs), nil
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

// registryOf extracts the registry host from an image reference,
// defaulting to Docker Hub when the first path segment is not a host.
func registryOf(image string) string {
	first, _, found := strings.Cut(image, "/")
	if !found {
		return "docker.io"
	}
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		return first
	}
	return "docker.io"
}
