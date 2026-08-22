package provenance

import (
	"context"
	"encoding/json"
	"testing"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ssyno/evidenced/internal/evidence"
)

func podSpec(images ...string) corev1.PodSpec {
	spec := corev1.PodSpec{}
	for i, img := range images {
		spec.Containers = append(spec.Containers, corev1.Container{
			Name: "c" + string(rune('0'+i)), Image: img, ImagePullPolicy: corev1.PullIfNotPresent,
		})
	}
	return spec
}

func TestCollectWorkloadsAndAdmission(t *testing.T) {
	client := fake.NewClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "prod"},
			Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{
				Spec: podSpec(
					"ghcr.io/acme/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					"redis:7.2",
				),
			}},
		},
		&appsv1.StatefulSet{
			ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "prod"},
			Spec: appsv1.StatefulSetSpec{Template: corev1.PodTemplateSpec{
				Spec: podSpec("registry.example.com:5000/db@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
			}},
		},
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{Name: "agent", Namespace: "kube-system"},
			Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{
				Spec: podSpec("quay.io/agent:v1"),
			}},
		},
		&admissionv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "kyverno-resource-validating-webhook-cfg"},
		},
		&admissionv1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{Name: "cert-manager-webhook"},
		},
	)
	c := New(Config{}, client)
	records, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	byTarget := map[string]evidence.Record{}
	for _, r := range records {
		if r.Outcome != evidence.OutcomeObserved {
			t.Errorf("record %s failed: %s", r.Target.Name, r.Error)
		}
		byTarget[r.Target.Type+":"+r.Target.Name] = r
	}
	if len(records) != 4 {
		t.Fatalf("got %d records, want 4 (3 workloads + admission)", len(records))
	}

	var web workloadObservation
	if err := json.Unmarshal(byTarget[TargetTypeWorkloadImage+":prod/web"].Observation, &web); err != nil {
		t.Fatal(err)
	}
	if web.AllDigestPinned {
		t.Error("web has an unpinned image; AllDigestPinned must be false")
	}
	if len(web.Images) != 2 || !web.Images[0].DigestPinned || web.Images[0].Registry != "ghcr.io" {
		t.Errorf("web images = %+v", web.Images)
	}
	if web.Images[1].Registry != "docker.io" || web.Images[1].DigestPinned {
		t.Errorf("bare image parsed wrong: %+v", web.Images[1])
	}

	var db workloadObservation
	if err := json.Unmarshal(byTarget[TargetTypeWorkloadImage+":prod/db"].Observation, &db); err != nil {
		t.Fatal(err)
	}
	if !db.AllDigestPinned || db.Images[0].Registry != "registry.example.com:5000" {
		t.Errorf("db observation = %+v", db)
	}

	var adm admissionObservation
	if err := json.Unmarshal(byTarget[TargetTypeAdmissionPolicy+":cluster-wide"].Observation, &adm); err != nil {
		t.Fatal(err)
	}
	if !adm.SignatureVerificationDetected || len(adm.DetectedEngines) != 1 || adm.DetectedEngines[0] != "kyverno" {
		t.Errorf("admission observation = %+v", adm)
	}
	if len(adm.ValidatingWebhookConfigurations) != 2 {
		t.Errorf("webhook list = %v", adm.ValidatingWebhookConfigurations)
	}
}

func TestRegistryOf(t *testing.T) {
	tests := []struct {
		image string
		want  string
	}{
		{"nginx", "docker.io"},
		{"nginx:1.25", "docker.io"},
		{"library/nginx", "docker.io"},
		{"ghcr.io/org/app:v1", "ghcr.io"},
		{"localhost/app", "localhost"},
		{"registry.example.com:5000/app@sha256:abc", "registry.example.com:5000"},
	}
	for _, tt := range tests {
		if got := registryOf(tt.image); got != tt.want {
			t.Errorf("registryOf(%q) = %q, want %q", tt.image, got, tt.want)
		}
	}
}

func TestNamespaceScoping(t *testing.T) {
	client := fake.NewClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "prod"},
			Spec:       appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: podSpec("a:1")}},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "dev"},
			Spec:       appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: podSpec("b:1")}},
		},
	)
	c := New(Config{Namespaces: []string{"prod"}}, client)
	records, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	workloads := 0
	for _, r := range records {
		if r.Target.Type == TargetTypeWorkloadImage {
			workloads++
			if r.Target.Name != "prod/web" {
				t.Errorf("unexpected workload %s", r.Target.Name)
			}
		}
	}
	if workloads != 1 {
		t.Errorf("got %d workload records, want 1", workloads)
	}
}
