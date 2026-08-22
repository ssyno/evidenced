package operator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/ssyno/evidenced/api/v1alpha1"
	"github.com/ssyno/evidenced/internal/core"
	"github.com/ssyno/evidenced/evidence"
	"github.com/ssyno/evidenced/internal/shells/wiring"
)

type fakeCollector struct{ id string }

func (f *fakeCollector) ID() string                             { return f.id }
func (f *fakeCollector) Version() string                        { return "0.0.1" }
func (f *fakeCollector) Description() string                    { return "fake" }
func (f *fakeCollector) RequiredAccess() []core.AccessRequirement { return nil }
func (f *fakeCollector) Collect(context.Context) ([]evidence.Record, error) {
	return []evidence.Record{{
		CollectorID:      f.id,
		CollectorVersion: "0.0.1",
		Target:           evidence.Target{Type: "tls/endpoint", Name: "fake:443"},
		Outcome:          evidence.OutcomeObserved,
	}}, nil
}

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func policyFixture(dir string) *v1alpha1.EvidencePolicy {
	interval := metav1.Duration{Duration: 30 * time.Minute}
	return &v1alpha1.EvidencePolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Generation: 1},
		Spec: v1alpha1.EvidencePolicySpec{
			Interval:   &interval,
			StorePath:  filepath.Join(dir, "evidence.jsonl"),
			ExportDir:  filepath.Join(dir, "reports"),
			Collectors: []v1alpha1.CollectorSpec{{Name: "tlsscan"}},
		},
	}
}

func TestReconcileRunsCycleAndReports(t *testing.T) {
	dir := t.TempDir()
	policy := policyFixture(dir)
	scheme := newScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy).
		WithStatusSubresource(&v1alpha1.EvidencePolicy{}).
		Build()

	r := &EvidencePolicyReconciler{
		Client: cl,
		Factories: map[string]wiring.Factory{
			"tlsscan": func(core.CollectorConfig) (core.Collector, error) {
				return &fakeCollector{id: "tlsscan"}, nil
			},
		},
		Clock: func() time.Time { return time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC) },
	}

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "default"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.RequeueAfter != 30*time.Minute {
		t.Errorf("RequeueAfter = %s, want 30m", res.RequeueAfter)
	}

	var updated v1alpha1.EvidencePolicy
	if err := cl.Get(context.Background(), types.NamespacedName{Name: "default"}, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.Records != 1 || updated.Status.LastError != "" || updated.Status.LastRunTime == nil {
		t.Errorf("status = %+v", updated.Status)
	}
	if updated.Status.LastBundle == "" {
		t.Error("status.LastBundle is empty")
	}
	if _, err := os.Stat(filepath.Join(updated.Status.LastBundle, "manifest.json")); err != nil {
		t.Errorf("bundle not on disk: %v", err)
	}

	var reports v1alpha1.EvidenceReportList
	if err := cl.List(context.Background(), &reports); err != nil {
		t.Fatal(err)
	}
	if len(reports.Items) != 1 {
		t.Fatalf("got %d EvidenceReports, want 1", len(reports.Items))
	}
	rep := reports.Items[0]
	if rep.Spec.PolicyName != "default" || rep.Spec.RecordCount != 1 || rep.Spec.Framework != "DORA" {
		t.Errorf("report spec = %+v", rep.Spec)
	}
	if len(rep.OwnerReferences) != 1 || rep.OwnerReferences[0].Kind != "EvidencePolicy" {
		t.Errorf("report owner refs = %+v", rep.OwnerReferences)
	}

	// Evidence in the store must be mapped to DORA controls.
	records, err := core.ReadStoreRecords(policy.Spec.StorePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || len(records[0].ControlIDs) == 0 {
		t.Errorf("stored records = %+v", records)
	}

	// A second reconcile reuses the cached engine and extends the chain.
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "default"},
	}); err != nil {
		t.Fatal(err)
	}
	records, err = core.ReadStoreRecords(policy.Spec.StorePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records after second cycle, want 2", len(records))
	}
	if err := evidence.Verify(records); err != nil {
		t.Errorf("chain broken across reconciles: %v", err)
	}
}

func TestReconcileSurfacesBuildErrors(t *testing.T) {
	dir := t.TempDir()
	policy := policyFixture(dir)
	policy.Spec.Collectors = []v1alpha1.CollectorSpec{{Name: "unknown"}}
	scheme := newScheme(t)
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy).
		WithStatusSubresource(&v1alpha1.EvidencePolicy{}).
		Build()

	r := &EvidencePolicyReconciler{Client: cl}
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "default"},
	})
	if err != nil {
		t.Fatalf("build errors must not fail reconcile: %v", err)
	}
	if res.RequeueAfter != time.Minute {
		t.Errorf("RequeueAfter = %s, want 1m retry", res.RequeueAfter)
	}
	var updated v1alpha1.EvidencePolicy
	if err := cl.Get(context.Background(), types.NamespacedName{Name: "default"}, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Status.LastError == "" {
		t.Error("status.LastError is empty after build failure")
	}
}

func TestReconcileDeletedPolicyDropsEngine(t *testing.T) {
	scheme := newScheme(t)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &EvidencePolicyReconciler{Client: cl}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "gone"},
	}); err != nil {
		t.Fatalf("Reconcile(missing policy) = %v, want nil", err)
	}
}

func TestTranslate(t *testing.T) {
	settings, err := json.Marshal(map[string]any{"endpoints": []string{"a.example.com:443"}})
	if err != nil {
		t.Fatal(err)
	}
	interval := metav1.Duration{Duration: 2 * time.Hour}
	spec := &v1alpha1.EvidencePolicySpec{
		Interval: &interval,
		Collectors: []v1alpha1.CollectorSpec{
			{Name: "tlsscan", Settings: &runtime.RawExtension{Raw: settings}},
			{Name: "rbacposture"},
		},
	}
	cfg, err := Translate(spec)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Interval != 2*time.Hour {
		t.Errorf("Interval = %s", cfg.Interval)
	}
	if cfg.StorePath != "/var/lib/evidenced/evidence.jsonl" {
		t.Errorf("StorePath default = %q", cfg.StorePath)
	}
	if !cfg.Enabled("tlsscan") || !cfg.Enabled("rbacposture") {
		t.Error("collectors not enabled after translation")
	}
	var s struct {
		Endpoints []string `yaml:"endpoints"`
	}
	if err := cfg.Collectors["tlsscan"].DecodeSettings(&s); err != nil {
		t.Fatal(err)
	}
	if len(s.Endpoints) != 1 || s.Endpoints[0] != "a.example.com:443" {
		t.Errorf("settings round-trip = %+v", s)
	}

	if _, err := Translate(&v1alpha1.EvidencePolicySpec{
		Collectors: []v1alpha1.CollectorSpec{{Name: ""}},
	}); err == nil {
		t.Error("Translate with empty collector name = nil error, want failure")
	}

	tooFast := metav1.Duration{Duration: time.Second}
	if _, err := Translate(&v1alpha1.EvidencePolicySpec{
		Interval:   &tooFast,
		Collectors: []v1alpha1.CollectorSpec{{Name: "tlsscan"}},
	}); err == nil {
		t.Error("Translate with sub-minute interval = nil error, want failure")
	}
}
