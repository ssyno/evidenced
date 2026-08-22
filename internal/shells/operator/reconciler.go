// Package operator is the Kubernetes shell: a controller-runtime manager
// whose EvidencePolicy CRD is a frontend to the same core config used by
// the daemon and CLI shells. controller-runtime stays in this package
// (and api/) only.
package operator

import (
	"context"
	"fmt"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"gopkg.in/yaml.v3"

	"github.com/ssyno/evidenced/api/v1alpha1"
	"github.com/ssyno/evidenced/internal/core"
	"github.com/ssyno/evidenced/internal/shells/wiring"
)

// Own CRDs.
// +kubebuilder:rbac:groups=evidenced.io,resources=evidencepolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=evidenced.io,resources=evidencepolicies/status,verbs=get;patch;update
// +kubebuilder:rbac:groups=evidenced.io,resources=evidencereports,verbs=get;list;watch;create
// Read-only access required by collectors (see each collector's RequiredAccess).
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificates;issuers;clusterissuers,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles;clusterrolebindings,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments;statefulsets;daemonsets,verbs=get;list;watch
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations,verbs=get;list;watch

// EvidencePolicyReconciler runs a collection cycle per reconcile and
// requeues itself at the policy's interval — the scheduler loop is the
// reconcile loop in this shell.
type EvidencePolicyReconciler struct {
	client.Client
	// Factories provides collector constructors; injected so tests can
	// substitute fakes.
	Factories map[string]wiring.Factory
	Clock     func() time.Time

	mu      sync.Mutex
	engines map[string]*cachedEngine
}

type cachedEngine struct {
	generation int64
	engine     *wiring.Engine
}

func (r *EvidencePolicyReconciler) now() time.Time {
	if r.Clock != nil {
		return r.Clock()
	}
	return time.Now().UTC()
}

func (r *EvidencePolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var policy v1alpha1.EvidencePolicy
	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		if apierrors.IsNotFound(err) {
			r.dropEngine(req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	engine, err := r.engineFor(&policy)
	if err != nil {
		logger.Error(err, "building engine from policy")
		r.patchStatus(ctx, &policy, func(s *v1alpha1.EvidencePolicyStatus) {
			s.LastError = err.Error()
			s.ObservedGeneration = policy.Generation
		})
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	if err := engine.Scheduler.RunOnce(ctx); err != nil {
		// Store failures are fatal for the cycle but the policy stays
		// active; surface and retry.
		r.patchStatus(ctx, &policy, func(s *v1alpha1.EvidencePolicyStatus) {
			s.LastError = err.Error()
			s.ObservedGeneration = policy.Generation
		})
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	bundle, err := engine.Exporter.Export(engine.Config.Export.Dir)
	if err != nil {
		r.patchStatus(ctx, &policy, func(s *v1alpha1.EvidencePolicyStatus) {
			s.LastError = err.Error()
			s.ObservedGeneration = policy.Generation
		})
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	now := r.now()
	if err := r.createReport(ctx, &policy, engine, bundle, now); err != nil {
		logger.Error(err, "creating EvidenceReport")
	}

	r.patchStatus(ctx, &policy, func(s *v1alpha1.EvidencePolicyStatus) {
		s.LastError = ""
		s.ObservedGeneration = policy.Generation
		s.LastRunTime = &metav1.Time{Time: now}
		s.Records = int64(engine.Store.Count())
		s.LastBundle = bundle
	})

	logger.Info("collection cycle complete", "records", engine.Store.Count(), "bundle", bundle)
	return ctrl.Result{RequeueAfter: engine.Config.Interval}, nil
}

func (r *EvidencePolicyReconciler) createReport(ctx context.Context, policy *v1alpha1.EvidencePolicy, engine *wiring.Engine, bundle string, now time.Time) error {
	report := &v1alpha1.EvidenceReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-%s", policy.Name, now.Format("20060102-150405")),
		},
		Spec: v1alpha1.EvidenceReportSpec{
			PolicyName:  policy.Name,
			GeneratedAt: metav1.Time{Time: now},
			BundlePath:  bundle,
			RecordCount: int64(engine.Store.Count()),
			Framework:   engine.Mapping.Framework,
		},
	}
	if err := controllerutil.SetControllerReference(policy, report, r.Scheme()); err != nil {
		return err
	}
	if err := r.Create(ctx, report); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func (r *EvidencePolicyReconciler) patchStatus(ctx context.Context, policy *v1alpha1.EvidencePolicy, mutate func(*v1alpha1.EvidencePolicyStatus)) {
	base := policy.DeepCopy()
	mutate(&policy.Status)
	if err := r.Status().Patch(ctx, policy, client.MergeFrom(base)); err != nil {
		log.FromContext(ctx).Error(err, "patching policy status")
	}
}

// engineFor returns the cached engine for the policy, rebuilding it when
// the spec generation changes.
func (r *EvidencePolicyReconciler) engineFor(policy *v1alpha1.EvidencePolicy) (*wiring.Engine, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.engines == nil {
		r.engines = map[string]*cachedEngine{}
	}
	if e, ok := r.engines[policy.Name]; ok && e.generation == policy.Generation {
		return e.engine, nil
	}
	if e, ok := r.engines[policy.Name]; ok {
		_ = e.engine.Close()
		delete(r.engines, policy.Name)
	}
	cfg, err := Translate(&policy.Spec)
	if err != nil {
		return nil, err
	}
	engine, err := wiring.Build(cfg, r.Factories)
	if err != nil {
		return nil, err
	}
	r.engines[policy.Name] = &cachedEngine{generation: policy.Generation, engine: engine}
	return engine, nil
}

func (r *EvidencePolicyReconciler) dropEngine(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.engines[name]; ok {
		_ = e.engine.Close()
		delete(r.engines, name)
	}
}

func (r *EvidencePolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.EvidencePolicy{}).
		Named("evidencepolicy").
		Complete(r)
}

// Translate converts an EvidencePolicySpec into the shared core config.
// This is the entire meaning of the CRD: one schema, multiple frontends.
func Translate(spec *v1alpha1.EvidencePolicySpec) (*core.Config, error) {
	raw := map[string]core.CollectorConfig{}
	for _, c := range spec.Collectors {
		if c.Name == "" {
			return nil, fmt.Errorf("collector entry with empty name")
		}
		cc := core.CollectorConfig{Enabled: true}
		if c.Settings != nil && len(c.Settings.Raw) > 0 {
			var node yaml.Node
			if err := yaml.Unmarshal(c.Settings.Raw, &node); err != nil {
				return nil, fmt.Errorf("collector %s: parse settings: %w", c.Name, err)
			}
			if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
				node = *node.Content[0]
			}
			cc.Settings = node
		}
		raw[c.Name] = cc
	}

	cfg := &core.Config{
		StorePath:  spec.StorePath,
		Export:     core.ExportConfig{Dir: spec.ExportDir},
		Signing:    core.SigningConfig{KeyPath: spec.SigningKeyPath},
		Collectors: raw,
	}
	if spec.Interval != nil {
		cfg.Interval = spec.Interval.Duration
	}
	if cfg.StorePath == "" {
		cfg.StorePath = "/var/lib/evidenced/evidence.jsonl"
	}
	if cfg.Export.Dir == "" {
		cfg.Export.Dir = "/var/lib/evidenced/reports"
	}
	if cfg.Interval == 0 {
		cfg.Interval = time.Hour
	}
	if cfg.Interval < time.Minute {
		return nil, fmt.Errorf("interval %s is below the 1m minimum", cfg.Interval)
	}
	return cfg, nil
}
