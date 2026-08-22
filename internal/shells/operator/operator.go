package operator

import (
	"context"
	"flag"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/ssyno/evidenced/api/v1alpha1"
	"github.com/ssyno/evidenced/internal/shells/wiring"
)

// Run starts the operator shell and blocks until the manager stops.
func Run(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("operator", flag.ContinueOnError)
	metricsAddr := fs.String("metrics-bind-address", ":8080", "metrics endpoint bind address")
	probeAddr := fs.String("health-probe-bind-address", ":8081", "health probe bind address")
	leaderElect := fs.Bool("leader-elect", false, "enable leader election")
	zapOpts := zap.Options{}
	zapOpts.BindFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zapOpts)))

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return fmt.Errorf("register client-go scheme: %w", err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		return fmt.Errorf("register evidenced scheme: %w", err)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: *metricsAddr},
		HealthProbeBindAddress: *probeAddr,
		LeaderElection:         *leaderElect,
		LeaderElectionID:       "evidenced.io",
	})
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	factories, err := wiring.KubeFactories(mgr.GetConfig())
	if err != nil {
		return err
	}
	reconciler := &EvidencePolicyReconciler{
		Client:    mgr.GetClient(),
		Factories: factories,
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup EvidencePolicy controller: %w", err)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return err
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return err
	}

	return mgr.Start(ctx)
}
