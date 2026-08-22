package wiring

import (
	"fmt"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/ssyno/evidenced/internal/collectors/certlifecycle"
	"github.com/ssyno/evidenced/internal/collectors/provenance"
	"github.com/ssyno/evidenced/internal/collectors/rbacposture"
	"github.com/ssyno/evidenced/internal/core"
)

// KubeFactories returns collector factories backed by restCfg. Shells
// that can reach a cluster (operator always, cli/daemon when a
// kubeconfig resolves) pass the result to Build.
func KubeFactories(restCfg *rest.Config) (map[string]Factory, error) {
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("build kubernetes client: %w", err)
	}
	dyn, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("build dynamic client: %w", err)
	}
	return map[string]Factory{
		"certlifecycle": func(cc core.CollectorConfig) (core.Collector, error) {
			var cfg certlifecycle.Config
			if err := cc.DecodeSettings(&cfg); err != nil {
				return nil, err
			}
			return certlifecycle.New(cfg, dyn), nil
		},
		"rbacposture": func(cc core.CollectorConfig) (core.Collector, error) {
			var cfg rbacposture.Config
			if err := cc.DecodeSettings(&cfg); err != nil {
				return nil, err
			}
			return rbacposture.New(cfg, clientset), nil
		},
		"provenance": func(cc core.CollectorConfig) (core.Collector, error) {
			var cfg provenance.Config
			if err := cc.DecodeSettings(&cfg); err != nil {
				return nil, err
			}
			return provenance.New(cfg, clientset), nil
		},
	}, nil
}

// ResolveKubeFactories builds Kubernetes collector factories using
// in-cluster config or the default kubeconfig chain. When neither
// resolves it returns nil factories and no error: the shell simply has
// no Kubernetes collectors available, which only matters if one is
// enabled in the config.
func ResolveKubeFactories() (map[string]Factory, error) {
	loading := clientcmd.NewDefaultClientConfigLoadingRules()
	restCfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loading, nil).ClientConfig()
	if err != nil {
		if restCfg, err = rest.InClusterConfig(); err != nil {
			return nil, nil //nolint:nilnil // no cluster access available is not an error
		}
	}
	return KubeFactories(restCfg)
}
