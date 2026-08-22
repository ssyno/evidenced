// Package rbacposture observes cluster access-rights posture: privileged
// cluster roles (wildcards, secrets access), bindings to cluster-admin,
// and service-account sprawl. It records subjects and rule shapes only —
// never credentials or tokens.
package rbacposture

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/ssyno/evidenced/internal/core"
	"github.com/ssyno/evidenced/evidence"
)

const (
	collectorID      = "rbacposture"
	collectorVersion = "0.1.0"

	TargetTypeClusterRole    = "rbac/cluster-role"
	TargetTypeBinding        = "rbac/binding"
	TargetTypeServiceAccount = "rbac/service-account"
)

type Config struct{}

type Collector struct {
	client kubernetes.Interface
	clock  func() time.Time
}

func New(_ Config, client kubernetes.Interface) *Collector {
	return &Collector{client: client, clock: func() time.Time { return time.Now().UTC() }}
}

func (c *Collector) ID() string          { return collectorID }
func (c *Collector) Version() string     { return collectorVersion }
func (c *Collector) Description() string { return "RBAC privilege and service-account posture" }

func (c *Collector) RequiredAccess() []core.AccessRequirement {
	return []core.AccessRequirement{
		{
			System: "kubernetes", Resource: "rbac.authorization.k8s.io/clusterroles,clusterrolebindings", Access: "get,list,watch",
			Description: "observes privileged rules and who is bound to them",
		},
		{
			System: "kubernetes", Resource: "serviceaccounts", Access: "get,list,watch",
			Description: "counts service accounts per namespace to evidence sprawl",
		},
	}
}

type roleObservation struct {
	Name              string `json:"name"`
	Rules             int    `json:"rules"`
	WildcardVerbs     bool   `json:"wildcardVerbs"`
	WildcardResources bool   `json:"wildcardResources"`
	WildcardAPIGroups bool   `json:"wildcardApiGroups"`
	SecretsRead       bool   `json:"secretsRead"`
	Builtin           bool   `json:"builtin"` // kubernetes-managed (system: prefix or defaults)
}

type subject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

type bindingObservation struct {
	Name     string    `json:"name"`
	RoleRef  string    `json:"roleRef"`
	Subjects []subject `json:"subjects"`
}

type saObservation struct {
	TotalServiceAccounts int            `json:"totalServiceAccounts"`
	Namespaces           int            `json:"namespaces"`
	PerNamespace         map[string]int `json:"perNamespace"`
}

// Collect emits one record per privileged ClusterRole, one per binding
// to cluster-admin, and a cluster-wide service-account summary.
func (c *Collector) Collect(ctx context.Context) ([]evidence.Record, error) {
	var records []evidence.Record

	roles, err := c.client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list clusterroles: %w", err)
	}
	for _, role := range roles.Items {
		obs := analyzeRole(role)
		if !obs.WildcardVerbs && !obs.WildcardResources && !obs.WildcardAPIGroups && !obs.SecretsRead {
			continue
		}
		records = append(records, c.record(TargetTypeClusterRole, role.Name, nil, obs))
	}

	bindings, err := c.client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list clusterrolebindings: %w", err)
	}
	for _, b := range bindings.Items {
		if b.RoleRef.Name != "cluster-admin" {
			continue
		}
		obs := bindingObservation{Name: b.Name, RoleRef: b.RoleRef.Name}
		for _, s := range b.Subjects {
			obs.Subjects = append(obs.Subjects, subject{Kind: s.Kind, Name: s.Name, Namespace: s.Namespace})
		}
		records = append(records, c.record(TargetTypeBinding, b.Name, map[string]string{"roleRef": b.RoleRef.Name}, obs))
	}

	sas, err := c.client.CoreV1().ServiceAccounts(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list serviceaccounts: %w", err)
	}
	summary := saObservation{PerNamespace: map[string]int{}}
	for _, sa := range sas.Items {
		summary.TotalServiceAccounts++
		summary.PerNamespace[sa.Namespace]++
	}
	summary.Namespaces = len(summary.PerNamespace)
	records = append(records, c.record(TargetTypeServiceAccount, "cluster-wide", nil, summary))

	return records, nil
}

func analyzeRole(role rbacv1.ClusterRole) roleObservation {
	obs := roleObservation{
		Name:    role.Name,
		Rules:   len(role.Rules),
		Builtin: len(role.Name) > 7 && role.Name[:7] == "system:",
	}
	for _, rule := range role.Rules {
		if slices.Contains(rule.Verbs, rbacv1.VerbAll) {
			obs.WildcardVerbs = true
		}
		if slices.Contains(rule.Resources, rbacv1.ResourceAll) {
			obs.WildcardResources = true
		}
		if slices.Contains(rule.APIGroups, rbacv1.APIGroupAll) {
			obs.WildcardAPIGroups = true
		}
		if readsSecrets(rule) {
			obs.SecretsRead = true
		}
	}
	return obs
}

func readsSecrets(rule rbacv1.PolicyRule) bool {
	touchesSecrets := slices.Contains(rule.Resources, "secrets") || slices.Contains(rule.Resources, rbacv1.ResourceAll)
	if !touchesSecrets {
		return false
	}
	for _, v := range rule.Verbs {
		switch v {
		case "get", "list", "watch", rbacv1.VerbAll:
			return true
		}
	}
	return false
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
