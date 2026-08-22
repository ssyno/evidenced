package rbacposture

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ssyno/evidenced/evidence"
)

func fixtures() []runtime.Object {
	return []runtime.Object{
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"},
			}},
		},
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "secret-reader"},
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"},
			}},
		},
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "pod-viewer"},
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"},
			}},
		},
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "ops-admin"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []rbacv1.Subject{
				{Kind: "Group", Name: "ops-team"},
				{Kind: "ServiceAccount", Name: "deployer", Namespace: "ci"},
			},
		},
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "viewers"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "pod-viewer"},
			Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "devs"}},
		},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "prod"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "prod"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "dev"}},
		// A secret with a sensitive value that must never surface in output.
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "db-creds", Namespace: "prod"},
			Data:       map[string][]byte{"password": []byte("hunter2-super-secret")},
		},
	}
}

func TestCollectPosture(t *testing.T) {
	c := New(Config{}, fake.NewClientset(fixtures()...))
	records, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	byTarget := map[string]evidence.Record{}
	for _, r := range records {
		byTarget[r.Target.Type+":"+r.Target.Name] = r
	}

	// cluster-admin and secret-reader are privileged; pod-viewer is not.
	if _, ok := byTarget[TargetTypeClusterRole+":cluster-admin"]; !ok {
		t.Error("cluster-admin role record missing")
	}
	sr, ok := byTarget[TargetTypeClusterRole+":secret-reader"]
	if !ok {
		t.Fatal("secret-reader role record missing")
	}
	if _, ok := byTarget[TargetTypeClusterRole+":pod-viewer"]; ok {
		t.Error("pod-viewer is unprivileged and must not produce a record")
	}
	var robs roleObservation
	if err := json.Unmarshal(sr.Observation, &robs); err != nil {
		t.Fatal(err)
	}
	if !robs.SecretsRead || robs.WildcardVerbs {
		t.Errorf("secret-reader observation = %+v", robs)
	}

	// Only the cluster-admin binding is recorded.
	b, ok := byTarget[TargetTypeBinding+":ops-admin"]
	if !ok {
		t.Fatal("ops-admin binding record missing")
	}
	if _, ok := byTarget[TargetTypeBinding+":viewers"]; ok {
		t.Error("non-admin binding must not produce a record")
	}
	var bobs bindingObservation
	if err := json.Unmarshal(b.Observation, &bobs); err != nil {
		t.Fatal(err)
	}
	if len(bobs.Subjects) != 2 || bobs.Subjects[1].Namespace != "ci" {
		t.Errorf("binding observation = %+v", bobs)
	}

	sa, ok := byTarget[TargetTypeServiceAccount+":cluster-wide"]
	if !ok {
		t.Fatal("service-account summary missing")
	}
	var sobs saObservation
	if err := json.Unmarshal(sa.Observation, &sobs); err != nil {
		t.Fatal(err)
	}
	if sobs.TotalServiceAccounts != 3 || sobs.Namespaces != 2 || sobs.PerNamespace["prod"] != 2 {
		t.Errorf("service-account summary = %+v", sobs)
	}
}

// Secret values present in the cluster must never appear anywhere in the
// collector's output.
func TestNoSecretValuesInOutput(t *testing.T) {
	c := New(Config{}, fake.NewClientset(fixtures()...))
	records, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	all, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(all), "hunter2") {
		t.Fatal("secret value leaked into collector output")
	}
}

func TestAnalyzeRole(t *testing.T) {
	tests := []struct {
		name string
		rule rbacv1.PolicyRule
		want roleObservation
	}{
		{
			"wildcard everything",
			rbacv1.PolicyRule{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
			roleObservation{WildcardVerbs: true, WildcardResources: true, WildcardAPIGroups: true, SecretsRead: true},
		},
		{
			"secrets write only is not secrets read",
			rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"create", "delete"}},
			roleObservation{},
		},
		{
			"resource wildcard implies secrets read when readable",
			rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"*"}, Verbs: []string{"get"}},
			roleObservation{WildcardResources: true, SecretsRead: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzeRole(rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "r"},
				Rules:      []rbacv1.PolicyRule{tt.rule},
			})
			if got.WildcardVerbs != tt.want.WildcardVerbs ||
				got.WildcardResources != tt.want.WildcardResources ||
				got.WildcardAPIGroups != tt.want.WildcardAPIGroups ||
				got.SecretsRead != tt.want.SecretsRead {
				t.Errorf("analyzeRole = %+v, want %+v", got, tt.want)
			}
		})
	}
}
