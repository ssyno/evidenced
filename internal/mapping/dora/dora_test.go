package dora

import (
	"testing"

	"github.com/ssyno/evidenced/internal/evidence"
)

func TestLoadIsValid(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatalf("embedded DORA mapping is invalid: %v", err)
	}
	if m.Framework != "DORA" {
		t.Errorf("Framework = %q", m.Framework)
	}
}

func TestEveryMVPCollectorTargetMapsToAControl(t *testing.T) {
	m, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		collector  string
		targetType string
	}{
		{"tlsscan", "tls/endpoint"},
		{"certlifecycle", "cert-manager/certificate"},
		{"certlifecycle", "cert-manager/issuer"},
		{"rbacposture", "rbac/cluster-role"},
		{"rbacposture", "rbac/binding"},
		{"rbacposture", "rbac/service-account"},
		{"provenance", "workload/image"},
		{"provenance", "admission/policy"},
		{"tlsscan", "evidenced/collector-run"},
		{"certlifecycle", "evidenced/collector-run"},
		{"rbacposture", "evidenced/collector-run"},
		{"provenance", "evidenced/collector-run"},
	}
	for _, tt := range tests {
		t.Run(tt.collector+"/"+tt.targetType, func(t *testing.T) {
			r := evidence.Record{
				CollectorID: tt.collector,
				Target:      evidence.Target{Type: tt.targetType, Name: "x"},
			}
			m.Apply(&r)
			if len(r.ControlIDs) == 0 {
				t.Errorf("no controls mapped for %s/%s", tt.collector, tt.targetType)
			}
			for _, id := range r.ControlIDs {
				if _, ok := m.Control(id); !ok {
					t.Errorf("mapped control %q missing from catalog", id)
				}
			}
		})
	}
}
