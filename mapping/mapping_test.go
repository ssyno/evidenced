package mapping

import (
	"reflect"
	"testing"

	"github.com/ssyno/evidenced/evidence"
)

const testMappingYAML = `
framework: TESTFW
controls:
  - id: fw-1
    article: "Article 1"
    title: Certificate hygiene
    summary: Certificates must be rotated before expiry.
  - id: fw-2
    article: "Article 2"
    title: Access control
    summary: Access rights are reviewed.
rules:
  - collector: certs
    targetType: tls/certificate
    controls: [fw-1]
  - collector: certs
    controls: [fw-2]
  - collector: rbac
    controls: [fw-2]
`

func TestLoadMappingValid(t *testing.T) {
	m, err := Load([]byte(testMappingYAML))
	if err != nil {
		t.Fatal(err)
	}
	if m.Framework != "TESTFW" {
		t.Errorf("Framework = %q", m.Framework)
	}
	if c, ok := m.Control("fw-1"); !ok || c.Title != "Certificate hygiene" {
		t.Errorf("Control(fw-1) = %+v, %v", c, ok)
	}
}

func TestLoadMappingRejectsInvalid(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{"no framework", "controls: []\nrules: []"},
		{"duplicate control", "framework: f\ncontrols:\n  - id: a\n  - id: a\n"},
		{"empty control id", "framework: f\ncontrols:\n  - title: x\n"},
		{"rule without collector", "framework: f\ncontrols:\n  - id: a\nrules:\n  - controls: [a]\n"},
		{"rule with no controls", "framework: f\ncontrols:\n  - id: a\nrules:\n  - collector: c\n"},
		{"rule references unknown control", "framework: f\ncontrols:\n  - id: a\nrules:\n  - collector: c\n    controls: [missing]\n"},
		{"not yaml", "{{{"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Load([]byte(tt.yaml)); err == nil {
				t.Error("LoadMapping = nil error, want failure")
			}
		})
	}
}

func TestMappingApply(t *testing.T) {
	m, err := Load([]byte(testMappingYAML))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		collector  string
		targetType string
		want       []string
	}{
		{"target-type rule plus catch-all", "certs", "tls/certificate", []string{"fw-1", "fw-2"}},
		{"catch-all only for other target type", "certs", "tls/issuer", []string{"fw-2"}},
		{"different collector", "rbac", "anything", []string{"fw-2"}},
		{"unknown collector maps to nothing", "nope", "tls/certificate", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := evidence.Record{
				CollectorID: tt.collector,
				Target:      evidence.Target{Type: tt.targetType, Name: "x"},
			}
			m.Apply(&r)
			if !reflect.DeepEqual(r.ControlIDs, tt.want) {
				t.Errorf("ControlIDs = %v, want %v", r.ControlIDs, tt.want)
			}
		})
	}
}
