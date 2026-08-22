// Package v1alpha1 defines the operator shell's CRDs. They are a thin
// frontend: EvidencePolicy translates 1:1 into the plain-YAML core
// config every other shell uses, and EvidenceReport surfaces completed
// export bundles. No controller-runtime types may leak below the shell.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// CollectorSpec enables one collector. Settings carries the
// collector-specific configuration verbatim (same schema as the YAML
// config's settings block).
type CollectorSpec struct {
	Name string `json:"name"`
	// +optional
	Settings *runtime.RawExtension `json:"settings,omitempty"`
}

type EvidencePolicySpec struct {
	// Interval between collection cycles. Defaults to 1h.
	// +optional
	Interval *metav1.Duration `json:"interval,omitempty"`
	// Collectors to enable.
	Collectors []CollectorSpec `json:"collectors"`
	// StorePath is the evidence store location inside the pod (mount a
	// PVC there for durability). Defaults to /var/lib/evidenced/evidence.jsonl.
	// +optional
	StorePath string `json:"storePath,omitempty"`
	// ExportDir is where bundles are written. Defaults to /var/lib/evidenced/reports.
	// +optional
	ExportDir string `json:"exportDir,omitempty"`
	// SigningKeyPath is the ed25519 key used to sign bundles; generated
	// on first use. Empty disables signing.
	// +optional
	SigningKeyPath string `json:"signingKeyPath,omitempty"`
}

type EvidencePolicyStatus struct {
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +optional
	LastRunTime *metav1.Time `json:"lastRunTime,omitempty"`
	// +optional
	Records int64 `json:"records,omitempty"`
	// +optional
	LastBundle string `json:"lastBundle,omitempty"`
	// +optional
	LastError string `json:"lastError,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status

// EvidencePolicy configures continuous evidence collection.
type EvidencePolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EvidencePolicySpec   `json:"spec,omitempty"`
	Status EvidencePolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

type EvidencePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EvidencePolicy `json:"items"`
}

type EvidenceReportSpec struct {
	PolicyName  string      `json:"policyName"`
	GeneratedAt metav1.Time `json:"generatedAt"`
	BundlePath  string      `json:"bundlePath"`
	RecordCount int64       `json:"recordCount"`
	Framework   string      `json:"framework"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster

// EvidenceReport records one completed evidence bundle export.
type EvidenceReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec EvidenceReportSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

type EvidenceReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EvidenceReport `json:"items"`
}
