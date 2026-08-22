// Hand-written deepcopy implementations (no controller-gen in the build
// yet); keep in sync with types.go.
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime"
)

func (in *CollectorSpec) DeepCopyInto(out *CollectorSpec) {
	*out = *in
	if in.Settings != nil {
		out.Settings = in.Settings.DeepCopy()
	}
}

func (in *EvidencePolicySpec) DeepCopyInto(out *EvidencePolicySpec) {
	*out = *in
	if in.Interval != nil {
		d := *in.Interval
		out.Interval = &d
	}
	if in.Collectors != nil {
		out.Collectors = make([]CollectorSpec, len(in.Collectors))
		for i := range in.Collectors {
			in.Collectors[i].DeepCopyInto(&out.Collectors[i])
		}
	}
	if in.Push != nil {
		p := *in.Push
		out.Push = &p
	}
}

func (in *EvidencePolicyStatus) DeepCopyInto(out *EvidencePolicyStatus) {
	*out = *in
	if in.LastRunTime != nil {
		out.LastRunTime = in.LastRunTime.DeepCopy()
	}
}

func (in *EvidencePolicy) DeepCopyInto(out *EvidencePolicy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

func (in *EvidencePolicy) DeepCopy() *EvidencePolicy {
	if in == nil {
		return nil
	}
	out := new(EvidencePolicy)
	in.DeepCopyInto(out)
	return out
}

func (in *EvidencePolicy) DeepCopyObject() runtime.Object {
	return in.DeepCopy()
}

func (in *EvidencePolicyList) DeepCopyInto(out *EvidencePolicyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]EvidencePolicy, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

func (in *EvidencePolicyList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(EvidencePolicyList)
	in.DeepCopyInto(out)
	return out
}

func (in *EvidenceReportSpec) DeepCopyInto(out *EvidenceReportSpec) {
	*out = *in
	out.GeneratedAt = *in.GeneratedAt.DeepCopy()
}

func (in *EvidenceReport) DeepCopyInto(out *EvidenceReport) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
}

func (in *EvidenceReport) DeepCopy() *EvidenceReport {
	if in == nil {
		return nil
	}
	out := new(EvidenceReport)
	in.DeepCopyInto(out)
	return out
}

func (in *EvidenceReport) DeepCopyObject() runtime.Object {
	return in.DeepCopy()
}

func (in *EvidenceReportList) DeepCopyInto(out *EvidenceReportList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]EvidenceReport, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

func (in *EvidenceReportList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(EvidenceReportList)
	in.DeepCopyInto(out)
	return out
}
