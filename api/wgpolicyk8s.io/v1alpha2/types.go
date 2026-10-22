package v1alpha2

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PolicyResult is the outcome of one policy rule against one resource.
// +kubebuilder:validation:Enum=pass;fail;warn;error;skip
type PolicyResult string

const (
	StatusPass  PolicyResult = "pass"
	StatusFail  PolicyResult = "fail"
	StatusWarn  PolicyResult = "warn"
	StatusError PolicyResult = "error"
	StatusSkip  PolicyResult = "skip"
)

// PolicySeverity ranks a failing result.
// +kubebuilder:validation:Enum=critical;high;low;medium;info
type PolicySeverity string

const (
	SeverityCritical PolicySeverity = "critical"
	SeverityHigh     PolicySeverity = "high"
	SeverityMedium   PolicySeverity = "medium"
	SeverityLow      PolicySeverity = "low"
	SeverityInfo     PolicySeverity = "info"
)

// PolicyReportSummary counts results by outcome.
type PolicyReportSummary struct {
	Pass  int `json:"pass,omitempty"`
	Fail  int `json:"fail,omitempty"`
	Warn  int `json:"warn,omitempty"`
	Error int `json:"error,omitempty"`
	Skip  int `json:"skip,omitempty"`
}

// PolicyReportResult is one policy rule applied to one or more resources.
type PolicyReportResult struct {
	Source           string                   `json:"source,omitempty"`
	Policy           string                   `json:"policy"`
	Rule             string                   `json:"rule,omitempty"`
	Category         string                   `json:"category,omitempty"`
	Severity         PolicySeverity           `json:"severity,omitempty"`
	Timestamp        metav1.Timestamp         `json:"timestamp,omitempty"`
	Result           PolicyResult             `json:"result,omitempty"`
	Scored           bool                     `json:"scored,omitempty"`
	Resources        []corev1.ObjectReference `json:"resources,omitempty"`
	ResourceSelector *metav1.LabelSelector    `json:"resourceSelector,omitempty"`
	Message          string                   `json:"message,omitempty"`
	Properties       map[string]string        `json:"properties,omitempty"`
}

// PolicyReport is the namespaced report resource of wgpolicyk8s.io/v1alpha2.
// +kubebuilder:object:root=true
// +kubebuilder:resource:shortName=polr
type PolicyReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Scope         *corev1.ObjectReference `json:"scope,omitempty"`
	ScopeSelector *metav1.LabelSelector   `json:"scopeSelector,omitempty"`
	Summary       PolicyReportSummary     `json:"summary,omitempty"`
	Results       []PolicyReportResult    `json:"results,omitempty"`
}

// PolicyReportList contains a list of PolicyReport.
// +kubebuilder:object:root=true
type PolicyReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PolicyReport `json:"items"`
}
