package controller

import (
	"fmt"
	"strings"

	kubescapev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/giantswarm/sbom-advisory-operator/api/wgpolicyk8s.io/v1alpha2"
	"github.com/giantswarm/sbom-advisory-operator/internal/advisory"
)

const (
	// Source is the PolicyReport source every result carries.
	Source = "sbom-advisory-operator"

	labelManagedBy       = "app.kubernetes.io/managed-by"
	ruleSBOMUnavailable  = "sbom-unavailable"
	categoryTrustStore   = "Trust Store"
	sbomSyftAPIVersion   = "spdx.softwarecomposition.kubescape.io/v1beta1"
	sbomSyftKind         = "SBOMSyft"
	unavailableMessageFm = "SBOM is not evaluable (status: %s)"
)

// BuildPolicyReport renders evaluation results as the PolicyReport owned by the SBOMSyft.
func BuildPolicyReport(s *kubescapev1beta1.SBOMSyft, results []advisory.Result, now metav1.Time) *v1alpha2.PolicyReport {
	pr := newReport(s)
	image := imageOf(s)
	distro := strings.TrimSpace(s.Spec.Syft.Distro.ID + " " + s.Spec.Syft.Distro.VersionID)
	ts := metav1.Timestamp{Seconds: now.Unix()}
	for _, r := range results {
		res := v1alpha2.PolicyReportResult{
			Source:    Source,
			Policy:    r.AdvisoryID,
			Rule:      r.Rule,
			Category:  r.Category,
			Timestamp: ts,
			Message:   r.Message,
			Properties: map[string]string{
				"image":     image,
				"package":   r.Package.Name,
				"version":   r.Package.Version,
				"type":      r.Package.Type,
				"series":    r.Series,
				"floor":     r.Floor,
				"distro":    distro,
				"reference": r.Reference,
			},
		}
		switch r.Verdict {
		case advisory.VerdictPass:
			res.Result = v1alpha2.StatusPass
			pr.Summary.Pass++
		case advisory.VerdictFail:
			res.Result = v1alpha2.StatusFail
			res.Severity = v1alpha2.PolicySeverity(r.Severity)
			pr.Summary.Fail++
		default:
			res.Result = v1alpha2.StatusWarn
			pr.Summary.Warn++
		}
		pr.Results = append(pr.Results, res)
	}
	return pr
}

// BuildUnavailablePolicyReport renders the single error result for an SBOM that cannot be evaluated.
func BuildUnavailablePolicyReport(s *kubescapev1beta1.SBOMSyft, status string, now metav1.Time) *v1alpha2.PolicyReport {
	pr := newReport(s)
	pr.Results = []v1alpha2.PolicyReportResult{{
		Source:     Source,
		Policy:     Source,
		Rule:       ruleSBOMUnavailable,
		Category:   categoryTrustStore,
		Timestamp:  metav1.Timestamp{Seconds: now.Unix()},
		Result:     v1alpha2.StatusError,
		Message:    fmt.Sprintf(unavailableMessageFm, status),
		Properties: map[string]string{"image": imageOf(s), "status": status},
	}}
	pr.Summary.Error = 1
	return pr
}

func newReport(s *kubescapev1beta1.SBOMSyft) *v1alpha2.PolicyReport {
	return &v1alpha2.PolicyReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.Name,
			Namespace: s.Namespace,
			Labels:    map[string]string{labelManagedBy: Source},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: sbomSyftAPIVersion,
				Kind:       sbomSyftKind,
				Name:       s.Name,
				UID:        s.UID,
				Controller: ptr.To(true),
			}},
		},
		Scope: &corev1.ObjectReference{
			APIVersion: sbomSyftAPIVersion,
			Kind:       sbomSyftKind,
			Namespace:  s.Namespace,
			Name:       s.Name,
			UID:        s.UID,
		},
	}
}
