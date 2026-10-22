package controller

import (
	"testing"

	kubescapev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/giantswarm/sbom-advisory-operator/api/wgpolicyk8s.io/v1alpha2"
	"github.com/giantswarm/sbom-advisory-operator/internal/advisory"
)

func TestBuildPolicyReport_IsOwnedByTheSBOM(t *testing.T) {
	t.Parallel()

	// arrange
	sbom := newSBOM("app")

	// act
	report := BuildPolicyReport(sbom, nil, metav1.Now())

	// assert
	assert.Equal(t, "app", report.Name)
	assert.Equal(t, sbomNamespace, report.Namespace)
	assert.Equal(t, map[string]string{"app.kubernetes.io/managed-by": "sbom-advisory-operator"}, report.Labels)
	assert.Equal(t, []metav1.OwnerReference{{
		APIVersion: "spdx.softwarecomposition.kubescape.io/v1beta1",
		Kind:       "SBOMSyft",
		Name:       "app",
		UID:        "uid-app",
		Controller: ptr.To(true),
	}}, report.OwnerReferences)
	assert.Equal(t, &corev1.ObjectReference{
		APIVersion: "spdx.softwarecomposition.kubescape.io/v1beta1",
		Kind:       "SBOMSyft",
		Namespace:  sbomNamespace,
		Name:       "app",
		UID:        "uid-app",
	}, report.Scope)
}

func TestBuildPolicyReport_DescribesFailedPackage(t *testing.T) {
	t.Parallel()

	// arrange
	sbom := newSBOM("app")
	sbom.Annotations["kubescape.io/image-tag"] = "registry/app:1.0.0"
	sbom.Spec.Syft.Distro = kubescapev1beta1.LinuxRelease{ID: "debian", VersionID: "13"}
	failed := advisory.Result{
		AdvisoryID: "test-advisory",
		Severity:   "high",
		Category:   "Trust Store",
		Reference:  "https://example.com/advisory",
		Rule:       "go-stdlib",
		Verdict:    advisory.VerdictFail,
		Package:    advisory.Package{Name: "stdlib", Version: "go1.26.6", Type: "go-module"},
		Series:     "1.26",
		Floor:      "1.26.10",
		Message:    "stdlib go1.26.6 is below the fixed version 1.26.10",
	}

	// act
	report := BuildPolicyReport(sbom, []advisory.Result{failed}, metav1.Unix(1_700_000_000, 0))

	// assert
	assert.Equal(t, []v1alpha2.PolicyReportResult{{
		Source:    "sbom-advisory-operator",
		Policy:    "test-advisory",
		Rule:      "go-stdlib",
		Category:  "Trust Store",
		Severity:  v1alpha2.SeverityHigh,
		Timestamp: metav1.Timestamp{Seconds: 1_700_000_000},
		Result:    v1alpha2.StatusFail,
		Message:   "stdlib go1.26.6 is below the fixed version 1.26.10",
		Properties: map[string]string{
			"image":     "registry/app:1.0.0",
			"package":   "stdlib",
			"version":   "go1.26.6",
			"type":      "go-module",
			"series":    "1.26",
			"floor":     "1.26.10",
			"distro":    "debian 13",
			"reference": "https://example.com/advisory",
		},
	}}, report.Results)
}

func TestBuildPolicyReport_PassedResultHasNoSeverity(t *testing.T) {
	t.Parallel()

	// arrange
	passed := advisory.Result{AdvisoryID: "test-advisory", Severity: "high", Verdict: advisory.VerdictPass}

	// act
	report := BuildPolicyReport(newSBOM("app"), []advisory.Result{passed}, metav1.Now())

	// assert
	require.Len(t, report.Results, 1)
	assert.Equal(t, v1alpha2.StatusPass, report.Results[0].Result)
	assert.Empty(t, report.Results[0].Severity)
}

func TestBuildPolicyReport_UnknownVerdictBecomesWarn(t *testing.T) {
	t.Parallel()

	// arrange
	unknown := advisory.Result{AdvisoryID: "test-advisory", Verdict: advisory.VerdictUnknown}

	// act
	report := BuildPolicyReport(newSBOM("app"), []advisory.Result{unknown}, metav1.Now())

	// assert
	require.Len(t, report.Results, 1)
	assert.Equal(t, v1alpha2.StatusWarn, report.Results[0].Result)
}

func TestBuildPolicyReport_SummaryCountsEachVerdict(t *testing.T) {
	t.Parallel()

	// arrange
	results := []advisory.Result{
		{Verdict: advisory.VerdictFail},
		{Verdict: advisory.VerdictFail},
		{Verdict: advisory.VerdictPass},
		{Verdict: advisory.VerdictUnknown},
	}

	// act
	report := BuildPolicyReport(newSBOM("app"), results, metav1.Now())

	// assert
	assert.Equal(t, v1alpha2.PolicyReportSummary{Fail: 2, Pass: 1, Warn: 1}, report.Summary)
}

func TestBuildUnavailablePolicyReport_HasSingleErrorResult(t *testing.T) {
	t.Parallel()

	// arrange
	sbom := newSBOM("app")
	sbom.Annotations["kubescape.io/image-tag"] = "registry/app:1.0.0"

	// act
	report := BuildUnavailablePolicyReport(sbom, "too-large", metav1.Unix(1_700_000_000, 0))

	// assert
	assert.Equal(t, []v1alpha2.PolicyReportResult{{
		Source:     "sbom-advisory-operator",
		Policy:     "sbom-advisory-operator",
		Rule:       "sbom-unavailable",
		Category:   "Trust Store",
		Timestamp:  metav1.Timestamp{Seconds: 1_700_000_000},
		Result:     v1alpha2.StatusError,
		Message:    "SBOM is not evaluable (status: too-large)",
		Properties: map[string]string{"image": "registry/app:1.0.0", "status": "too-large"},
	}}, report.Results)
	assert.Equal(t, v1alpha2.PolicyReportSummary{Error: 1}, report.Summary)
}
