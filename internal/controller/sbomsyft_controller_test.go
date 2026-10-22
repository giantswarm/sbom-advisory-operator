package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/giantswarm/sbom-advisory-operator/api/wgpolicyk8s.io/v1alpha2"
	"github.com/giantswarm/sbom-advisory-operator/internal/advisory"
)

func TestReconcile_CreatesFailingReportWhenPackageIsBelowFloor(t *testing.T) {
	t.Parallel()

	// arrange
	sbom := newSBOM("app")
	addPackage(sbom, advisory.Package{Name: "certifi", Version: "2026.7.22", Type: "python"})
	c := newFakeClient(t, sbom)
	r := newTestReconciler(c, certifiAdvisory("2026.10.19"))

	// act
	_, err := r.Reconcile(t.Context(), requestFor("app"))

	// assert
	require.NoError(t, err)
	report, err := getReport(t, c, "app")
	require.NoError(t, err)
	assert.Equal(t, v1alpha2.PolicyReportSummary{Fail: 1}, report.Summary)
}

func TestReconcile_ReplacesResultsOfExistingReport(t *testing.T) {
	t.Parallel()

	// arrange
	sbom := newSBOM("app")
	addPackage(sbom, advisory.Package{Name: "certifi", Version: "2026.7.22", Type: "python"})
	stale := &v1alpha2.PolicyReport{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: sbomNamespace},
		Results: []v1alpha2.PolicyReportResult{
			{Policy: "removed-advisory", Result: v1alpha2.StatusFail},
			{Policy: "removed-advisory", Result: v1alpha2.StatusFail},
		},
	}
	c := newFakeClient(t, sbom, stale)
	r := newTestReconciler(c, certifiAdvisory("2026.10.19"))

	// act
	_, err := r.Reconcile(t.Context(), requestFor("app"))

	// assert
	require.NoError(t, err)
	report, err := getReport(t, c, "app")
	require.NoError(t, err)
	require.Len(t, report.Results, 1)
	assert.Equal(t, "test-advisory", report.Results[0].Policy)
}

func TestReconcile_DeletesReportWhenNoRuleMatches(t *testing.T) {
	t.Parallel()

	// arrange
	sbom := newSBOM("app")
	addPackage(sbom, advisory.Package{Name: "redis", Version: "7.2", Type: "binary"})
	existing := &v1alpha2.PolicyReport{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: sbomNamespace}}
	c := newFakeClient(t, sbom, existing)
	r := newTestReconciler(c, certifiAdvisory("2026.10.19"))

	// act
	_, err := r.Reconcile(t.Context(), requestFor("app"))

	// assert
	require.NoError(t, err)
	_, err = getReport(t, c, "app")
	assert.True(t, apierrors.IsNotFound(err), "want the report deleted, got %v", err)
}

func TestReconcile_DeletesReportWhenSBOMIsGone(t *testing.T) {
	t.Parallel()

	// arrange
	orphan := &v1alpha2.PolicyReport{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: sbomNamespace}}
	c := newFakeClient(t, orphan)
	r := newTestReconciler(c, certifiAdvisory("2026.10.19"))

	// act
	_, err := r.Reconcile(t.Context(), requestFor("app"))

	// assert
	require.NoError(t, err)
	_, err = getReport(t, c, "app")
	assert.True(t, apierrors.IsNotFound(err), "want the report deleted, got %v", err)
}

func TestReconcile_WritesErrorReportWhenSBOMIsTooLarge(t *testing.T) {
	t.Parallel()

	// arrange
	sbom := newSBOM("app")
	sbom.Annotations["kubescape.io/status"] = "too-large"
	c := newFakeClient(t, sbom)
	r := newTestReconciler(c, certifiAdvisory("2026.10.19"))

	// act
	_, err := r.Reconcile(t.Context(), requestFor("app"))

	// assert
	require.NoError(t, err)
	report, err := getReport(t, c, "app")
	require.NoError(t, err)
	require.Len(t, report.Results, 1)
	assert.Equal(t, v1alpha2.StatusError, report.Results[0].Result)
}

func TestReconcile_ReadsSBOMBodyFromReaderNotCache(t *testing.T) {
	t.Parallel()

	// arrange
	// The cache only holds metadata, so its copy of the SBOM has no packages.
	cached := newFakeClient(t, newSBOM("app"))
	full := newSBOM("app")
	addPackage(full, advisory.Package{Name: "certifi", Version: "2026.7.22", Type: "python"})
	reader := newFakeClient(t, full)
	r := newTestReconciler(cached, certifiAdvisory("2026.10.19"))
	r.Reader = reader

	// act
	_, err := r.Reconcile(t.Context(), requestFor("app"))

	// assert
	require.NoError(t, err)
	report, err := getReport(t, cached, "app")
	require.NoError(t, err)
	assert.Equal(t, v1alpha2.PolicyReportSummary{Fail: 1}, report.Summary)
}

func TestReconcile_DoesNotRewriteReportWhenOnlyTimestampChanges(t *testing.T) {
	t.Parallel()

	// arrange
	sbom := newSBOM("app")
	addPackage(sbom, advisory.Package{Name: "certifi", Version: "2026.7.22", Type: "python"})
	c := newFakeClient(t, sbom)
	r := newTestReconciler(c, certifiAdvisory("2026.10.19"))
	r.Now = func() metav1.Time { return metav1.Unix(1_700_000_000, 0) }
	_, err := r.Reconcile(t.Context(), requestFor("app"))
	require.NoError(t, err)
	before, err := getReport(t, c, "app")
	require.NoError(t, err)
	r.Now = func() metav1.Time { return metav1.Unix(1_700_000_060, 0) }

	// act
	_, err = r.Reconcile(t.Context(), requestFor("app"))

	// assert
	require.NoError(t, err)
	after, err := getReport(t, c, "app")
	require.NoError(t, err)
	assert.Equal(t, before.ResourceVersion, after.ResourceVersion)
}

func TestReconcile_UpdatesReportWhenSBOMChanges(t *testing.T) {
	t.Parallel()

	// arrange
	sbom := newSBOM("app")
	addPackage(sbom, advisory.Package{Name: "certifi", Version: "2026.7.22", Type: "python"})
	c := newFakeClient(t, sbom)
	r := newTestReconciler(c, certifiAdvisory("2026.10.19"))
	_, err := r.Reconcile(t.Context(), requestFor("app"))
	require.NoError(t, err)
	sbom.Spec.Syft.Artifacts[0].Version = "2026.10.19"
	require.NoError(t, c.Update(t.Context(), sbom))

	// act
	_, err = r.Reconcile(t.Context(), requestFor("app"))

	// assert
	require.NoError(t, err)
	report, err := getReport(t, c, "app")
	require.NoError(t, err)
	assert.Equal(t, v1alpha2.PolicyReportSummary{Pass: 1}, report.Summary)
}
