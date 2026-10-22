package controller

import (
	"context"
	"testing"

	kubescapev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/giantswarm/sbom-advisory-operator/api/wgpolicyk8s.io/v1alpha2"
	"github.com/giantswarm/sbom-advisory-operator/internal/advisory"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := kubescapev1beta1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha2.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func newReconciler(c client.Client, reader client.Reader) *SBOMSyftReconciler {
	return &SBOMSyftReconciler{Client: c, Reader: reader, Advisories: advisory.Default, Now: metav1.Now}
}

func reconcileOnce(t *testing.T, r *SBOMSyftReconciler, name string) {
	t.Helper()
	if _, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "kubescape", Name: name}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
}

func getReport(t *testing.T, c client.Client, name string) (*v1alpha2.PolicyReport, bool) {
	t.Helper()
	pr := &v1alpha2.PolicyReport{}
	err := c.Get(context.Background(), types.NamespacedName{Namespace: "kubescape", Name: name}, pr)
	if apierrors.IsNotFound(err) {
		return nil, false
	}
	if err != nil {
		t.Fatalf("Get PolicyReport: %v", err)
	}
	return pr, true
}

func readySBOM(name string, pkgs ...[3]string) *kubescapev1beta1.SBOMSyft {
	return sbomFixture(name, map[string]string{"kubescape.io/status": "ready", "kubescape.io/image-tag": "registry/" + name}, "debian", "13", pkgs...)
}

func TestReconcileCreatesReport(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(readySBOM("a", [3]string{"ca-certificates", "20250419", "deb"})).Build()
	reconcileOnce(t, newReconciler(c, c), "a")
	pr, ok := getReport(t, c, "a")
	if !ok || pr.Summary.Fail != 1 {
		t.Fatalf("report = %+v, found=%v", pr, ok)
	}
}

func TestReconcileUpdatesReport(t *testing.T) {
	stale := &v1alpha2.PolicyReport{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "kubescape"}}
	for i := 0; i < 5; i++ {
		stale.Results = append(stale.Results, v1alpha2.PolicyReportResult{Policy: "old", Result: v1alpha2.StatusFail})
	}
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(readySBOM("a", [3]string{"ca-certificates", "20250419", "deb"}), stale).Build()
	reconcileOnce(t, newReconciler(c, c), "a")
	pr, _ := getReport(t, c, "a")
	if len(pr.Results) != 1 || pr.Results[0].Policy != "emudhra-2026-10" {
		t.Fatalf("results = %+v", pr.Results)
	}
}

func TestReconcileDeletesReportWhenNoResults(t *testing.T) {
	existing := &v1alpha2.PolicyReport{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "kubescape"}}
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(readySBOM("a", [3]string{"redis", "7.2", "binary"}), existing).Build()
	reconcileOnce(t, newReconciler(c, c), "a")
	if _, ok := getReport(t, c, "a"); ok {
		t.Fatal("report should have been deleted")
	}
}

func TestReconcileUnavailableSBOM(t *testing.T) {
	s := sbomFixture("a", map[string]string{"kubescape.io/status": "too-large"}, "", "")
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(s).Build()
	reconcileOnce(t, newReconciler(c, c), "a")
	pr, ok := getReport(t, c, "a")
	if !ok || len(pr.Results) != 1 || pr.Results[0].Result != v1alpha2.StatusError {
		t.Fatalf("report = %+v, found=%v", pr, ok)
	}
}

func TestReconcileDeletesReportWhenSBOMGone(t *testing.T) {
	existing := &v1alpha2.PolicyReport{ObjectMeta: metav1.ObjectMeta{Name: "gone", Namespace: "kubescape"}}
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(existing).Build()
	reconcileOnce(t, newReconciler(c, c), "gone")
	if _, ok := getReport(t, c, "gone"); ok {
		t.Fatal("report should have been deleted")
	}
}

func TestReconcileUsesReaderNotCache(t *testing.T) {
	full := readySBOM("a", [3]string{"ca-certificates", "20250419", "deb"})
	stripped := sbomFixture("a", map[string]string{"kubescape.io/status": "ready"}, "", "")
	reader := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(full).Build()
	cached := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(stripped).Build()
	reconcileOnce(t, newReconciler(cached, reader), "a")
	pr, ok := getReport(t, cached, "a")
	if !ok || pr.Summary.Fail != 1 || pr.Summary.Error != 0 {
		t.Fatalf("report = %+v, found=%v (body must come from Reader)", pr, ok)
	}
}

func TestReconcileSkipsUpdateWhenUnchanged(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(readySBOM("a", [3]string{"ca-certificates", "20250419", "deb"})).Build()
	r := newReconciler(c, c)
	tick := int64(0)
	r.Now = func() metav1.Time { tick++; return metav1.Unix(1_700_000_000+tick, 0) }

	reconcileOnce(t, r, "a")
	first, _ := getReport(t, c, "a")
	reconcileOnce(t, r, "a")
	second, _ := getReport(t, c, "a")
	if first.ResourceVersion != second.ResourceVersion {
		t.Fatalf("report was rewritten although nothing but the timestamp changed: rv %s -> %s", first.ResourceVersion, second.ResourceVersion)
	}

	// A real change must still be written.
	sbom := &kubescapev1beta1.SBOMSyft{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "kubescape", Name: "a"}, sbom); err != nil {
		t.Fatal(err)
	}
	sbom.Spec.Syft.Artifacts[0].Version = "20250419+deb13u1"
	if err := c.Update(context.Background(), sbom); err != nil {
		t.Fatal(err)
	}
	reconcileOnce(t, r, "a")
	third, _ := getReport(t, c, "a")
	if third.ResourceVersion == second.ResourceVersion || third.Summary.Pass != 1 {
		t.Fatalf("report not updated after the SBOM changed: rv %s, summary %+v", third.ResourceVersion, third.Summary)
	}
}
