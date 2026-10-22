package controller

import (
	"testing"

	kubescapev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
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

const sbomNamespace = "kubescape"

// newSBOM returns an SBOMSyft without annotations, distro or packages.
func newSBOM(name string) *kubescapev1beta1.SBOMSyft {
	return &kubescapev1beta1.SBOMSyft{ObjectMeta: metav1.ObjectMeta{
		Name:        name,
		Namespace:   sbomNamespace,
		UID:         types.UID("uid-" + name),
		Annotations: map[string]string{},
	}}
}

func addPackage(s *kubescapev1beta1.SBOMSyft, p advisory.Package) {
	var artifact kubescapev1beta1.SyftPackage
	artifact.Name, artifact.Version, artifact.Type = p.Name, p.Version, p.Type
	s.Spec.Syft.Artifacts = append(s.Spec.Syft.Artifacts, artifact)
}

// certifiAdvisory returns an advisory set with a single rule: python certifi must be at least floor.
func certifiAdvisory(floor string) *advisory.Set {
	return &advisory.Set{Advisories: []advisory.Advisory{{
		ID:       "test-advisory",
		Title:    "Test advisory",
		Severity: "high",
		Rules: []advisory.Rule{{
			Name:    "certifi",
			Match:   advisory.Match{Type: "python", Names: []string{"certifi"}},
			Series:  "none",
			Compare: advisory.CompareNumeric,
			Floors:  map[string]string{"*": floor},
		}},
	}}}
}

func newFakeClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := kubescapev1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := v1alpha2.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

func newTestReconciler(c client.Client, advisories *advisory.Set) *SBOMSyftReconciler {
	return &SBOMSyftReconciler{
		Client:     c,
		Reader:     c,
		Advisories: func() *advisory.Set { return advisories },
		Now:        metav1.Now,
	}
}

func requestFor(sbomName string) reconcile.Request {
	return reconcile.Request{NamespacedName: types.NamespacedName{Namespace: sbomNamespace, Name: sbomName}}
}

func getReport(t *testing.T, c client.Client, name string) (*v1alpha2.PolicyReport, error) {
	t.Helper()
	report := &v1alpha2.PolicyReport{}
	err := c.Get(t.Context(), types.NamespacedName{Namespace: sbomNamespace, Name: name}, report)
	return report, err
}
