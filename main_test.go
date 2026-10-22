package main

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/cache"

	"github.com/giantswarm/sbom-advisory-operator/api/wgpolicyk8s.io/v1alpha2"
)

func TestCacheOptionsBoundWhatIsCached(t *testing.T) {
	opts := cacheOptions("ops")

	var cm, pr *cache.ByObject
	for obj, by := range opts.ByObject {
		by := by
		switch obj.(type) {
		case *corev1.ConfigMap:
			cm = &by
		case *v1alpha2.PolicyReport:
			pr = &by
		}
	}
	if cm == nil {
		t.Fatal("ConfigMap informer is not restricted")
	}
	if _, ok := cm.Namespaces["ops"]; !ok || len(cm.Namespaces) != 1 {
		t.Errorf("ConfigMap namespaces = %v, want only ops", cm.Namespaces)
	}
	if pr == nil {
		t.Fatal("PolicyReport informer is not restricted")
	}
	want := labels.SelectorFromSet(labels.Set{"app.kubernetes.io/managed-by": "sbom-advisory-operator"})
	if pr.Label == nil || pr.Label.String() != want.String() {
		t.Errorf("PolicyReport label selector = %v, want %v", pr.Label, want)
	}
	if opts.NewInformer == nil {
		t.Error("NewInformer hook (watch-list opt-out) missing")
	}
}
