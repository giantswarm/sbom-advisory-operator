// Package v1alpha2 holds a minimal copy of the wgpolicyk8s.io/v1alpha2 PolicyReport API.
//
// The types mirror the CRD published by the Kubernetes Policy Working Group
// (https://github.com/kubernetes-sigs/wg-policy-prototypes, Apache-2.0). Only the fields this
// operator writes are declared; the CRD itself is installed by kyverno-crds.
// +kubebuilder:object:generate=true
// +groupName=wgpolicyk8s.io
package v1alpha2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is group version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: "wgpolicyk8s.io", Version: "v1alpha2"}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func addKnownTypes(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion, &PolicyReport{}, &PolicyReportList{})
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}
