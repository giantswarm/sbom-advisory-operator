// Package controller reconciles kubescape SBOMSyft objects into PolicyReports.
package controller

import (
	kubescapev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"

	"github.com/giantswarm/sbom-advisory-operator/internal/advisory"
)

const (
	annotationImageTag = "kubescape.io/image-tag"
	annotationImageID  = "kubescape.io/image-id"
	annotationStatus   = "kubescape.io/status"

	statusReady = "ready"
	statusEmpty = "empty"
)

// InputFromSBOM converts a full SBOMSyft body into the evaluator's input.
func InputFromSBOM(s *kubescapev1beta1.SBOMSyft) advisory.Input {
	in := advisory.Input{
		Image:  imageOf(s),
		Distro: advisory.Distro{ID: s.Spec.Syft.Distro.ID, VersionID: s.Spec.Syft.Distro.VersionID},
	}
	for _, a := range s.Spec.Syft.Artifacts {
		in.Packages = append(in.Packages, advisory.Package{Name: a.Name, Version: a.Version, Type: a.Type})
	}
	return in
}

// SBOMUnavailable reports whether the SBOM body cannot be evaluated: kubescape marked it with a
// status other than ready (too-large, incomplete, unsupported-schema, failed) or it has no artifacts.
// The returned status is the annotation value, or "empty" when the annotation is missing.
func SBOMUnavailable(s *kubescapev1beta1.SBOMSyft) (string, bool) {
	status := s.Annotations[annotationStatus]
	if status != "" && status != statusReady {
		return status, true
	}
	if len(s.Spec.Syft.Artifacts) == 0 {
		if status == "" {
			status = statusEmpty
		}
		return status, true
	}
	return "", false
}

func imageOf(s *kubescapev1beta1.SBOMSyft) string {
	if v := s.Annotations[annotationImageTag]; v != "" {
		return v
	}
	if v := s.Annotations[annotationImageID]; v != "" {
		return v
	}
	return s.Name
}
