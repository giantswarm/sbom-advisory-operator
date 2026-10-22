package controller

import (
	"testing"

	kubescapev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"

	"github.com/giantswarm/sbom-advisory-operator/internal/advisory"
)

func TestInputFromSBOM_CopiesDistroAndPackages(t *testing.T) {
	t.Parallel()

	// arrange
	sbom := newSBOM("app")
	sbom.Spec.Syft.Distro = kubescapev1beta1.LinuxRelease{ID: "debian", VersionID: "13"}
	addPackage(sbom, advisory.Package{Name: "ca-certificates", Version: "20250419", Type: "deb"})
	addPackage(sbom, advisory.Package{Name: "stdlib", Version: "go1.26.6", Type: "go-module"})

	// act
	input := InputFromSBOM(sbom)

	// assert
	assert.Equal(t, advisory.Distro{ID: "debian", VersionID: "13"}, input.Distro)
	assert.Equal(t, []advisory.Package{
		{Name: "ca-certificates", Version: "20250419", Type: "deb"},
		{Name: "stdlib", Version: "go1.26.6", Type: "go-module"},
	}, input.Packages)
}

func TestInputFromSBOM_TakesImageFromAnnotations(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		annotations map[string]string
		wantImage   string
	}{
		{
			name:        "image tag wins over image id",
			annotations: map[string]string{"kubescape.io/image-tag": "registry/app:1.0.0", "kubescape.io/image-id": "sha256:abc"},
			wantImage:   "registry/app:1.0.0",
		},
		{
			name:        "image id when there is no tag",
			annotations: map[string]string{"kubescape.io/image-id": "sha256:abc"},
			wantImage:   "sha256:abc",
		},
		{
			name:        "object name when there are no image annotations",
			annotations: map[string]string{},
			wantImage:   "app",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// arrange
			sbom := newSBOM("app")
			sbom.Annotations = tc.annotations

			// act
			input := InputFromSBOM(sbom)

			// assert
			assert.Equal(t, tc.wantImage, input.Image)
		})
	}
}

func TestSBOMUnavailable_ReportsSBOMsThatCannotBeEvaluated(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name             string
		statusAnnotation string
		hasPackages      bool
		wantUnavailable  bool
		wantStatus       string
	}{
		{name: "ready with packages is evaluable", statusAnnotation: "ready", hasPackages: true, wantUnavailable: false, wantStatus: ""},
		{name: "too-large is unavailable", statusAnnotation: "too-large", hasPackages: false, wantUnavailable: true, wantStatus: "too-large"},
		{name: "incomplete is unavailable even with packages", statusAnnotation: "incomplete", hasPackages: true, wantUnavailable: true, wantStatus: "incomplete"},
		{name: "no status and no packages is reported as empty", statusAnnotation: "", hasPackages: false, wantUnavailable: true, wantStatus: "empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// arrange
			sbom := newSBOM("app")
			if tc.statusAnnotation != "" {
				sbom.Annotations["kubescape.io/status"] = tc.statusAnnotation
			}
			if tc.hasPackages {
				addPackage(sbom, advisory.Package{Name: "ca-certificates", Version: "20250419", Type: "deb"})
			}

			// act
			status, unavailable := SBOMUnavailable(sbom)

			// assert
			assert.Equal(t, tc.wantUnavailable, unavailable)
			assert.Equal(t, tc.wantStatus, status)
		})
	}
}
