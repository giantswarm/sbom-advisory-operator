package controller

import (
	"testing"

	kubescapev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func sbomFixture(name string, annotations map[string]string, distroID, distroVersion string, pkgs ...[3]string) *kubescapev1beta1.SBOMSyft {
	s := &kubescapev1beta1.SBOMSyft{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "kubescape", UID: types.UID("uid-" + name), Annotations: annotations}}
	s.Spec.Syft.Distro = kubescapev1beta1.LinuxRelease{ID: distroID, VersionID: distroVersion}
	for _, p := range pkgs {
		var sp kubescapev1beta1.SyftPackage
		sp.Name, sp.Version, sp.Type = p[0], p[1], p[2]
		s.Spec.Syft.Artifacts = append(s.Spec.Syft.Artifacts, sp)
	}
	return s
}

func TestInputFromSBOM(t *testing.T) {
	s := sbomFixture("x", map[string]string{"kubescape.io/image-tag": "gsoci.azurecr.io/giantswarm/app-operator:7.5.4", "kubescape.io/status": "ready"}, "debian", "13",
		[3]string{"ca-certificates", "20250419", "deb"}, [3]string{"stdlib", "go1.26.6", "go-module"})
	in := InputFromSBOM(s)
	if in.Image != "gsoci.azurecr.io/giantswarm/app-operator:7.5.4" {
		t.Errorf("Image = %q", in.Image)
	}
	if in.Distro.ID != "debian" || in.Distro.VersionID != "13" {
		t.Errorf("Distro = %+v", in.Distro)
	}
	if len(in.Packages) != 2 || in.Packages[0].Name != "ca-certificates" || in.Packages[1].Version != "go1.26.6" || in.Packages[1].Type != "go-module" {
		t.Errorf("Packages = %+v", in.Packages)
	}

	bare := sbomFixture("bare", nil, "", "")
	if got := InputFromSBOM(bare).Image; got != "bare" {
		t.Errorf("Image without annotations = %q, want object name", got)
	}
	idOnly := sbomFixture("id", map[string]string{"kubescape.io/image-id": "sha256:abc"}, "", "")
	if got := InputFromSBOM(idOnly).Image; got != "sha256:abc" {
		t.Errorf("Image with image-id only = %q", got)
	}
}

func TestSBOMUnavailable(t *testing.T) {
	cases := []struct {
		name       string
		status     string
		artifacts  int
		wantStatus string
		want       bool
	}{
		{"ready", "ready", 3, "", false},
		{"too-large", "too-large", 0, "too-large", true},
		{"no annotation, empty", "", 0, "empty", true},
		{"incomplete", "incomplete", 3, "incomplete", true},
	}
	for _, tc := range cases {
		ann := map[string]string{}
		if tc.status != "" {
			ann["kubescape.io/status"] = tc.status
		}
		var pkgs [][3]string
		for i := 0; i < tc.artifacts; i++ {
			pkgs = append(pkgs, [3]string{"p", "1", "deb"})
		}
		s := sbomFixture(tc.name, ann, "debian", "13", pkgs...)
		status, unavailable := SBOMUnavailable(s)
		if unavailable != tc.want || status != tc.wantStatus {
			t.Errorf("%s: got (%q, %v), want (%q, %v)", tc.name, status, unavailable, tc.wantStatus, tc.want)
		}
	}
}
