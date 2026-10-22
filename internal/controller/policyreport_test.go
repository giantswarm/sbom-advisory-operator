package controller

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/giantswarm/sbom-advisory-operator/api/wgpolicyk8s.io/v1alpha2"
	"github.com/giantswarm/sbom-advisory-operator/internal/advisory"
)

func TestBuildPolicyReport(t *testing.T) {
	s := sbomFixture("img-a", map[string]string{"kubescape.io/image-tag": "registry/img:1"}, "debian", "13")
	results := []advisory.Result{
		{AdvisoryID: "emudhra-2026-10", Severity: "high", Category: "Trust Store", Reference: "https://example", Rule: "go-stdlib", Verdict: advisory.VerdictFail, Package: advisory.Package{Name: "stdlib", Version: "go1.26.6", Type: "go-module"}, Series: "1.26", Floor: "1.26.10", Message: "below"},
		{AdvisoryID: "emudhra-2026-10", Severity: "high", Category: "Trust Store", Rule: "python-certifi", Verdict: advisory.VerdictPass, Package: advisory.Package{Name: "certifi", Version: "2026.10.19", Type: "python"}, Series: "*", Floor: "2026.10.19", Message: "ok"},
		{AdvisoryID: "emudhra-2026-10", Severity: "high", Category: "Trust Store", Rule: "os-ca-certificates-rpm", Verdict: advisory.VerdictUnknown, Package: advisory.Package{Name: "ca-certificates", Version: "2025.2", Type: "rpm"}, Series: "9.8", Message: "unknown"},
	}
	now := metav1.Now()
	pr := BuildPolicyReport(s, results, now)

	if pr.Name != "img-a" || pr.Namespace != "kubescape" {
		t.Errorf("name/namespace = %s/%s", pr.Namespace, pr.Name)
	}
	if len(pr.OwnerReferences) != 1 || pr.OwnerReferences[0].UID != s.UID || pr.OwnerReferences[0].Controller == nil || !*pr.OwnerReferences[0].Controller {
		t.Errorf("owner references = %+v", pr.OwnerReferences)
	}
	if pr.Labels["app.kubernetes.io/managed-by"] != Source {
		t.Errorf("labels = %v", pr.Labels)
	}
	if pr.Scope == nil || pr.Scope.Kind != "SBOMSyft" || pr.Scope.Name != "img-a" || pr.Scope.UID != s.UID {
		t.Errorf("scope = %+v", pr.Scope)
	}
	if len(pr.Results) != 3 {
		t.Fatalf("len(results) = %d", len(pr.Results))
	}
	r0, r1, r2 := pr.Results[0], pr.Results[1], pr.Results[2]
	if r0.Result != v1alpha2.StatusFail || r0.Severity != "high" || r0.Source != "sbom-advisory-operator" || r0.Policy != "emudhra-2026-10" || r0.Rule != "go-stdlib" {
		t.Errorf("results[0] = %+v", r0)
	}
	if r1.Result != v1alpha2.StatusPass || r1.Severity != "" {
		t.Errorf("results[1] = %+v", r1)
	}
	if r2.Result != v1alpha2.StatusWarn {
		t.Errorf("results[2] = %+v", r2)
	}
	if r0.Properties["floor"] != "1.26.10" || r0.Properties["image"] != "registry/img:1" || r0.Properties["distro"] != "debian 13" || r0.Properties["reference"] != "https://example" {
		t.Errorf("results[0].Properties = %v", r0.Properties)
	}
	if r0.Timestamp.Seconds != now.Unix() {
		t.Errorf("timestamp = %+v, want %d", r0.Timestamp, now.Unix())
	}
	want := v1alpha2.PolicyReportSummary{Pass: 1, Fail: 1, Warn: 1}
	if pr.Summary != want {
		t.Errorf("summary = %+v, want %+v", pr.Summary, want)
	}
}

func TestBuildUnavailablePolicyReport(t *testing.T) {
	s := sbomFixture("img-b", map[string]string{"kubescape.io/image-tag": "registry/img:2", "kubescape.io/status": "too-large"}, "", "")
	pr := BuildUnavailablePolicyReport(s, "too-large", metav1.Now())
	if len(pr.Results) != 1 {
		t.Fatalf("len(results) = %d", len(pr.Results))
	}
	r := pr.Results[0]
	if r.Rule != "sbom-unavailable" || r.Policy != "sbom-advisory-operator" || r.Result != v1alpha2.StatusError || r.Category != "Trust Store" {
		t.Errorf("result = %+v", r)
	}
	if r.Message != "SBOM is not evaluable (status: too-large)" {
		t.Errorf("message = %q", r.Message)
	}
	if r.Properties["status"] != "too-large" || r.Properties["image"] != "registry/img:2" {
		t.Errorf("properties = %v", r.Properties)
	}
	if (pr.Summary != v1alpha2.PolicyReportSummary{Error: 1}) {
		t.Errorf("summary = %+v", pr.Summary)
	}
}
