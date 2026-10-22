package controller

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/giantswarm/sbom-advisory-operator/internal/advisory"
)

const (
	defaultAdvisoryID = "emudhra-2026-10"
	defaultPlusTest   = "emudhra-2026-10,test-1"
)

const testAdvisoryYAML = `advisories:
  - id: test-1
    title: test
    severity: low
    category: Test
    rules:
      - name: certifi
        match: {type: python, names: [certifi]}
        series: none
        compare: numeric
        floors: {"*": "2099.1.1"}
`

func advisoryConfigMap(name, key, data string) *corev1.ConfigMap {
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ops"}}
	if key != "" {
		cm.Data = map[string]string{key: data}
	}
	return cm
}

func TestAdvisorySourceDefaultUntilLoaded(t *testing.T) {
	src := NewAdvisorySource("ops", "advisories", "advisories.yaml", record.NewFakeRecorder(4))
	if got := ids(src.Current()); len(got) != 1 || got[0] != defaultAdvisoryID {
		t.Errorf("Current() = %v", got)
	}
}

func TestAdvisorySourceLoadMergesOverDefault(t *testing.T) {
	src := NewAdvisorySource("ops", "advisories", "advisories.yaml", record.NewFakeRecorder(4))
	if err := src.Load(advisoryConfigMap("advisories", "advisories.yaml", testAdvisoryYAML)); err != nil {
		t.Fatal(err)
	}
	if got := ids(src.Current()); strings.Join(got, ",") != defaultPlusTest {
		t.Errorf("Current() = %v", got)
	}
}

func TestAdvisorySourceLoadDisablesBuiltin(t *testing.T) {
	src := NewAdvisorySource("ops", "advisories", "advisories.yaml", record.NewFakeRecorder(4))
	if err := src.Load(advisoryConfigMap("advisories", "advisories.yaml", "advisories:\n- id: emudhra-2026-10\n  disabled: true\n")); err != nil {
		t.Fatal(err)
	}
	if got := ids(src.Current()); len(got) != 0 {
		t.Errorf("Current() = %v, want none", got)
	}
}

func TestAdvisorySourceKeepsLastGoodOnInvalid(t *testing.T) {
	rec := record.NewFakeRecorder(4)
	src := NewAdvisorySource("ops", "advisories", "advisories.yaml", rec)
	if err := src.Load(advisoryConfigMap("advisories", "advisories.yaml", testAdvisoryYAML)); err != nil {
		t.Fatal(err)
	}
	if err := src.Load(advisoryConfigMap("advisories", "advisories.yaml", "advisories: [")); err == nil {
		t.Fatal("expected an error for invalid YAML")
	}
	if got := ids(src.Current()); strings.Join(got, ",") != defaultPlusTest {
		t.Errorf("Current() after invalid load = %v", got)
	}
	select {
	case ev := <-rec.Events:
		if !strings.Contains(ev, "InvalidAdvisories") {
			t.Errorf("event = %q, want reason InvalidAdvisories", ev)
		}
	default:
		t.Error("no event recorded")
	}
}

func TestAdvisorySourceMissingKeyFallsBackToDefault(t *testing.T) {
	src := NewAdvisorySource("ops", "advisories", "advisories.yaml", record.NewFakeRecorder(4))
	_ = src.Load(advisoryConfigMap("advisories", "advisories.yaml", testAdvisoryYAML))
	if err := src.Load(advisoryConfigMap("advisories", "", "")); err != nil {
		t.Fatal(err)
	}
	if got := ids(src.Current()); strings.Join(got, ",") != defaultAdvisoryID {
		t.Errorf("Current() = %v", got)
	}
}

func TestAdvisorySourceResetOnDelete(t *testing.T) {
	src := NewAdvisorySource("ops", "advisories", "advisories.yaml", record.NewFakeRecorder(4))
	_ = src.Load(advisoryConfigMap("advisories", "advisories.yaml", testAdvisoryYAML))
	src.Reset()
	if got := ids(src.Current()); strings.Join(got, ",") != defaultAdvisoryID {
		t.Errorf("Current() = %v", got)
	}
}

func TestConfigMapChangeEnqueuesAllSBOMs(t *testing.T) {
	cm := advisoryConfigMap("advisories", "advisories.yaml", testAdvisoryYAML)
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(readySBOM("a"), readySBOM("b"), readySBOM("c"), cm).Build()
	src := NewAdvisorySource("ops", "advisories", "advisories.yaml", record.NewFakeRecorder(4))
	r := &SBOMSyftReconciler{Client: c, Reader: c, Advisories: src.Current, Now: metav1.Now, Source: src}

	reqs := r.enqueueAllSBOMs(context.Background(), cm)
	if len(reqs) != 3 {
		t.Fatalf("got %d requests, want 3: %v", len(reqs), reqs)
	}
	if got := ids(src.Current()); strings.Join(got, ",") != defaultPlusTest {
		t.Errorf("Load was not applied: %v", got)
	}
	if reqs = r.enqueueAllSBOMs(context.Background(), advisoryConfigMap("other", "advisories.yaml", testAdvisoryYAML)); len(reqs) != 0 {
		t.Errorf("unrelated ConfigMap produced %d requests", len(reqs))
	}
}

func ids(s *advisory.Set) []string {
	out := make([]string, 0, len(s.Advisories))
	for _, a := range s.Advisories {
		out = append(out, a.ID)
	}
	return out
}
