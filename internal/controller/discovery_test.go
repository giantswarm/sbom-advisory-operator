package controller

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakediscovery "k8s.io/client-go/discovery/fake"
	clienttesting "k8s.io/client-go/testing"
)

func TestWaitForKubescapeAPI(t *testing.T) {
	present := &fakediscovery.FakeDiscovery{Fake: &clienttesting.Fake{Resources: []*metav1.APIResourceList{{
		GroupVersion: "spdx.softwarecomposition.kubescape.io/v1beta1",
		APIResources: []metav1.APIResource{{Name: "sbomsyfts", Kind: "SBOMSyft"}},
	}}}}
	if err := waitForKubescapeAPIWith(context.Background(), present, time.Millisecond, logr.Discard()); err != nil {
		t.Fatalf("present: unexpected error %v", err)
	}

	absent := &fakediscovery.FakeDiscovery{Fake: &clienttesting.Fake{}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := waitForKubescapeAPIWith(ctx, absent, 5*time.Millisecond, logr.Discard())
	if err == nil || ctx.Err() == nil {
		t.Fatalf("absent: expected the context error, got %v", err)
	}
}
