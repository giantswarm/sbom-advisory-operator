package controller

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakediscovery "k8s.io/client-go/discovery/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/stretchr/testify/assert"
)

func TestWaitForKubescapeAPI_ReturnsWhenSBOMSyftIsServed(t *testing.T) {
	t.Parallel()

	// arrange
	discovery := &fakediscovery.FakeDiscovery{Fake: &clienttesting.Fake{Resources: []*metav1.APIResourceList{{
		GroupVersion: "spdx.softwarecomposition.kubescape.io/v1beta1",
		APIResources: []metav1.APIResource{{Name: "sbomsyfts", Kind: "SBOMSyft"}},
	}}}}

	// act
	err := waitForKubescapeAPIWith(t.Context(), discovery, time.Millisecond, logr.Discard())

	// assert
	assert.NoError(t, err)
}

func TestWaitForKubescapeAPI_KeepsPollingUntilContextEnds(t *testing.T) {
	t.Parallel()

	// arrange
	withoutKubescape := &fakediscovery.FakeDiscovery{Fake: &clienttesting.Fake{}}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()

	// act
	err := waitForKubescapeAPIWith(ctx, withoutKubescape, 5*time.Millisecond, logr.Discard())

	// assert
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}
