package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/cache"

	"github.com/giantswarm/sbom-advisory-operator/api/wgpolicyk8s.io/v1alpha2"
	"github.com/giantswarm/sbom-advisory-operator/internal/controller"
)

// byObject returns the cache restriction registered for the given object type, keyed by type
// because cache.Options.ByObject is keyed by object identity.
func byObject[T any](opts cache.Options) (cache.ByObject, bool) {
	for obj, by := range opts.ByObject {
		if _, ok := obj.(T); ok {
			return by, true
		}
	}
	return cache.ByObject{}, false
}

func TestCacheOptions_WatchesConfigMapsOnlyInTheAdvisoryNamespace(t *testing.T) {
	t.Parallel()

	// act
	opts := cacheOptions("ops")

	// assert
	by, ok := byObject[*corev1.ConfigMap](opts)
	require.True(t, ok, "ConfigMap informer must be restricted")
	assert.Len(t, by.Namespaces, 1)
	assert.Contains(t, by.Namespaces, "ops")
}

func TestCacheOptions_CachesOnlyOwnPolicyReports(t *testing.T) {
	t.Parallel()

	// act
	opts := cacheOptions("ops")

	// assert
	by, ok := byObject[*v1alpha2.PolicyReport](opts)
	require.True(t, ok, "PolicyReport informer must be restricted")
	require.NotNil(t, by.Label)
	want := labels.SelectorFromSet(labels.Set{"app.kubernetes.io/managed-by": controller.Source})
	assert.Equal(t, want.String(), by.Label.String())
}

func TestCacheOptions_DisablesWatchListForEveryInformer(t *testing.T) {
	t.Parallel()

	// act
	opts := cacheOptions("ops")

	// assert
	assert.NotNil(t, opts.NewInformer, "the watch-list opt-out hook must be installed")
}
