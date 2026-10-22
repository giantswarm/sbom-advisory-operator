package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/giantswarm/sbom-advisory-operator/internal/advisory"
)

const (
	builtInAdvisoryID     = "emudhra-2026-10"
	advisoryNamespace     = "ops"
	advisoryConfigMapName = "advisories"
	advisoryKey           = "advisories.yaml"
)

const extraAdvisoryYAML = `
advisories:
  - id: extra-advisory
    title: Extra advisory
    severity: low
    rules:
      - name: certifi
        match: {type: python, names: [certifi]}
        series: none
        compare: numeric
        floors: {"*": "2099.1.1"}
`

const disableBuiltInYAML = `
advisories:
  - id: emudhra-2026-10
    disabled: true
`

func TestAdvisorySource_ServesBuiltInAdvisoryBeforeLoad(t *testing.T) {
	t.Parallel()

	// arrange
	source := newTestAdvisorySource(events.NewFakeRecorder(1))

	// act
	current := source.Current()

	// assert
	assert.Equal(t, []string{builtInAdvisoryID}, advisoryIDs(current))
}

func TestAdvisorySource_Load_AddsConfigMapAdvisoriesToBuiltIn(t *testing.T) {
	t.Parallel()

	// arrange
	source := newTestAdvisorySource(events.NewFakeRecorder(1))

	// act
	err := source.Load(advisoryConfigMap(extraAdvisoryYAML))

	// assert
	require.NoError(t, err)
	assert.Equal(t, []string{builtInAdvisoryID, "extra-advisory"}, advisoryIDs(source.Current()))
}

func TestAdvisorySource_Load_DisablesBuiltInAdvisory(t *testing.T) {
	t.Parallel()

	// arrange
	source := newTestAdvisorySource(events.NewFakeRecorder(1))

	// act
	err := source.Load(advisoryConfigMap(disableBuiltInYAML))

	// assert
	require.NoError(t, err)
	assert.Empty(t, advisoryIDs(source.Current()))
}

func TestAdvisorySource_Load_KeepsPreviousAdvisoriesWhenYAMLIsInvalid(t *testing.T) {
	t.Parallel()

	// arrange
	source := newTestAdvisorySource(events.NewFakeRecorder(1))
	require.NoError(t, source.Load(advisoryConfigMap(extraAdvisoryYAML)))

	// act
	err := source.Load(advisoryConfigMap("advisories: ["))

	// assert
	require.Error(t, err)
	assert.Equal(t, []string{builtInAdvisoryID, "extra-advisory"}, advisoryIDs(source.Current()))
}

func TestAdvisorySource_Load_RecordsWarningEventWhenYAMLIsInvalid(t *testing.T) {
	t.Parallel()

	// arrange
	recorder := events.NewFakeRecorder(1)
	source := newTestAdvisorySource(recorder)

	// act
	_ = source.Load(advisoryConfigMap("advisories: ["))

	// assert
	require.Len(t, recorder.Events, 1)
	event := <-recorder.Events
	assert.Contains(t, event, "Warning")
	assert.Contains(t, event, "InvalidAdvisories")
}

func TestAdvisorySource_Load_FallsBackToBuiltInWhenKeyIsMissing(t *testing.T) {
	t.Parallel()

	// arrange
	source := newTestAdvisorySource(events.NewFakeRecorder(1))
	require.NoError(t, source.Load(advisoryConfigMap(extraAdvisoryYAML)))
	withoutKey := advisoryConfigMap("")
	withoutKey.Data = nil

	// act
	err := source.Load(withoutKey)

	// assert
	require.NoError(t, err)
	assert.Equal(t, []string{builtInAdvisoryID}, advisoryIDs(source.Current()))
}

func TestAdvisorySource_Reset_FallsBackToBuiltIn(t *testing.T) {
	t.Parallel()

	// arrange
	source := newTestAdvisorySource(events.NewFakeRecorder(1))
	require.NoError(t, source.Load(advisoryConfigMap(extraAdvisoryYAML)))

	// act
	source.Reset()

	// assert
	assert.Equal(t, []string{builtInAdvisoryID}, advisoryIDs(source.Current()))
}

func TestEnqueueAllSBOMs_QueuesEverySBOMWhenAdvisoryConfigMapChanges(t *testing.T) {
	t.Parallel()

	// arrange
	cm := advisoryConfigMap(extraAdvisoryYAML)
	c := newFakeClient(t, newSBOM("first"), newSBOM("second"), newSBOM("third"), cm)
	r := newTestReconciler(c, nil)
	r.Source = newTestAdvisorySource(events.NewFakeRecorder(1))

	// act
	requests := r.enqueueAllSBOMs(t.Context(), cm)

	// assert
	assert.ElementsMatch(t, []reconcile.Request{requestFor("first"), requestFor("second"), requestFor("third")}, requests)
}

func TestEnqueueAllSBOMs_LoadsChangedAdvisoryConfigMap(t *testing.T) {
	t.Parallel()

	// arrange
	cm := advisoryConfigMap(extraAdvisoryYAML)
	c := newFakeClient(t, cm)
	r := newTestReconciler(c, nil)
	r.Source = newTestAdvisorySource(events.NewFakeRecorder(1))

	// act
	r.enqueueAllSBOMs(t.Context(), cm)

	// assert
	assert.Equal(t, []string{builtInAdvisoryID, "extra-advisory"}, advisoryIDs(r.Source.Current()))
}

func TestEnqueueAllSBOMs_IgnoresOtherConfigMaps(t *testing.T) {
	t.Parallel()

	// arrange
	other := advisoryConfigMap(extraAdvisoryYAML)
	other.Name = "unrelated"
	c := newFakeClient(t, newSBOM("first"), other)
	r := newTestReconciler(c, nil)
	r.Source = newTestAdvisorySource(events.NewFakeRecorder(1))

	// act
	requests := r.enqueueAllSBOMs(t.Context(), other)

	// assert
	assert.Empty(t, requests)
}

func newTestAdvisorySource(recorder events.EventRecorder) *AdvisorySource {
	return NewAdvisorySource(advisoryNamespace, advisoryConfigMapName, advisoryKey, recorder)
}

func advisoryConfigMap(advisoriesYAML string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: advisoryConfigMapName, Namespace: advisoryNamespace},
		Data:       map[string]string{advisoryKey: advisoriesYAML},
	}
}

func advisoryIDs(s *advisory.Set) []string {
	out := make([]string, 0, len(s.Advisories))
	for _, a := range s.Advisories {
		out = append(out, a.ID)
	}
	return out
}
