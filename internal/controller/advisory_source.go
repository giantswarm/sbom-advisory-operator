package controller

import (
	"fmt"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"

	"github.com/giantswarm/sbom-advisory-operator/internal/advisory"
)

// EventReasonInvalidAdvisories is recorded on the ConfigMap when its advisories cannot be parsed.
const EventReasonInvalidAdvisories = "InvalidAdvisories"

// AdvisorySource holds the advisory set currently in effect: the built-in default merged with
// whatever the configured ConfigMap provides.
type AdvisorySource struct {
	Namespace string
	Name      string
	Key       string

	recorder record.EventRecorder
	mu       sync.RWMutex
	current  *advisory.Set
}

// NewAdvisorySource returns a source serving the built-in default until Load is called.
func NewAdvisorySource(namespace, name, key string, recorder record.EventRecorder) *AdvisorySource {
	return &AdvisorySource{Namespace: namespace, Name: name, Key: key, recorder: recorder, current: advisory.Default()}
}

// Current returns the advisory set in effect.
func (a *AdvisorySource) Current() *advisory.Set {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.current
}

// Matches reports whether the ConfigMap is the one this source reads.
func (a *AdvisorySource) Matches(namespace, name string) bool {
	return namespace == a.Namespace && name == a.Name
}

// Load parses the ConfigMap's advisories and merges them over the built-in default. On a parse
// error the previous set stays in effect and a warning Event is recorded on the ConfigMap. A
// ConfigMap without the key resets to the default.
func (a *AdvisorySource) Load(cm *corev1.ConfigMap) error {
	data, ok := cm.Data[a.Key]
	if !ok {
		a.set(advisory.Default())
		return nil
	}
	overlay, err := advisory.Parse([]byte(data))
	if err != nil {
		if a.recorder != nil {
			a.recorder.Eventf(cm, corev1.EventTypeWarning, EventReasonInvalidAdvisories, "advisories in key %q rejected, keeping the previous set: %v", a.Key, err)
		}
		return fmt.Errorf("advisories in ConfigMap %s/%s key %q: %w", cm.Namespace, cm.Name, a.Key, err)
	}
	a.set(advisory.Merge(advisory.Default(), overlay))
	return nil
}

// Reset returns to the built-in default, for when the ConfigMap is deleted.
func (a *AdvisorySource) Reset() {
	a.set(advisory.Default())
}

func (a *AdvisorySource) set(s *advisory.Set) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.current = s
}
