// Package advisory evaluates SBOM package lists against version floors.
package advisory

import (
	_ "embed"
	"fmt"
	"strconv"
	"strings"

	"sigs.k8s.io/yaml"
)

//go:embed default_advisories.yaml
var defaultAdvisoriesYAML []byte

// Match selects the packages a rule applies to.
type Match struct {
	Type   string   `json:"type"`
	Names  []string `json:"names"`
	Distro string   `json:"distro,omitempty"`
}

// Rule is one version floor check inside an advisory.
type Rule struct {
	Name          string            `json:"name"`
	Match         Match             `json:"match"`
	Normalize     Normalizer        `json:"normalize,omitempty"`
	Series        string            `json:"series"`
	Compare       Comparator        `json:"compare"`
	Floors        map[string]string `json:"floors"`
	MissingSeries string            `json:"missingSeries,omitempty"`
}

// Advisory groups the rules that stem from one incident.
type Advisory struct {
	ID        string `json:"id"`
	Title     string `json:"title,omitempty"`
	Reference string `json:"reference,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Category  string `json:"category,omitempty"`
	Disabled  bool   `json:"disabled,omitempty"`
	Rules     []Rule `json:"rules,omitempty"`
}

// Set is an ordered list of advisories.
type Set struct {
	Advisories []Advisory `json:"advisories"`
}

const (
	missingSeriesFail    = "fail"
	missingSeriesUnknown = "unknown"
)

var validSeverities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}

// Parse decodes and validates an advisory set from YAML.
func Parse(yamlBytes []byte) (*Set, error) {
	var s Set
	if err := yaml.UnmarshalStrict(yamlBytes, &s); err != nil {
		return nil, fmt.Errorf("invalid advisories yaml: %w", err)
	}
	seenIDs := map[string]bool{}
	for i := range s.Advisories {
		a := &s.Advisories[i]
		if a.ID == "" {
			return nil, fmt.Errorf("advisories[%d]: id is required", i)
		}
		if seenIDs[a.ID] {
			return nil, fmt.Errorf("advisory id %q is declared twice", a.ID)
		}
		seenIDs[a.ID] = true
		if a.Disabled {
			continue
		}
		if !validSeverities[a.Severity] {
			return nil, fmt.Errorf("advisory %q: severity %q must be one of critical, high, medium, low, info", a.ID, a.Severity)
		}
		seenRules := map[string]bool{}
		for j := range a.Rules {
			r := &a.Rules[j]
			if r.Name == "" {
				return nil, fmt.Errorf("advisory %q: rules[%d]: name is required", a.ID, j)
			}
			if seenRules[r.Name] {
				return nil, fmt.Errorf("advisory %q: rule %q is declared twice", a.ID, r.Name)
			}
			seenRules[r.Name] = true
			if err := r.validate(); err != nil {
				return nil, fmt.Errorf("advisory %q: rule %q: %w", a.ID, r.Name, err)
			}
		}
	}
	return &s, nil
}

func (r *Rule) validate() error {
	if r.Match.Type == "" {
		return fmt.Errorf("match.type is required")
	}
	if len(r.Match.Names) == 0 {
		return fmt.Errorf("match.names must list at least one package name")
	}
	switch r.Normalize {
	case "", NormalizeGo, NormalizeJava:
	default:
		return fmt.Errorf("normalize %q must be go or java", r.Normalize)
	}
	if err := validateSeriesMode(r.Series); err != nil {
		return err
	}
	switch r.Compare {
	case CompareDpkg, CompareApk, CompareRpm, CompareNumeric:
	default:
		return fmt.Errorf("compare %q must be one of dpkg, apk, rpm, numeric", r.Compare)
	}
	switch r.MissingSeries {
	case "":
		r.MissingSeries = missingSeriesUnknown
	case missingSeriesFail, missingSeriesUnknown:
	default:
		return fmt.Errorf("missingSeries %q must be fail or unknown", r.MissingSeries)
	}
	if r.Floors == nil {
		r.Floors = map[string]string{}
	}
	return nil
}

func validateSeriesMode(mode string) error {
	switch {
	case mode == seriesNone, mode == seriesDistro:
		return nil
	case strings.HasPrefix(mode, seriesPrefix):
		if n, err := strconv.Atoi(strings.TrimPrefix(mode, seriesPrefix)); err != nil || n < 1 {
			return fmt.Errorf("series %q must be none, distro or version:N", mode)
		}
		return nil
	default:
		return fmt.Errorf("series %q must be none, distro or version:N", mode)
	}
}

// Merge layers overlay onto base by advisory id without mutating either set: an overlay
// advisory with a base id replaces it in place, a disabled overlay removes it, and other
// overlay advisories are appended in overlay order.
func Merge(base, overlay *Set) *Set {
	out := &Set{}
	replacements := map[string]*Advisory{}
	for i := range overlay.Advisories {
		replacements[overlay.Advisories[i].ID] = &overlay.Advisories[i]
	}
	for _, a := range base.Advisories {
		if o, ok := replacements[a.ID]; ok {
			if !o.Disabled {
				out.Advisories = append(out.Advisories, *o)
			}
			delete(replacements, a.ID)
			continue
		}
		out.Advisories = append(out.Advisories, a)
	}
	for _, o := range overlay.Advisories {
		if _, pending := replacements[o.ID]; pending && !o.Disabled {
			out.Advisories = append(out.Advisories, o)
		}
	}
	return out
}

// Default returns the advisory set embedded in the binary.
func Default() *Set {
	s, err := Parse(defaultAdvisoriesYAML)
	if err != nil {
		panic(fmt.Sprintf("embedded default advisories are invalid: %v", err))
	}
	return s
}
