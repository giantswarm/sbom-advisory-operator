package advisory

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const builtInAdvisoryID = "emudhra-2026-10"

func TestDefault_ParsesTheEmbeddedEMudhraAdvisory(t *testing.T) {
	t.Parallel()

	// act
	set := Default()

	// assert
	require.Equal(t, []string{builtInAdvisoryID}, advisoryIDs(set))
	assert.Len(t, set.Advisories[0].Rules, 11)
}

func TestParse_RejectsInvalidAdvisories(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		yaml          string
		errorMentions string
	}{
		{
			name:          "unknown comparator",
			errorMentions: "compare",
			yaml: `
advisories:
  - id: test
    severity: low
    rules:
      - name: certifi
        match: {type: python, names: [certifi]}
        series: none
        compare: semver
        floors: {"*": "1"}
`,
		},
		{
			name:          "unknown normalizer",
			errorMentions: "normalize",
			yaml: `
advisories:
  - id: test
    severity: low
    rules:
      - name: certifi
        match: {type: python, names: [certifi]}
        normalize: python
        series: none
        compare: numeric
        floors: {"*": "1"}
`,
		},
		{
			name:          "series version:N without a number",
			errorMentions: "series",
			yaml: `
advisories:
  - id: test
    severity: low
    rules:
      - name: certifi
        match: {type: python, names: [certifi]}
        series: version:x
        compare: numeric
        floors: {"*": "1"}
`,
		},
		{
			name:          "match without package names",
			errorMentions: "names",
			yaml: `
advisories:
  - id: test
    severity: low
    rules:
      - name: certifi
        match: {type: python}
        series: none
        compare: numeric
        floors: {"*": "1"}
`,
		},
		{
			name:          "rule name declared twice",
			errorMentions: "rule",
			yaml: `
advisories:
  - id: test
    severity: low
    rules:
      - name: certifi
        match: {type: python, names: [certifi]}
        series: none
        compare: numeric
        floors: {"*": "1"}
      - name: certifi
        match: {type: python, names: [certifi]}
        series: none
        compare: numeric
        floors: {"*": "2"}
`,
		},
		{
			name:          "advisory id declared twice",
			errorMentions: "id",
			yaml: `
advisories:
  - id: test
    severity: low
  - id: test
    severity: low
`,
		},
		{
			name:          "unknown severity",
			errorMentions: "severity",
			yaml: `
advisories:
  - id: test
    severity: urgent
`,
		},
		{
			name:          "malformed YAML",
			errorMentions: "yaml",
			yaml:          `advisories: [`,
		},
		{
			name:          "floor that the numeric comparator cannot parse",
			errorMentions: "floor",
			yaml: `
advisories:
  - id: test
    severity: low
    rules:
      - name: certifi
        match: {type: python, names: [certifi]}
        series: none
        compare: numeric
        floors: {"*": "latest"}
`,
		},
		{
			name:          "floor that the dpkg comparator cannot parse",
			errorMentions: "floor",
			yaml: `
advisories:
  - id: test
    severity: low
    rules:
      - name: ca-certificates
        match: {type: deb, names: [ca-certificates]}
        series: distro
        compare: dpkg
        floors: {"13": "not a version!"}
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// act
			_, err := Parse([]byte(tc.yaml))

			// assert
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errorMentions)
		})
	}
}

func TestMerge_AppendsOverlayAdvisoryWithNewID(t *testing.T) {
	t.Parallel()

	// arrange
	base := &Set{Advisories: []Advisory{{ID: "base"}}}
	overlay := &Set{Advisories: []Advisory{{ID: "added"}}}

	// act
	merged := Merge(base, overlay)

	// assert
	assert.Equal(t, []string{"base", "added"}, advisoryIDs(merged))
}

func TestMerge_ReplacesBaseAdvisoryWithSameID(t *testing.T) {
	t.Parallel()

	// arrange
	base := &Set{Advisories: []Advisory{{ID: "shared", Title: "from base"}}}
	overlay := &Set{Advisories: []Advisory{{ID: "shared", Title: "from overlay"}}}

	// act
	merged := Merge(base, overlay)

	// assert
	assert.Equal(t, []Advisory{{ID: "shared", Title: "from overlay"}}, merged.Advisories)
}

func TestMerge_RemovesBaseAdvisoryDisabledByOverlay(t *testing.T) {
	t.Parallel()

	// arrange
	base := &Set{Advisories: []Advisory{{ID: "shared"}}}
	overlay := &Set{Advisories: []Advisory{{ID: "shared", Disabled: true}}}

	// act
	merged := Merge(base, overlay)

	// assert
	assert.Empty(t, merged.Advisories)
}

func TestMerge_IgnoresDisabledAdvisoryThatIsNotInBase(t *testing.T) {
	t.Parallel()

	// arrange
	base := &Set{Advisories: []Advisory{{ID: "base"}}}
	overlay := &Set{Advisories: []Advisory{{ID: "unknown", Disabled: true}}}

	// act
	merged := Merge(base, overlay)

	// assert
	assert.Equal(t, []string{"base"}, advisoryIDs(merged))
}

func TestMerge_DoesNotChangeBase(t *testing.T) {
	t.Parallel()

	// arrange
	base := &Set{Advisories: []Advisory{{ID: "shared"}}}
	overlay := &Set{Advisories: []Advisory{{ID: "shared", Disabled: true}, {ID: "added"}}}

	// act
	Merge(base, overlay)

	// assert
	assert.Equal(t, []string{"shared"}, advisoryIDs(base))
}

func advisoryIDs(s *Set) []string {
	out := make([]string, 0, len(s.Advisories))
	for _, a := range s.Advisories {
		out = append(out, a.ID)
	}
	return out
}
