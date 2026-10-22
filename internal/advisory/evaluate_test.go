package advisory

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluate_FailsWhenVersionIsBelowFloor(t *testing.T) {
	t.Parallel()

	// arrange
	set := setWithRule(Rule{
		Name:    "certifi",
		Match:   Match{Type: "python", Names: []string{"certifi"}},
		Series:  "none",
		Compare: CompareNumeric,
		Floors:  map[string]string{"*": "2026.10.19"},
	})
	certifi := Package{Name: "certifi", Version: "2026.7.22", Type: "python"}

	// act
	results := set.Evaluate(Input{Packages: []Package{certifi}})

	// assert
	require.Len(t, results, 1)
	assert.Equal(t, VerdictFail, results[0].Verdict)
	assert.Equal(t, "2026.10.19", results[0].Floor)
	assert.Equal(t, "certifi 2026.7.22 is below the fixed version 2026.10.19 for series * (Test advisory)", results[0].Message)
}

func TestEvaluate_PassesWhenVersionEqualsFloor(t *testing.T) {
	t.Parallel()

	// arrange
	set := setWithRule(Rule{
		Name:    "certifi",
		Match:   Match{Type: "python", Names: []string{"certifi"}},
		Series:  "none",
		Compare: CompareNumeric,
		Floors:  map[string]string{"*": "2026.10.19"},
	})
	certifi := Package{Name: "certifi", Version: "2026.10.19", Type: "python"}

	// act
	results := set.Evaluate(Input{Packages: []Package{certifi}})

	// assert
	require.Len(t, results, 1)
	assert.Equal(t, VerdictPass, results[0].Verdict)
	assert.Equal(t, "certifi 2026.10.19 is at or above the fixed version 2026.10.19 (Test advisory)", results[0].Message)
}

func TestEvaluate_ReturnsNothingForPackagesNoRuleMatches(t *testing.T) {
	t.Parallel()

	// arrange
	set := setWithRule(Rule{
		Name:    "certifi",
		Match:   Match{Type: "python", Names: []string{"certifi"}},
		Series:  "none",
		Compare: CompareNumeric,
		Floors:  map[string]string{"*": "2026.10.19"},
	})
	redis := Package{Name: "redis", Version: "7.2", Type: "binary"}

	// act
	results := set.Evaluate(Input{Packages: []Package{redis}})

	// assert
	assert.Empty(t, results)
}

func TestEvaluate_MatchesPackageNamesCaseInsensitively(t *testing.T) {
	t.Parallel()

	// arrange
	set := setWithRule(Rule{
		Name:    "certifi",
		Match:   Match{Type: "python", Names: []string{"certifi"}},
		Series:  "none",
		Compare: CompareNumeric,
		Floors:  map[string]string{"*": "2026.10.19"},
	})
	capitalised := Package{Name: "Certifi", Version: "2026.7.22", Type: "python"}

	// act
	results := set.Evaluate(Input{Packages: []Package{capitalised}})

	// assert
	require.Len(t, results, 1)
	assert.Equal(t, "certifi", results[0].Rule)
}

func TestEvaluate_SkipsRuleWhenImageHasAnotherDistro(t *testing.T) {
	t.Parallel()

	// arrange
	set := setWithRule(Rule{
		Name:    "debian-ca-certificates",
		Match:   Match{Type: "deb", Names: []string{"ca-certificates"}, Distro: "debian"},
		Series:  "distro",
		Compare: CompareDpkg,
		Floors:  map[string]string{"13": "20250419+deb13u1"},
	})
	ubuntu := Distro{ID: "ubuntu", VersionID: "24.04"}
	caCertificates := Package{Name: "ca-certificates", Version: "20250419", Type: "deb"}

	// act
	results := set.Evaluate(Input{Distro: ubuntu, Packages: []Package{caCertificates}})

	// assert
	assert.Empty(t, results)
}

func TestEvaluate_UnknownWhenSeriesHasNoFloor(t *testing.T) {
	t.Parallel()

	// arrange
	set := setWithRule(Rule{
		Name:    "debian-ca-certificates",
		Match:   Match{Type: "deb", Names: []string{"ca-certificates"}, Distro: "debian"},
		Series:  "distro",
		Compare: CompareDpkg,
		Floors:  map[string]string{"13": "20250419+deb13u1"},
	})
	debian11 := Distro{ID: "debian", VersionID: "11"}
	caCertificates := Package{Name: "ca-certificates", Version: "20210119", Type: "deb"}

	// act
	results := set.Evaluate(Input{Distro: debian11, Packages: []Package{caCertificates}})

	// assert
	require.Len(t, results, 1)
	assert.Equal(t, VerdictUnknown, results[0].Verdict)
	assert.Equal(t, "ca-certificates 20210119: no fixed version known for debian 11 (Test advisory)", results[0].Message)
}

func TestEvaluate_FailsWhenSeriesHasNoFloorAndMissingSeriesIsFail(t *testing.T) {
	t.Parallel()

	// arrange
	set := setWithRule(Rule{
		Name:          "go-stdlib",
		Match:         Match{Type: "go-module", Names: []string{"stdlib"}},
		Normalize:     NormalizeGo,
		Series:        "version:2",
		Compare:       CompareNumeric,
		Floors:        map[string]string{"1.27": "1.27.3"},
		MissingSeries: missingSeriesFail,
	})
	go125 := Package{Name: "stdlib", Version: "go1.25.9", Type: "go-module"}

	// act
	results := set.Evaluate(Input{Packages: []Package{go125}})

	// assert
	require.Len(t, results, 1)
	assert.Equal(t, VerdictFail, results[0].Verdict)
	assert.Equal(t, "stdlib go1.25.9 has no fixed release in series 1.25; rebuild on a fixed series (Test advisory)", results[0].Message)
}

func TestEvaluate_UnknownWhenVersionHasNoDigits(t *testing.T) {
	t.Parallel()

	// arrange
	set := setWithRule(Rule{
		Name:    "node",
		Match:   Match{Type: "binary", Names: []string{"node"}},
		Series:  "version:1",
		Compare: CompareNumeric,
		Floors:  map[string]string{"24": "24.22.1"},
	})
	node := Package{Name: "node", Version: "UNKNOWN", Type: "binary"}

	// act
	results := set.Evaluate(Input{Packages: []Package{node}})

	// assert
	require.Len(t, results, 1)
	assert.Equal(t, VerdictUnknown, results[0].Verdict)
	assert.Equal(t, `node version "UNKNOWN" could not be parsed`, results[0].Message)
}

func TestEvaluate_ReturnsOneResultPerAdvisoryMatchingThePackage(t *testing.T) {
	t.Parallel()

	// arrange
	rule := Rule{
		Name:    "certifi",
		Match:   Match{Type: "python", Names: []string{"certifi"}},
		Series:  "none",
		Compare: CompareNumeric,
		Floors:  map[string]string{"*": "2026.10.19"},
	}
	set := &Set{Advisories: []Advisory{
		{ID: "first", Severity: "low", Rules: []Rule{rule}},
		{ID: "second", Severity: "low", Rules: []Rule{rule}},
	}}
	certifi := Package{Name: "certifi", Version: "2026.7.22", Type: "python"}

	// act
	results := set.Evaluate(Input{Packages: []Package{certifi}})

	// assert
	require.Len(t, results, 2)
	assert.Equal(t, "first", results[0].AdvisoryID)
	assert.Equal(t, "second", results[1].AdvisoryID)
}

// The built-in advisory is data, so these cases check its floors against the versions found on
// real images.
func TestDefault_JudgesKnownImageVersions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		distro      Distro
		pkg         Package
		wantRule    string
		wantVerdict Verdict
		wantFloor   string
	}{
		{
			name:        "debian 13 ca-certificates before the fix",
			distro:      Distro{ID: "debian", VersionID: "13"},
			pkg:         Package{Name: "ca-certificates", Version: "20250419", Type: "deb"},
			wantRule:    "os-ca-certificates-debian",
			wantVerdict: VerdictFail,
			wantFloor:   "20250419+deb13u1",
		},
		{
			name:        "debian 13 ca-certificates with the fix",
			distro:      Distro{ID: "debian", VersionID: "13"},
			pkg:         Package{Name: "ca-certificates", Version: "20250419+deb13u1", Type: "deb"},
			wantRule:    "os-ca-certificates-debian",
			wantVerdict: VerdictPass,
			wantFloor:   "20250419+deb13u1",
		},
		{
			name:        "debian 12 ca-certificates one revision before the fix",
			distro:      Distro{ID: "debian", VersionID: "12"},
			pkg:         Package{Name: "ca-certificates", Version: "20250419~deb12u1", Type: "deb"},
			wantRule:    "os-ca-certificates-debian",
			wantVerdict: VerdictFail,
			wantFloor:   "20250419~deb12u2",
		},
		{
			name:        "debian 11 has no fixed release",
			distro:      Distro{ID: "debian", VersionID: "11"},
			pkg:         Package{Name: "ca-certificates", Version: "20250419~deb12u1~deb11u1", Type: "deb"},
			wantRule:    "os-ca-certificates-debian",
			wantVerdict: VerdictUnknown,
		},
		{
			name:        "ubuntu 24.04 ca-certificates before the fix",
			distro:      Distro{ID: "ubuntu", VersionID: "24.04"},
			pkg:         Package{Name: "ca-certificates", Version: "20260601~24.04.1", Type: "deb"},
			wantRule:    "os-ca-certificates-ubuntu",
			wantVerdict: VerdictFail,
			wantFloor:   "20260816ubuntu0.24.04.1",
		},
		{
			name:        "alpine ca-certificates before the fix",
			distro:      Distro{ID: "alpine", VersionID: "3.22.2"},
			pkg:         Package{Name: "ca-certificates", Version: "20250911-r0", Type: "apk"},
			wantRule:    "os-ca-certificates-alpine",
			wantVerdict: VerdictFail,
			wantFloor:   "20261020-r0",
		},
		{
			name:        "alpine ca-certificates with the fix",
			distro:      Distro{ID: "alpine", VersionID: "3.24.2"},
			pkg:         Package{Name: "ca-certificates", Version: "20261020-r0", Type: "apk"},
			wantRule:    "os-ca-certificates-alpine",
			wantVerdict: VerdictPass,
			wantFloor:   "20261020-r0",
		},
		{
			name:        "alpine ca-certificates-bundle before the fix",
			distro:      Distro{ID: "alpine", VersionID: "3.22.2"},
			pkg:         Package{Name: "ca-certificates-bundle", Version: "20250911-r0", Type: "apk"},
			wantRule:    "os-ca-certificates-alpine",
			wantVerdict: VerdictFail,
			wantFloor:   "20261020-r0",
		},
		{
			name:        "wolfi ca-certificates one release before the fix",
			distro:      Distro{ID: "wolfi", VersionID: "20230201"},
			pkg:         Package{Name: "ca-certificates", Version: "20260909-r2", Type: "apk"},
			wantRule:    "os-ca-certificates-wolfi",
			wantVerdict: VerdictFail,
			wantFloor:   "20260909-r3",
		},
		{
			name:        "wolfi ca-certificates-bundle before the fix",
			distro:      Distro{ID: "wolfi", VersionID: "20230201"},
			pkg:         Package{Name: "ca-certificates-bundle", Version: "20260909-r1", Type: "apk"},
			wantRule:    "os-ca-certificates-wolfi",
			wantVerdict: VerdictFail,
			wantFloor:   "20260909-r3",
		},
		{
			name:        "rpm ca-certificates has no known floor",
			distro:      Distro{ID: "amzn", VersionID: "2023"},
			pkg:         Package{Name: "ca-certificates", Version: "2025.2.76-1.0.amzn2023.0.3", Type: "rpm"},
			wantRule:    "os-ca-certificates-rpm",
			wantVerdict: VerdictUnknown,
		},
		{
			name:        "certifi before the fix",
			pkg:         Package{Name: "certifi", Version: "2026.7.22", Type: "python"},
			wantRule:    "python-certifi",
			wantVerdict: VerdictFail,
			wantFloor:   "2026.10.19",
		},
		{
			name:        "certifi with the fix",
			pkg:         Package{Name: "certifi", Version: "2026.10.19", Type: "python"},
			wantRule:    "python-certifi",
			wantVerdict: VerdictPass,
			wantFloor:   "2026.10.19",
		},
		{
			name:        "go 1.27 one patch before the fix",
			pkg:         Package{Name: "stdlib", Version: "go1.27.2", Type: "go-module"},
			wantRule:    "go-stdlib",
			wantVerdict: VerdictFail,
			wantFloor:   "1.27.3",
		},
		{
			name:        "go 1.26 with the fix",
			pkg:         Package{Name: "stdlib", Version: "go1.26.10", Type: "go-module"},
			wantRule:    "go-stdlib",
			wantVerdict: VerdictPass,
			wantFloor:   "1.26.10",
		},
		{
			name:        "go 1.26 with an experiment suffix before the fix",
			pkg:         Package{Name: "stdlib", Version: "go1.26.5-X:jsonv2", Type: "go-module"},
			wantRule:    "go-stdlib",
			wantVerdict: VerdictFail,
			wantFloor:   "1.26.10",
		},
		{
			name:        "go 1.25 has no fixed release",
			pkg:         Package{Name: "stdlib", Version: "go1.25.9", Type: "go-module"},
			wantRule:    "go-stdlib",
			wantVerdict: VerdictFail,
		},
		{
			name:        "node 24 before the fix",
			pkg:         Package{Name: "node", Version: "24.21.0", Type: "binary"},
			wantRule:    "node-runtime",
			wantVerdict: VerdictFail,
			wantFloor:   "24.22.1",
		},
		{
			name:        "node 16 has no fixed release",
			pkg:         Package{Name: "node", Version: "16.7.0", Type: "binary"},
			wantRule:    "node-runtime",
			wantVerdict: VerdictFail,
		},
		{
			name:        "openjdk 25 GA before the fix",
			pkg:         Package{Name: "openjdk", Version: "25+36-LTS", Type: "binary"},
			wantRule:    "java-runtime",
			wantVerdict: VerdictFail,
			wantFloor:   "25.0.5",
		},
		{
			name:        "java 8 before the fix",
			pkg:         Package{Name: "java", Version: "1.8.0_412", Type: "binary"},
			wantRule:    "java-runtime",
			wantVerdict: VerdictFail,
			wantFloor:   "8.0.511",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// arrange
			set := Default()

			// act
			results := set.Evaluate(Input{Distro: tc.distro, Packages: []Package{tc.pkg}})

			// assert
			require.Len(t, results, 1)
			assert.Equal(t, tc.wantRule, results[0].Rule)
			assert.Equal(t, tc.wantVerdict, results[0].Verdict)
			assert.Equal(t, tc.wantFloor, results[0].Floor)
		})
	}
}

func setWithRule(rule Rule) *Set {
	return &Set{Advisories: []Advisory{{
		ID:       "test-advisory",
		Title:    "Test advisory",
		Severity: "high",
		Rules:    []Rule{rule},
	}}}
}
