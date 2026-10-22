package advisory

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	older = -1
	equal = 0
	newer = 1
)

func TestCompare_OrdersVersions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		comparator Comparator
		version    string
		than       string
		want       int
	}{
		{name: "dpkg: upstream version is older than its +deb revision", comparator: CompareDpkg, version: "20250419", than: "20250419+deb13u1", want: older},
		{name: "dpkg: ~deb12u1 is older than ~deb12u2", comparator: CompareDpkg, version: "20250419~deb12u1", than: "20250419~deb12u2", want: older},
		{name: "dpkg: identical versions are equal", comparator: CompareDpkg, version: "20250419+deb13u1", than: "20250419+deb13u1", want: equal},
		{name: "dpkg: ~ sorts before the ubuntu suffix", comparator: CompareDpkg, version: "20260601~24.04.1", than: "20260816ubuntu0.24.04.1", want: older},
		{name: "dpkg: an epoch beats any version without one", comparator: CompareDpkg, version: "1:20250419", than: "20250419+deb13u1", want: newer},
		{name: "apk: earlier date is older", comparator: CompareApk, version: "20250911-r0", than: "20261020-r0", want: older},
		{name: "apk: identical versions are equal", comparator: CompareApk, version: "20261020-r0", than: "20261020-r0", want: equal},
		{name: "apk: lower release is older", comparator: CompareApk, version: "20260909-r2", than: "20260909-r3", want: older},
		{name: "rpm: earlier year is older", comparator: CompareRpm, version: "2025.2.76-1.0.amzn2023.0.3", than: "2026.1.1-1.amzn2023", want: older},
		{name: "numeric: month 7 is older than month 10", comparator: CompareNumeric, version: "2026.7.22", than: "2026.10.19", want: older},
		{name: "numeric: identical versions are equal", comparator: CompareNumeric, version: "2026.10.19", than: "2026.10.19", want: equal},
		{name: "numeric: lower patch is older", comparator: CompareNumeric, version: "1.27.2", than: "1.27.3", want: older},
		{name: "numeric: lower minor is older", comparator: CompareNumeric, version: "24.21.0", than: "24.22.1", want: older},
		{name: "numeric: missing components count as zero", comparator: CompareNumeric, version: "25", than: "25.0.5", want: older},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// act
			got, err := Compare(tc.comparator, tc.version, tc.than)

			// assert
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestCompare_RejectsNumericVersionWithoutDigits(t *testing.T) {
	t.Parallel()

	// act
	_, err := Compare(CompareNumeric, "UNKNOWN", "1.0")

	// assert
	assert.Error(t, err)
}

func TestCompare_RejectsUnknownComparator(t *testing.T) {
	t.Parallel()

	// act
	_, err := Compare(Comparator("semver"), "1", "2")

	// assert
	assert.Error(t, err)
}

func TestNormalize_RewritesVersions(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		normalizer Normalizer
		version    string
		want       string
	}{
		{name: "go: drops the go prefix", normalizer: NormalizeGo, version: "go1.27.3", want: "1.27.3"},
		{name: "go: drops the experiment suffix", normalizer: NormalizeGo, version: "go1.26.5-X:jsonv2", want: "1.26.5"},
		{name: "java: drops build and LTS suffix", normalizer: NormalizeJava, version: "25+36-LTS", want: "25"},
		{name: "java: drops the build number", normalizer: NormalizeJava, version: "17.0.21+9", want: "17.0.21"},
		{name: "java: rewrites 1.8.0_N to 8.0.N", normalizer: NormalizeJava, version: "1.8.0_412", want: "8.0.412"},
		{name: "no normalizer keeps the version", normalizer: "", version: "anything", want: "anything"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// act
			got := Normalize(tc.normalizer, tc.version)

			// assert
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestSeries_DerivesFloorKey(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name            string
		mode            string
		version         string
		distroVersionID string
		want            string
	}{
		{name: "none always uses *", mode: "none", version: "1.2.3", distroVersionID: "13", want: "*"},
		{name: "distro uses the distro version", mode: "distro", version: "x", distroVersionID: "24.04", want: "24.04"},
		{name: "version:2 keeps major and minor", mode: "version:2", version: "1.27.2", want: "1.27"},
		{name: "version:1 keeps the major", mode: "version:1", version: "24.21.0", want: "24"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// act
			got, err := Series(tc.mode, tc.version, tc.distroVersionID)

			// assert
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestSeries_RejectsVersionWithFewerComponentsThanRequested(t *testing.T) {
	t.Parallel()

	// act
	_, err := Series("version:2", "25", "")

	// assert
	assert.Error(t, err)
}

func TestSeries_RejectsUnknownMode(t *testing.T) {
	t.Parallel()

	// act
	_, err := Series("bogus", "1", "")

	// assert
	assert.Error(t, err)
}
