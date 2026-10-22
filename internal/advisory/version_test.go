package advisory

import "testing"

func TestCompare(t *testing.T) {
	cases := []struct {
		c    Comparator
		a, b string
		want int
	}{
		{CompareDpkg, "20250419", "20250419+deb13u1", -1},
		{CompareDpkg, "20250419~deb12u1", "20250419~deb12u2", -1},
		{CompareDpkg, "20250419+deb13u1", "20250419+deb13u1", 0},
		{CompareDpkg, "20260601~24.04.1", "20260816ubuntu0.24.04.1", -1},
		{CompareDpkg, "1:20250419", "20250419+deb13u1", 1},
		{CompareApk, "20250911-r0", "20261020-r0", -1},
		{CompareApk, "20261020-r0", "20261020-r0", 0},
		{CompareApk, "20260909-r2", "20260909-r3", -1},
		{CompareRpm, "2025.2.76-1.0.amzn2023.0.3", "2026.1.1-1.amzn2023", -1},
		{CompareNumeric, "2026.7.22", "2026.10.19", -1},
		{CompareNumeric, "2026.10.19", "2026.10.19", 0},
		{CompareNumeric, "1.27.2", "1.27.3", -1},
		{CompareNumeric, "24.21.0", "24.22.1", -1},
		{CompareNumeric, "25", "25.0.5", -1},
	}
	for _, tc := range cases {
		got, err := Compare(tc.c, tc.a, tc.b)
		if err != nil {
			t.Errorf("Compare(%s, %q, %q): unexpected error %v", tc.c, tc.a, tc.b, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Compare(%s, %q, %q) = %d, want %d", tc.c, tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCompareUnparseable(t *testing.T) {
	if _, err := Compare(CompareNumeric, "UNKNOWN", "1.0"); err == nil {
		t.Fatal("expected an error for an unparseable numeric version")
	}
	if _, err := Compare(Comparator("semver"), "1", "2"); err == nil {
		t.Fatal("expected an error for an unknown comparator")
	}
}

func TestNormalize(t *testing.T) {
	cases := []struct {
		n    Normalizer
		in   string
		want string
	}{
		{NormalizeGo, "go1.27.3", "1.27.3"},
		{NormalizeGo, "go1.26.5-X:jsonv2", "1.26.5"},
		{NormalizeJava, "25+36-LTS", "25"},
		{NormalizeJava, "17.0.21+9", "17.0.21"},
		{NormalizeJava, "1.8.0_412", "8.0.412"},
		{"", "anything", "anything"},
	}
	for _, tc := range cases {
		if got := Normalize(tc.n, tc.in); got != tc.want {
			t.Errorf("Normalize(%q, %q) = %q, want %q", tc.n, tc.in, got, tc.want)
		}
	}
}

func TestSeries(t *testing.T) {
	ok := []struct {
		mode, version, distro, want string
	}{
		{"none", "1.2.3", "13", "*"},
		{"distro", "x", "24.04", "24.04"},
		{"version:2", "1.27.2", "", "1.27"},
		{"version:1", "24.21.0", "", "24"},
	}
	for _, tc := range ok {
		got, err := Series(tc.mode, tc.version, tc.distro)
		if err != nil {
			t.Errorf("Series(%q, %q, %q): unexpected error %v", tc.mode, tc.version, tc.distro, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Series(%q, %q, %q) = %q, want %q", tc.mode, tc.version, tc.distro, got, tc.want)
		}
	}
	if _, err := Series("version:2", "25", ""); err == nil {
		t.Error("expected an error when the version has fewer components than requested")
	}
	if _, err := Series("bogus", "1", ""); err == nil {
		t.Error("expected an error for an unknown series mode")
	}
}
