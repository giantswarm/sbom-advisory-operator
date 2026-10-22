package advisory

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	apkversion "github.com/knqyf263/go-apk-version"
	debversion "github.com/knqyf263/go-deb-version"
	rpmversion "github.com/knqyf263/go-rpm-version"
)

// Comparator names a version ordering.
type Comparator string

const (
	CompareDpkg    Comparator = "dpkg"
	CompareApk     Comparator = "apk"
	CompareRpm     Comparator = "rpm"
	CompareNumeric Comparator = "numeric"
)

// Normalizer names a rewrite applied to a package version before it is compared.
type Normalizer string

const (
	NormalizeGo   Normalizer = "go"
	NormalizeJava Normalizer = "java"
)

const (
	seriesNone   = "none"
	seriesDistro = "distro"
	seriesPrefix = "version:"
)

var digitRuns = regexp.MustCompile(`\d+`)

// Compare orders a against b under the named comparator and returns -1, 0 or 1.
// It returns an error when either side cannot be parsed by that comparator.
func Compare(c Comparator, a, b string) (int, error) {
	switch c {
	case CompareDpkg:
		va, err := debversion.NewVersion(a)
		if err != nil {
			return 0, fmt.Errorf("dpkg version %q: %w", a, err)
		}
		vb, err := debversion.NewVersion(b)
		if err != nil {
			return 0, fmt.Errorf("dpkg version %q: %w", b, err)
		}
		return sign(va.Compare(vb)), nil
	case CompareApk:
		va, err := apkversion.NewVersion(a)
		if err != nil {
			return 0, fmt.Errorf("apk version %q: %w", a, err)
		}
		vb, err := apkversion.NewVersion(b)
		if err != nil {
			return 0, fmt.Errorf("apk version %q: %w", b, err)
		}
		return sign(va.Compare(vb)), nil
	case CompareRpm:
		if !hasDigit(a) || !hasDigit(b) {
			return 0, fmt.Errorf("rpm version %q or %q has no numeric component", a, b)
		}
		return sign(rpmversion.NewVersion(a).Compare(rpmversion.NewVersion(b))), nil
	case CompareNumeric:
		ta, err := numericTuple(a)
		if err != nil {
			return 0, err
		}
		tb, err := numericTuple(b)
		if err != nil {
			return 0, err
		}
		return compareTuples(ta, tb), nil
	default:
		return 0, fmt.Errorf("unknown comparator %q", c)
	}
}

// Normalize rewrites v for the named normalizer; an empty normalizer returns v unchanged.
func Normalize(n Normalizer, v string) string {
	switch n {
	case NormalizeGo:
		v = strings.TrimPrefix(v, "go")
		v, _, _ = strings.Cut(v, "-")
		return v
	case NormalizeJava:
		v, _, _ = strings.Cut(v, "+")
		v, _, _ = strings.Cut(v, "-")
		if rest, ok := strings.CutPrefix(v, "1.8.0_"); ok {
			return "8.0." + rest
		}
		return v
	default:
		return v
	}
}

// Series derives the floor lookup key for a package: "*" for mode "none", the distro
// version ID for mode "distro", or the first N numeric components of version for "version:N".
func Series(mode string, version string, distroVersionID string) (string, error) {
	switch {
	case mode == seriesNone:
		return "*", nil
	case mode == seriesDistro:
		return distroVersionID, nil
	case strings.HasPrefix(mode, seriesPrefix):
		n, err := strconv.Atoi(strings.TrimPrefix(mode, seriesPrefix))
		if err != nil || n < 1 {
			return "", fmt.Errorf("invalid series mode %q", mode)
		}
		parts := digitRuns.FindAllString(version, -1)
		if len(parts) < n {
			return "", fmt.Errorf("version %q has fewer than %d numeric components", version, n)
		}
		return strings.Join(parts[:n], "."), nil
	default:
		return "", fmt.Errorf("unknown series mode %q", mode)
	}
}

func numericTuple(v string) ([]int, error) {
	parts := digitRuns.FindAllString(v, -1)
	if len(parts) == 0 {
		return nil, fmt.Errorf("version %q has no numeric component", v)
	}
	out := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("version %q: %w", v, err)
		}
		out[i] = n
	}
	return out, nil
}

func compareTuples(a, b []int) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			return sign(x - y)
		}
	}
	return 0
}

func hasDigit(s string) bool {
	return digitRuns.MatchString(s)
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}
