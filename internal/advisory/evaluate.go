package advisory

import (
	"fmt"
	"strings"
)

// Package is one SBOM artifact.
type Package struct {
	Name    string
	Version string
	Type    string
}

// Distro is the Linux distribution syft detected in the image.
type Distro struct {
	ID        string
	VersionID string
}

// Input is everything the evaluator needs about one image.
type Input struct {
	Image    string
	Distro   Distro
	Packages []Package
}

// Verdict is the outcome of one rule against one package.
type Verdict string

const (
	VerdictPass    Verdict = "pass"
	VerdictFail    Verdict = "fail"
	VerdictUnknown Verdict = "unknown"
)

// Result is one rule applied to one matching package.
type Result struct {
	AdvisoryID string
	Title      string
	Reference  string
	Severity   string
	Category   string
	Rule       string
	Verdict    Verdict
	Package    Package
	Series     string
	Floor      string
	Message    string
}

// Evaluate applies every rule of every advisory to the input, in set order, rule order,
// package order. Packages that no rule matches produce nothing.
func (s *Set) Evaluate(in Input) []Result {
	var out []Result
	for _, a := range s.Advisories {
		if a.Disabled {
			continue
		}
		for _, r := range a.Rules {
			for _, p := range in.Packages {
				if !r.matches(p, in.Distro) {
					continue
				}
				res := Result{AdvisoryID: a.ID, Title: a.Title, Reference: a.Reference, Severity: a.Severity, Category: a.Category, Rule: r.Name, Package: p}
				r.judge(&res, in.Distro, a.Title)
				out = append(out, res)
			}
		}
	}
	return out
}

func (r *Rule) matches(p Package, d Distro) bool {
	if p.Type != r.Match.Type {
		return false
	}
	if r.Match.Distro != "" && r.Match.Distro != d.ID {
		return false
	}
	for _, n := range r.Match.Names {
		if strings.EqualFold(n, p.Name) {
			return true
		}
	}
	return false
}

func (r *Rule) judge(res *Result, d Distro, title string) {
	version := Normalize(r.Normalize, res.Package.Version)
	series, err := Series(r.Series, version, d.VersionID)
	if err != nil {
		res.Verdict = VerdictUnknown
		res.Message = fmt.Sprintf("%s version %q could not be parsed", res.Package.Name, res.Package.Version)
		return
	}
	res.Series = series
	label := r.seriesLabel(series, d)

	floor, ok := r.Floors[series]
	if !ok && r.Series == seriesDistro {
		if major, _, found := strings.Cut(series, "."); found {
			floor, ok = r.Floors[major]
		}
	}
	if !ok {
		if r.MissingSeries == missingSeriesFail {
			res.Verdict = VerdictFail
			res.Message = fmt.Sprintf("%s %s has no fixed release in its series %s; rebuild on a fixed series (%s)", res.Package.Name, res.Package.Version, label, title)
			return
		}
		res.Verdict = VerdictUnknown
		res.Message = fmt.Sprintf("%s %s: no fixed version known for %s (%s)", res.Package.Name, res.Package.Version, label, title)
		return
	}
	res.Floor = floor

	cmp, err := Compare(r.Compare, version, floor)
	if err != nil {
		res.Verdict = VerdictUnknown
		res.Message = fmt.Sprintf("%s version %q could not be parsed", res.Package.Name, res.Package.Version)
		return
	}
	if cmp < 0 {
		res.Verdict = VerdictFail
		res.Message = fmt.Sprintf("%s %s is below the fixed version %s for %s (%s)", res.Package.Name, res.Package.Version, floor, label, title)
		return
	}
	res.Verdict = VerdictPass
	res.Message = fmt.Sprintf("%s %s is at or above the fixed version %s (%s)", res.Package.Name, res.Package.Version, floor, title)
}

func (r *Rule) seriesLabel(series string, d Distro) string {
	if r.Series == seriesDistro {
		return strings.TrimSpace(d.ID + " " + d.VersionID)
	}
	return "series " + series
}
