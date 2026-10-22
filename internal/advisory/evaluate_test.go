package advisory

import "testing"

func evalOne(t *testing.T, d Distro, p Package) Result {
	t.Helper()
	rs := Default().Evaluate(Input{Image: "img", Distro: d, Packages: []Package{p}})
	if len(rs) != 1 {
		t.Fatalf("Evaluate(%v, %v) returned %d results, want 1: %+v", d, p, len(rs), rs)
	}
	return rs[0]
}

func TestEvaluateGraveler(t *testing.T) {
	cases := []struct {
		d     Distro
		p     Package
		rule  string
		v     Verdict
		floor string
	}{
		{Distro{"debian", "13"}, Package{"ca-certificates", "20250419", "deb"}, "os-ca-certificates-debian", VerdictFail, "20250419+deb13u1"},
		{Distro{"debian", "13"}, Package{"ca-certificates", "20250419+deb13u1", "deb"}, "os-ca-certificates-debian", VerdictPass, "20250419+deb13u1"},
		{Distro{"debian", "12"}, Package{"ca-certificates", "20250419~deb12u1", "deb"}, "os-ca-certificates-debian", VerdictFail, "20250419~deb12u2"},
		{Distro{"debian", "11"}, Package{"ca-certificates", "20250419~deb12u1~deb11u1", "deb"}, "os-ca-certificates-debian", VerdictUnknown, ""},
		{Distro{"ubuntu", "24.04"}, Package{"ca-certificates", "20260601~24.04.1", "deb"}, "os-ca-certificates-ubuntu", VerdictFail, "20260816ubuntu0.24.04.1"},
		{Distro{"alpine", "3.22.2"}, Package{"ca-certificates", "20250911-r0", "apk"}, "os-ca-certificates-alpine", VerdictFail, "20261020-r0"},
		{Distro{"alpine", "3.24.2"}, Package{"ca-certificates", "20261020-r0", "apk"}, "os-ca-certificates-alpine", VerdictPass, "20261020-r0"},
		{Distro{"wolfi", "20230201"}, Package{"ca-certificates", "20260909-r2", "apk"}, "os-ca-certificates-wolfi", VerdictFail, "20260909-r3"},
		{Distro{"amzn", "2023"}, Package{"ca-certificates", "2025.2.76-1.0.amzn2023.0.3", "rpm"}, "os-ca-certificates-rpm", VerdictUnknown, ""},
		{Distro{}, Package{"certifi", "2026.7.22", "python"}, "python-certifi", VerdictFail, "2026.10.19"},
		{Distro{}, Package{"certifi", "2026.10.19", "python"}, "python-certifi", VerdictPass, "2026.10.19"},
		{Distro{}, Package{"stdlib", "go1.27.2", "go-module"}, "go-stdlib", VerdictFail, "1.27.3"},
		{Distro{}, Package{"stdlib", "go1.26.10", "go-module"}, "go-stdlib", VerdictPass, "1.26.10"},
		{Distro{}, Package{"stdlib", "go1.26.5-X:jsonv2", "go-module"}, "go-stdlib", VerdictFail, "1.26.10"},
		{Distro{}, Package{"stdlib", "go1.25.9", "go-module"}, "go-stdlib", VerdictFail, ""},
		{Distro{}, Package{"node", "24.21.0", "binary"}, "node-runtime", VerdictFail, "24.22.1"},
		{Distro{}, Package{"node", "16.7.0", "binary"}, "node-runtime", VerdictFail, ""},
		{Distro{}, Package{"openjdk", "25+36-LTS", "binary"}, "java-runtime", VerdictFail, "25.0.5"},
	}
	for _, tc := range cases {
		r := evalOne(t, tc.d, tc.p)
		if r.Rule != tc.rule || r.Verdict != tc.v || r.Floor != tc.floor {
			t.Errorf("%v %v: got rule=%q verdict=%q floor=%q, want %q %q %q", tc.d, tc.p, r.Rule, r.Verdict, r.Floor, tc.rule, tc.v, tc.floor)
		}
		if r.Message == "" {
			t.Errorf("%v %v: empty message", tc.d, tc.p)
		}
	}
}

func TestEvaluateNoMatch(t *testing.T) {
	rs := Default().Evaluate(Input{Image: "img", Packages: []Package{{"redis", "7.2", "binary"}}})
	if len(rs) != 0 {
		t.Errorf("got %d results, want 0", len(rs))
	}
}

func TestEvaluateUnparseableVersion(t *testing.T) {
	r := evalOne(t, Distro{}, Package{"node", "UNKNOWN", "binary"})
	if r.Verdict != VerdictUnknown {
		t.Errorf("verdict = %q, want unknown", r.Verdict)
	}
	if want := `node version "UNKNOWN" could not be parsed`; r.Message != want {
		t.Errorf("message = %q, want %q", r.Message, want)
	}
}

func TestEvaluateTwoAdvisoriesSamePackage(t *testing.T) {
	rule := Rule{Name: "c", Match: Match{Type: "python", Names: []string{"certifi"}}, Series: "none", Compare: CompareNumeric, Floors: map[string]string{"*": "2026.10.19"}}
	s := &Set{Advisories: []Advisory{{ID: "a1", Severity: "low", Rules: []Rule{rule}}, {ID: "a2", Severity: "low", Rules: []Rule{rule}}}}
	rs := s.Evaluate(Input{Image: "img", Packages: []Package{{"certifi", "2026.7.22", "python"}}})
	if len(rs) != 2 || rs[0].AdvisoryID != "a1" || rs[1].AdvisoryID != "a2" {
		t.Errorf("got %+v", rs)
	}
}

func TestEvaluateDistroRequired(t *testing.T) {
	rs := Default().Evaluate(Input{Image: "img", Distro: Distro{"ubuntu", "24.04"}, Packages: []Package{{"ca-certificates", "20250419", "deb"}}})
	for _, r := range rs {
		if r.Rule == "os-ca-certificates-debian" {
			t.Errorf("debian rule matched an ubuntu image: %+v", r)
		}
	}
}

func TestEvaluateNameCaseInsensitive(t *testing.T) {
	r := evalOne(t, Distro{}, Package{"Certifi", "2026.7.22", "python"})
	if r.Rule != "python-certifi" {
		t.Errorf("rule = %q, want python-certifi", r.Rule)
	}
}

func TestEvaluateMessages(t *testing.T) {
	const title = "eMudhra intermediate CA compromise (October 2026)"
	cases := []struct {
		d    Distro
		p    Package
		want string
	}{
		{Distro{"debian", "13"}, Package{"ca-certificates", "20250419", "deb"}, "ca-certificates 20250419 is below the fixed version 20250419+deb13u1 for debian 13 (" + title + ")"},
		{Distro{}, Package{"stdlib", "go1.27.2", "go-module"}, "stdlib go1.27.2 is below the fixed version 1.27.3 for series 1.27 (" + title + ")"},
		{Distro{}, Package{"stdlib", "go1.25.9", "go-module"}, "stdlib go1.25.9 has no fixed release in series 1.25; rebuild on a fixed series (" + title + ")"},
		{Distro{"debian", "11"}, Package{"ca-certificates", "20250419~deb12u1~deb11u1", "deb"}, "ca-certificates 20250419~deb12u1~deb11u1: no fixed version known for debian 11 (" + title + ")"},
		{Distro{}, Package{"certifi", "2026.10.19", "python"}, "certifi 2026.10.19 is at or above the fixed version 2026.10.19 (" + title + ")"},
	}
	for _, tc := range cases {
		if got := evalOne(t, tc.d, tc.p).Message; got != tc.want {
			t.Errorf("%v %v:\n got  %q\n want %q", tc.d, tc.p, got, tc.want)
		}
	}
}
