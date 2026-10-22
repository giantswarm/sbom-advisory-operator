package advisory

import (
	"strings"
	"testing"
)

func TestParseDefault(t *testing.T) {
	s := Default()
	if len(s.Advisories) != 1 {
		t.Fatalf("Default() has %d advisories, want 1", len(s.Advisories))
	}
	a := s.Advisories[0]
	if a.ID != "emudhra-2026-10" {
		t.Errorf("ID = %q, want emudhra-2026-10", a.ID)
	}
	if len(a.Rules) != 11 {
		t.Errorf("len(Rules) = %d, want 11", len(a.Rules))
	}
	var java *Rule
	for i := range a.Rules {
		if a.Rules[i].Name == "java-runtime" {
			java = &a.Rules[i]
		}
	}
	if java == nil {
		t.Fatal("java-runtime rule missing")
	}
	if got := strings.Join(java.Match.Names, ","); got != "openjdk,java" {
		t.Errorf("java-runtime Match.Names = %q, want openjdk,java", got)
	}
	if java.Normalize != NormalizeJava {
		t.Errorf("java-runtime Normalize = %q, want java", java.Normalize)
	}
}

func TestParseRejects(t *testing.T) {
	cases := []struct{ name, yaml, want string }{
		{"compare", "advisories:\n- id: a\n  severity: low\n  rules:\n  - name: r\n    match: {type: deb, names: [x]}\n    series: none\n    compare: semver\n    floors: {\"*\": \"1\"}\n", "compare"},
		{"normalize", "advisories:\n- id: a\n  severity: low\n  rules:\n  - name: r\n    match: {type: deb, names: [x]}\n    normalize: python\n    series: none\n    compare: numeric\n    floors: {\"*\": \"1\"}\n", "normalize"},
		{"series", "advisories:\n- id: a\n  severity: low\n  rules:\n  - name: r\n    match: {type: deb, names: [x]}\n    series: version:x\n    compare: numeric\n    floors: {\"*\": \"1\"}\n", "series"},
		{"names", "advisories:\n- id: a\n  severity: low\n  rules:\n  - name: r\n    match: {type: deb}\n    series: none\n    compare: numeric\n    floors: {\"*\": \"1\"}\n", "names"},
		{"dup rule", "advisories:\n- id: a\n  severity: low\n  rules:\n  - name: r\n    match: {type: deb, names: [x]}\n    series: none\n    compare: numeric\n    floors: {\"*\": \"1\"}\n  - name: r\n    match: {type: deb, names: [y]}\n    series: none\n    compare: numeric\n    floors: {\"*\": \"1\"}\n", "rule"},
		{"dup advisory", "advisories:\n- id: a\n  severity: low\n- id: a\n  severity: low\n", "id"},
		{"severity", "advisories:\n- id: a\n  severity: urgent\n", "severity"},
		{"yaml", "advisories: [", "yaml"},
	}
	for _, tc := range cases {
		_, err := Parse([]byte(tc.yaml))
		if err == nil {
			t.Errorf("%s: expected an error", tc.name)
			continue
		}
		if !strings.Contains(strings.ToLower(err.Error()), tc.want) {
			t.Errorf("%s: error %q does not mention %q", tc.name, err, tc.want)
		}
	}
}

func TestMerge(t *testing.T) {
	base := Default()

	added := &Set{Advisories: []Advisory{{ID: "test-1", Severity: "low", Rules: []Rule{{Name: "r", Match: Match{Type: "deb", Names: []string{"x"}}, Series: "none", Compare: CompareNumeric, Floors: map[string]string{"*": "1"}}}}}}
	m := Merge(base, added)
	if len(m.Advisories) != 2 || m.Advisories[0].ID != "emudhra-2026-10" || m.Advisories[1].ID != "test-1" {
		t.Errorf("append: got %v", ids(m))
	}

	replaced := &Set{Advisories: []Advisory{{ID: "emudhra-2026-10", Title: "replaced", Severity: "low", Rules: added.Advisories[0].Rules}}}
	m = Merge(base, replaced)
	if len(m.Advisories) != 1 || m.Advisories[0].Title != "replaced" || len(m.Advisories[0].Rules) != 1 {
		t.Errorf("replace: got %d advisories, title %q, %d rules", len(m.Advisories), m.Advisories[0].Title, len(m.Advisories[0].Rules))
	}

	disabled := &Set{Advisories: []Advisory{{ID: "emudhra-2026-10", Disabled: true}}}
	if m = Merge(base, disabled); len(m.Advisories) != 0 {
		t.Errorf("disable: got %v, want none", ids(m))
	}

	nope := &Set{Advisories: []Advisory{{ID: "nope", Disabled: true}}}
	if m = Merge(base, nope); len(m.Advisories) != 1 {
		t.Errorf("disable unknown: got %v, want base unchanged", ids(m))
	}
	if len(base.Advisories) != 1 {
		t.Error("Merge must not mutate base")
	}
}

func ids(s *Set) []string {
	out := make([]string, 0, len(s.Advisories))
	for _, a := range s.Advisories {
		out = append(out, a.ID)
	}
	return out
}
