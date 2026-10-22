# sbom-advisory-operator MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A kubebuilder operator that evaluates every kubescape `SBOMSyft` against a merged set of built-in and ConfigMap-provided package version floors and writes one `wgpolicyk8s.io/v1alpha2` PolicyReport per SBOM.

**Architecture:** A pure evaluation package (`internal/advisory`) ports the validated Python logic: parse and merge advisories, match syft packages, normalise and compare versions with distro-aware comparators, emit verdicts. A single controller watches SBOMSyft metadata, fetches each body uncached, runs the evaluator, and upserts a PolicyReport owned by the SBOMSyft; unavailable SBOMs get a single `error` result. A ConfigMap watch re-enqueues everything on advisory changes, and a discovery gate keeps the pod healthy on clusters without kubescape.

**Tech Stack:** Go 1.26, kubebuilder v4 layout, controller-runtime v0.24.x, `github.com/kubescape/storage` v0.0.348 (SBOMSyft types), `github.com/knqyf263/go-deb-version`, `go-apk-version`, `go-rpm-version`, in-repo copy of PolicyReport v1alpha2 types, Helm chart + Giant Swarm app platform conventions from policy-meta-operator.

**Spec:** `docs/superpowers/specs/2026-10-22-sbom-advisory-operator-design.md` and its `reference/` folder (script, graveler data, verdicts). Copy the whole `docs/superpowers` tree into the new repository in Task 1.

## Global Constraints

- Module path `github.com/giantswarm/sbom-advisory-operator`; team `shield`; Helm chart at `helm/sbom-advisory-operator` with the three `io.giantswarm.application.*` annotations as in policy-meta-operator.
- Go `1.26`, `sigs.k8s.io/controller-runtime v0.24.1`, `k8s.io/* v0.36.x`, `github.com/kubescape/storage v0.0.348`.
- Never cache SBOMSyft bodies: metadata-only watch, `mgr.GetAPIReader()` for the full `Get`.
- PolicyReport `source` is the literal string `sbom-advisory-operator`; `result` is only ever `pass`, `fail`, `warn` (unknown) or `error` (SBOM unavailable).
- Built-in advisories are always active unless a ConfigMap advisory with the same `id` replaces them or sets `disabled: true`.
- A rule with no matching package yields no result; a complete SBOM with zero results gets no PolicyReport and any existing one is deleted; an unavailable SBOM always gets a report with one `error` result.
- Commit messages: single subject line, no body, no co-author trailer.
- Go style per `gs-godev:go-conventions`; run `gofmt`, `go vet` and the repo's pre-commit before each commit.

## Review Focus

- A syft package whose version has no digits (`binary` artifacts commonly report `UNKNOWN`) must produce `warn` with message `node version "UNKNOWN" could not be parsed`, never a panic or a false `pass`. Pinned in Task 3.
- A Go stdlib version with a GOEXPERIMENT suffix (`go1.26.5-X:jsonv2`) must compare as `1.26.5`, not pick up the `2` from `jsonv2`. Pinned in Task 2.
- Two different advisories matching the same package must both appear as separate results in the same report. Pinned in Task 3.
- An SBOMSyft deleted between the watch event and the `Get` must not leave a stale PolicyReport: the reconciler deletes the report on NotFound. Pinned in Task 4.
- A ConfigMap with invalid YAML must leave the last good merged set active and record an Event; it must not drop the built-in advisories or wipe reports. Pinned in Task 5.

---

### Task 1: Repository, scaffold, and docs

**Files:**
- Create: repository `giantswarm/sbom-advisory-operator` via `devctl repo create`
- Create: `main.go`, `go.mod`, `Dockerfile`, `.abs/main.yaml`, `.ats/main.yaml`, `Makefile.custom.mk` (kubebuilder scaffold adjusted to the policy-meta-operator shape)
- Create: `docs/superpowers/specs/...`, `docs/superpowers/plans/...` (copied from `/home/zach/go/src/github.com/giantswarm/sbom-advisory-operator-planning/docs/superpowers`)

**Interfaces:**
- Produces: a buildable module `github.com/giantswarm/sbom-advisory-operator` with an empty manager that starts, serves `/healthz` on `:8081` and metrics on `:8080`.

- [ ] **Step 1: Upgrade devctl and dry-run the repository declaration**

Run: `devctl version`. 7.23.2 lacks `devctl repo create`; install the latest release from `giantswarm/devctl`, then `devctl auth login --muster-only`.
Run: `devctl repo create --help` and read the valid `--component-type`, `--flavour` and `--language` values; pick the operator/app component type and the Go language. Then:

```bash
devctl repo create --team shield --name sbom-advisory-operator --component-type <app type> --flavour <kubebuilder or generic go flavour> --language go --description "Evaluates kubescape SBOMs against package version floors and publishes PolicyReports" --visibility public --dry-run
```
Expected: rendered entry, derived template, `ok` verdict.

- [ ] **Step 2: Create the repository and clone it**

Run the same command without `--dry-run`, then `devctl repo watch sbom-advisory-operator --pull-request <n>` until `scaffolded`. Clone to `/home/zach/go/src/github.com/giantswarm/sbom-advisory-operator`.

- [ ] **Step 3: Scaffold the kubebuilder layout if the template did not**

If `main.go` is absent: `kubebuilder init --domain giantswarm.io --repo github.com/giantswarm/sbom-advisory-operator --project-name sbom-advisory-operator`. Do not run `kubebuilder create api` (no CRD in the MVP). Move `cmd/main.go` to `main.go` to match policy-meta-operator, set `go 1.26` in `go.mod`, pin `sigs.k8s.io/controller-runtime v0.24.1`.

- [ ] **Step 4: Copy the convention files from policy-meta-operator**

Copy and rename: `Dockerfile` (distroless static, binary `sbom-advisory-operator-${TARGETOS}-${TARGETARCH}` → `/manager`), `.abs/main.yaml`, `.ats/main.yaml`, `Makefile.custom.mk` (drop the docker-compose and kind targets), `.nancy-ignore` empty. Copy `docs/superpowers` from the planning folder.

- [ ] **Step 5: Verify it builds and starts**

Run: `go build ./... && go vet ./...`
Expected: no output.
Run: `go run . --health-probe-bind-address :18081 --metrics-bind-address :18080` against the current kubeconfig for five seconds, then `curl -s localhost:18081/healthz`.
Expected: `ok`.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "Scaffold sbom-advisory-operator"
```

---

### Task 2: Version comparison, normalisation, and series

**Files:**
- Create: `internal/advisory/version.go`
- Test: `internal/advisory/version_test.go`

**Interfaces:**
- Produces:
  - `type Comparator string` with constants `CompareDpkg = "dpkg"`, `CompareApk = "apk"`, `CompareRpm = "rpm"`, `CompareNumeric = "numeric"`.
  - `func Compare(c Comparator, a, b string) (int, error)` — returns -1/0/1; error when either side cannot be parsed by the named comparator.
  - `type Normalizer string` with constants `NormalizeGo = "go"`, `NormalizeJava = "java"`; `func Normalize(n Normalizer, v string) string` (empty `n` returns `v` unchanged).
  - `func Series(mode string, version string, distroVersionID string) (string, error)` — `mode` is `none`, `distro`, or `version:N`; returns `"*"` for `none`, the distro versionID for `distro`, the first N numeric components joined by `.` for `version:N`; error on an unknown mode or when `version:N` finds fewer than N components.

- [ ] **Step 1: Write the failing tests**

```go
func TestCompare(t *testing.T) {
	cases := []struct{ c Comparator; a, b string; want int }{
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
	// assert Compare(c.c, c.a, c.b) == c.want with no error
}

func TestCompareUnparseable(t *testing.T) {
	_, err := Compare(CompareNumeric, "UNKNOWN", "1.0")
	// assert err != nil
}

func TestNormalize(t *testing.T) {
	// Normalize(NormalizeGo, "go1.27.3") == "1.27.3"
	// Normalize(NormalizeGo, "go1.26.5-X:jsonv2") == "1.26.5"
	// Normalize(NormalizeJava, "25+36-LTS") == "25"
	// Normalize(NormalizeJava, "17.0.21+9") == "17.0.21"
	// Normalize(NormalizeJava, "1.8.0_412") == "8.0.412"
	// Normalize("", "anything") == "anything"
}

func TestSeries(t *testing.T) {
	// Series("none", "1.2.3", "13") == "*"
	// Series("distro", "x", "24.04") == "24.04"
	// Series("version:2", "1.27.2", "") == "1.27"
	// Series("version:1", "24.21.0", "") == "24"
	// Series("version:2", "25", "") returns an error
	// Series("bogus", "1", "") returns an error
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/advisory/ -run 'TestCompare|TestNormalize|TestSeries' -v`
Expected: FAIL, undefined identifiers.

- [ ] **Step 3: Implement `version.go`**

`go get github.com/knqyf263/go-deb-version github.com/knqyf263/go-apk-version github.com/knqyf263/go-rpm-version`. Numeric comparison: extract all `\d+` runs into integer slices and compare lexicographically, shorter slice padded with zeros; error when a side has no digits. `NormalizeGo`: `strings.TrimPrefix(v, "go")`, then cut at the first `-`. `NormalizeJava`: cut at the first `+`, then at the first `-`, then rewrite a `1.8.0_N` prefix to `8.0.N`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/advisory/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/advisory/version.go internal/advisory/version_test.go go.mod go.sum
git commit -m "Add version comparison, normalisation and series helpers"
```

---

### Task 3: Advisory model, parsing, merging, and evaluation

**Files:**
- Create: `internal/advisory/advisory.go` (types + YAML parsing + merge + built-in default)
- Create: `internal/advisory/default_advisories.yaml` (embedded with `//go:embed`; content = the YAML block in the spec, verbatim)
- Create: `internal/advisory/evaluate.go`
- Test: `internal/advisory/advisory_test.go`, `internal/advisory/evaluate_test.go`

**Interfaces:**
- Consumes: `Compare`, `Normalize`, `Series` from Task 2.
- Produces:
  - `type Match struct { Type string; Names []string; Distro string }`
  - `type Rule struct { Name string; Match Match; Normalize Normalizer; Series string; Compare Comparator; Floors map[string]string; MissingSeries string }` (`MissingSeries` is `fail` or `unknown`, default `unknown`).
  - `type Advisory struct { ID, Title, Reference, Severity, Category string; Disabled bool; Rules []Rule }`
  - `type Set struct { Advisories []Advisory }`
  - `func Parse(yamlBytes []byte) (*Set, error)` — validates: non-empty `id`, unique advisory ids, unique rule names within an advisory, non-empty `match.names` unless `disabled`, `compare` ∈ the four comparators, `normalize` ∈ `""|go|java`, `series` ∈ `none|distro|version:N`, `missingSeries` ∈ `fail|unknown`, severity ∈ `critical|high|medium|low|info`. A `disabled: true` entry may omit everything but `id`.
  - `func Merge(base, overlay *Set) *Set` — result keeps base order; an overlay advisory with a base id replaces it in place; `disabled: true` removes it; other overlay advisories are appended in overlay order.
  - `func Default() *Set` — parsed from the embedded file (panics only at init if the embedded file is invalid).
  - `type Package struct { Name, Version, Type string }`; `type Distro struct { ID, VersionID string }`; `type Input struct { Image string; Distro Distro; Packages []Package }`
  - `type Verdict string` with `VerdictPass = "pass"`, `VerdictFail = "fail"`, `VerdictUnknown = "unknown"`.
  - `type Result struct { AdvisoryID, Title, Reference, Severity, Category, Rule string; Verdict Verdict; Package Package; Series, Floor string; Message string }`
  - `func (s *Set) Evaluate(in Input) []Result` — deterministic order: advisories in set order, rules in rule order, packages in input order.

- [ ] **Step 1: Write the failing parse and merge tests**

```go
func TestParseDefault(t *testing.T) {
	s := Default()
	// assert len(s.Advisories) == 1, s.Advisories[0].ID == "emudhra-2026-10", len(Rules) == 11
	// assert the java-runtime rule has Match.Names == []string{"openjdk", "java"} and Normalize == NormalizeJava
}

func TestParseRejects(t *testing.T) {
	// each of these inputs returns an error mentioning the field:
	//  - rule with compare: "semver"
	//  - rule with normalize: "python"
	//  - rule with series: "version:x"
	//  - rule with empty names
	//  - two rules named "a" in one advisory
	//  - two advisories with id "a"
	//  - advisory with severity: "urgent"
	//  - invalid YAML "advisories: ["
}

func TestMerge(t *testing.T) {
	// base = Default(); overlay with {id: "test-1", one rule} → 2 advisories, order [emudhra-2026-10, test-1]
	// overlay with {id: "emudhra-2026-10", title: "replaced", rules: [one rule]} → 1 advisory, Title "replaced", 1 rule
	// overlay with {id: "emudhra-2026-10", disabled: true} → 0 advisories
	// overlay with {id: "nope", disabled: true} → base unchanged
}
```

- [ ] **Step 2: Write the failing evaluate tests (values from the graveler validation data (kept outside the repository, see the spec))**

```go
func evalOne(t *testing.T, distro Distro, p Package) Result  // helper: Default().Evaluate(Input{Image:"img", Distro: distro, Packages: []Package{p}}) must return exactly one Result

func TestEvaluateGraveler(t *testing.T) {
	cases := []struct{ d Distro; p Package; rule string; v Verdict; floor string }{
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
	// for each: r := evalOne(...); assert r.Rule, r.Verdict, r.Floor; assert r.Message != ""
}

func TestEvaluateNoMatch(t *testing.T) {
	// Input with Package{"redis", "7.2", "binary"} → len(results) == 0
}

func TestEvaluateUnparseableVersion(t *testing.T) {
	// Package{"node", "UNKNOWN", "binary"} → one Result, VerdictUnknown, Message == `node version "UNKNOWN" could not be parsed`
}

func TestEvaluateTwoAdvisoriesSamePackage(t *testing.T) {
	// a Set with two advisories each having a rule matching {type: python, names: [certifi]}
	// → two Results with different AdvisoryID, in advisory order
}

func TestEvaluateDistroRequired(t *testing.T) {
	// Package{"ca-certificates", "20250419", "deb"} with Distro{"ubuntu","24.04"} must NOT match os-ca-certificates-debian
}

func TestEvaluateNameCaseInsensitive(t *testing.T) {
	// Package{"Certifi", "2026.7.22", "python"} matches python-certifi
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/advisory/ -v`
Expected: FAIL, undefined `Default`, `Parse`, `Merge`, `Evaluate`.

- [ ] **Step 4: Implement `advisory.go` and `evaluate.go`**

Parsing with `sigs.k8s.io/yaml`. Evaluation algorithm per (rule, package): match → `Normalize` → `Series` → look up floor → `Compare`; a `Series` or `Compare` error yields `VerdictUnknown` with the unparseable message. Message formats, exactly:
- fail with floor: `%s %s is below the fixed version %s for %s (%s)` → package name, version, floor, series label (`<distro id> <versionID>` for `distro` series, otherwise `series <key>`), advisory title.
- fail without floor: `%s %s has no fixed release in its series %s; rebuild on a fixed series (%s)`.
- pass: `%s %s is at or above the fixed version %s (%s)`.
- unknown (missing series): `%s %s: no fixed version known for %s (%s)`.
- unknown (unparseable): `%s version %q could not be parsed`.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/advisory/ -v -cover`
Expected: PASS, coverage above 85% for the package.

- [ ] **Step 6: Commit**

```bash
git add internal/advisory
git commit -m "Add advisory model, parsing, merging and SBOM evaluation"
```

---

### Task 4: PolicyReport types, SBOM adapter, discovery gate, and the SBOMSyft controller

**Files:**
- Create: `api/wgpolicyk8s.io/v1alpha2/types.go`, `api/wgpolicyk8s.io/v1alpha2/groupversion_info.go`, `api/wgpolicyk8s.io/v1alpha2/zz_generated.deepcopy.go` (controller-gen)
- Create: `internal/controller/sbom_input.go`
- Create: `internal/controller/policyreport.go`
- Create: `internal/controller/sbomsyft_controller.go`
- Create: `internal/controller/discovery.go`
- Modify: `main.go` (scheme registration, informer wrapper, discovery gate, controller setup)
- Test: `internal/controller/sbom_input_test.go`, `internal/controller/policyreport_test.go`, `internal/controller/sbomsyft_controller_test.go`, `internal/controller/discovery_test.go`

**Interfaces:**
- Consumes: `advisory.Set`, `advisory.Input`, `advisory.Result` from Task 3.
- Produces:
  - Package `v1alpha2` with `PolicyReport`, `PolicyReportList`, `PolicyReportResult`, `PolicyReportSummary`, `PolicyResult` (string, constants `StatusPass="pass"`, `StatusFail="fail"`, `StatusWarn="warn"`, `StatusError="error"`, `StatusSkip="skip"`), `PolicySeverity`; JSON tags exactly as the CRD: `scope`, `summary`, `results`, and per result `source,policy,rule,category,severity,result,message,properties,timestamp,resources`; `GroupVersion = schema.GroupVersion{Group: "wgpolicyk8s.io", Version: "v1alpha2"}`, `AddToScheme`.
  - `func InputFromSBOM(s *kubescapev1beta1.SBOMSyft) advisory.Input` — `Image` from annotation `kubescape.io/image-tag`, falling back to `kubescape.io/image-id`, then `s.Name`; `Distro{ID, VersionID}` from `Spec.Syft.Distro`; one `Package{Name, Version, Type}` per artifact.
  - `func SBOMUnavailable(s *kubescapev1beta1.SBOMSyft) (status string, unavailable bool)` — true when annotation `kubescape.io/status` is present and not `ready`, or when `len(Spec.Syft.Artifacts) == 0`; `status` is the annotation value or `empty` when the annotation is missing.
  - `func BuildPolicyReport(s *kubescapev1beta1.SBOMSyft, results []advisory.Result, now metav1.Time) *v1alpha2.PolicyReport` — name and namespace of the SBOMSyft, owner reference to it (controller=true), label `app.kubernetes.io/managed-by=sbom-advisory-operator`, scope ObjectReference, results mapped (`unknown` → `warn`; `severity` set only on fail), `properties` keys `image,package,version,type,series,floor,distro,reference`, summary counts.
  - `func BuildUnavailablePolicyReport(s *kubescapev1beta1.SBOMSyft, status string, now metav1.Time) *v1alpha2.PolicyReport` — same metadata; one result `policy: sbom-advisory-operator`, `rule: sbom-unavailable`, `result: error`, `category: Trust Store`, `message: SBOM is not evaluable (status: <status>)`, `properties: {image, status}`; summary `{Error: 1}`.
  - `func WaitForKubescapeAPI(ctx context.Context, cfg *rest.Config, interval time.Duration, log logr.Logger) error` — polls discovery for group version `spdx.softwarecomposition.kubescape.io/v1beta1` with resource `sbomsyfts`; returns nil when found, `ctx.Err()` on cancellation; logs `kubescape storage API not found, retrying in 60s` on each miss.
  - `type SBOMSyftReconciler struct { client.Client; Reader client.Reader; Advisories func() *advisory.Set; Now func() metav1.Time }` with `Reconcile(ctx, req) (ctrl.Result, error)` and `SetupWithManager(mgr ctrl.Manager) error`.

- [ ] **Step 1: Write the failing adapter and builder tests**

```go
func TestInputFromSBOM(t *testing.T) {
	// SBOMSyft with annotation image-tag "gsoci.azurecr.io/giantswarm/app-operator:7.5.4", distro debian/13,
	// artifacts [{ca-certificates 20250419 deb}, {stdlib go1.26.6 go-module}]
	// → Input.Image == tag, Distro == {debian 13}, 2 packages in order
	// SBOMSyft with no annotations → Input.Image == s.Name
}

func TestSBOMUnavailable(t *testing.T) {
	// status "ready" + 3 artifacts → false
	// status "too-large" + 0 artifacts → ("too-large", true)
	// no status annotation + 0 artifacts → ("empty", true)
	// status "incomplete" + 3 artifacts → ("incomplete", true)
}

func TestBuildPolicyReport(t *testing.T) {
	// results: one fail (go-stdlib), one pass (certifi), one unknown (rpm)
	// assert: Name/Namespace == SBOMSyft's, OwnerReferences[0].UID == SBOMSyft UID and Controller == true,
	//   Labels["app.kubernetes.io/managed-by"] == "sbom-advisory-operator",
	//   Scope.Kind == "SBOMSyft", len(Results) == 3,
	//   Results[0].Result == StatusFail && Results[0].Severity == "high" && Results[0].Source == "sbom-advisory-operator",
	//   Results[1].Result == StatusPass && Results[1].Severity == "",
	//   Results[2].Result == StatusWarn,
	//   Summary == {Pass:1, Fail:1, Warn:1}, Results[0].Properties["floor"] == "1.26.10"
}

func TestBuildUnavailablePolicyReport(t *testing.T) {
	// status "too-large" → one result, Rule "sbom-unavailable", Result StatusError,
	//   Message "SBOM is not evaluable (status: too-large)", Summary == {Error: 1}
}
```

- [ ] **Step 2: Write the failing reconciler and discovery tests (controller-runtime fake client, fake discovery)**

```go
// scheme: clientgoscheme + kubescapev1beta1 + v1alpha2
func TestReconcileCreatesReport(t *testing.T) {
	// fake client seeded with an SBOMSyft (status ready, debian 13, ca-certificates 20250419); Reader = same fake client
	// Reconcile → PolicyReport exists with Summary.Fail == 1
}
func TestReconcileUpdatesReport(t *testing.T) {
	// seed SBOMSyft + stale PolicyReport with 5 results; Reconcile → report has exactly the new results
}
func TestReconcileDeletesReportWhenNoResults(t *testing.T) {
	// seed SBOMSyft with only {redis 7.2 binary} + existing PolicyReport → after Reconcile the report is gone
}
func TestReconcileUnavailableSBOM(t *testing.T) {
	// seed SBOMSyft with status "too-large" and empty spec → report exists with one error result
}
func TestReconcileDeletesReportWhenSBOMGone(t *testing.T) {
	// seed only a PolicyReport named like a missing SBOMSyft → Reconcile returns nil error and report is gone
}
func TestReconcileUsesReaderNotCache(t *testing.T) {
	// Reader = fake client holding the full SBOMSyft; Client = a different fake client holding the same name with empty Spec and status ready
	// Reconcile → report has evaluation results, not an sbom-unavailable error (proves the body came from Reader)
}
func TestWaitForKubescapeAPI(t *testing.T) {
	// fake discovery (k8s.io/client-go/discovery/fake) without the group: WaitForKubescapeAPI with a cancelled-after-2-polls context returns ctx.Err()
	// fake discovery with the group and resource sbomsyfts: returns nil immediately
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/controller/ ./api/... -v`
Expected: FAIL, undefined types and functions.

- [ ] **Step 4: Implement the v1alpha2 types and run controller-gen for deepcopy**

Add `// +kubebuilder:object:root=true` markers; `make generate` (or `controller-gen object paths=./api/...`). Do not generate CRD manifests; kyverno-crds owns the CRD.

- [ ] **Step 5: Implement `sbom_input.go`, `policyreport.go`, `discovery.go`, `sbomsyft_controller.go`**

Reconcile flow: `Reader.Get` SBOMSyft → NotFound ⇒ delete PolicyReport of same name if present, return → `SBOMUnavailable` ⇒ upsert `BuildUnavailablePolicyReport`, return → `InputFromSBOM` → `Advisories().Evaluate` → zero results ⇒ delete report if present → else `BuildPolicyReport` and create-or-update (get existing, copy `ResourceVersion`, update; create on NotFound). `WaitForKubescapeAPI` takes `discovery.DiscoveryInterface` internally so the fake can be injected (signature above wraps it; expose `waitForKubescapeAPIWith(ctx, discovery.DiscoveryInterface, interval, log)` for the test). `SetupWithManager`: `For(&kubescapev1beta1.SBOMSyft{}, builder.OnlyMetadata)`, `WithOptions(controller.Options{MaxConcurrentReconciles: 2})`, `Owns(&v1alpha2.PolicyReport{})`.

- [ ] **Step 6: Wire `main.go`**

Register the three schemes. Add the starboard-exporter `watchListSemanticsDisabledListerWatcherWrapper` (copy `main.go:68-74` of starboard-exporter) and the `cache.Options.NewInformer` hook applying it to `*metav1.PartialObjectMetadata` and `*kubescapev1beta1.SBOMSyft`. Start the manager's health probes first, then run `WaitForKubescapeAPI(ctx, cfg, 60*time.Second, setupLog)` in a goroutine that, on success, calls `SetupWithManager` and only then lets the manager add the controller; the manager itself starts immediately so `/healthz` answers while waiting. Construct `SBOMSyftReconciler{Client: mgr.GetClient(), Reader: mgr.GetAPIReader(), Advisories: advisory.Default (replaced in Task 5), Now: metav1.Now}`.

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test ./... -v`
Expected: PASS.

- [ ] **Step 8: Verify the watch against a real kubescape storage (graveler)**

Run, with the `teleport.giantswarm.io-graveler` context: `kubectl get --raw '/apis/spdx.softwarecomposition.kubescape.io/v1beta1/namespaces/kubescape/sbomsyfts?limit=1' -H 'Accept: application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1' | head -c 300`
Expected: a `PartialObjectMetadataList`. If the server returns a plain `SBOMSyftList` instead, switch `SetupWithManager` to a full-object `For` and wrap the manager cache with starboard-exporter's hydrating cache pattern with `needsHydration` returning false; the reconciler already reads through `Reader`.
Then run `go run . --leader-elect=false` locally against graveler for two minutes and check `kubectl get policyreports -n kubescape | wc -l` grows past 100. Stop the process and `kubectl delete policyreports -n kubescape -l app.kubernetes.io/managed-by=sbom-advisory-operator` to leave the cluster clean.

- [ ] **Step 9: Verify the discovery gate against a cluster without kubescape**

Run `go run . --leader-elect=false --health-probe-bind-address :18081` against a kind cluster or any context lacking the group for 90 seconds.
Expected: the log shows `kubescape storage API not found, retrying in 60s` at least once and `curl -s localhost:18081/healthz` returns `ok` meanwhile; no exit.

- [ ] **Step 10: Commit**

```bash
git add api internal/controller main.go go.mod go.sum
git commit -m "Add SBOMSyft controller writing PolicyReports"
```

---

### Task 5: ConfigMap-driven advisories with merge and re-evaluation

**Files:**
- Create: `internal/controller/advisory_source.go`
- Modify: `internal/controller/sbomsyft_controller.go` (`SetupWithManager` adds the ConfigMap watch)
- Modify: `main.go`
- Test: `internal/controller/advisory_source_test.go`

**Interfaces:**
- Consumes: `advisory.Parse`, `advisory.Merge`, `advisory.Default` (Task 3); `SBOMSyftReconciler` (Task 4).
- Produces:
  - `type AdvisorySource struct { Namespace, Name, Key string; ... }` with `func NewAdvisorySource(namespace, name, key string, recorder record.EventRecorder) *AdvisorySource`, `func (a *AdvisorySource) Current() *advisory.Set` (goroutine-safe; returns `advisory.Default()` until a ConfigMap has been loaded), `func (a *AdvisorySource) Load(cm *corev1.ConfigMap) error` (parse `cm.Data[Key]`, then `Merge(Default(), parsed)`; on parse error keep the previous set and emit Event reason `InvalidAdvisories` on the ConfigMap; on a missing key set `Default()`), `func (a *AdvisorySource) Reset()` (ConfigMap deleted ⇒ back to `Default()`).
  - Flags in `main.go`: `--advisories-configmap-namespace` (default: the pod namespace from `POD_NAMESPACE`), `--advisories-configmap-name` (default `sbom-advisory-operator-advisories`), `--advisories-configmap-key` (default `advisories.yaml`).

- [ ] **Step 1: Write the failing tests**

```go
func TestAdvisorySourceDefaultUntilLoaded(t *testing.T) {
	// NewAdvisorySource(...).Current().Advisories[0].ID == "emudhra-2026-10"
}
func TestAdvisorySourceLoadMergesOverDefault(t *testing.T) {
	// Load a ConfigMap whose advisories.yaml has one advisory id "test-1"
	// → Current() has 2 advisories: [emudhra-2026-10, test-1]
}
func TestAdvisorySourceLoadDisablesBuiltin(t *testing.T) {
	// Load {id: emudhra-2026-10, disabled: true} → Current() has 0 advisories
}
func TestAdvisorySourceKeepsLastGoodOnInvalid(t *testing.T) {
	// Load valid "test-1", then Load invalid YAML → error returned, Current() still [emudhra-2026-10, test-1],
	// fake recorder received an event with reason "InvalidAdvisories"
}
func TestAdvisorySourceMissingKeyFallsBackToDefault(t *testing.T) {}
func TestAdvisorySourceResetOnDelete(t *testing.T) {
	// Load "test-1", then Reset() → Current() == Default()
}
func TestConfigMapChangeEnqueuesAllSBOMs(t *testing.T) {
	// using the map function from SetupWithManager with a fake client holding 3 SBOMSyft metadata objects
	// → 3 reconcile.Requests, one per SBOMSyft; a ConfigMap with another name → 0 requests
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/controller/ -run 'AdvisorySource|ConfigMapChange' -v`
Expected: FAIL.

- [ ] **Step 3: Implement `advisory_source.go` and the watch**

`SetupWithManager` gains `Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(r.enqueueAllSBOMs), builder.WithPredicates(namespaceAndNamePredicate))`; `enqueueAllSBOMs` calls `Load` (or `Reset` when the object carries a deletion timestamp or is a delete event), then lists `metav1.PartialObjectMetadataList` with GVK SBOMSyft through the cached client and returns one request per item. Pass `Advisories: source.Current` to the reconciler in `main.go`. Use `mgr.GetEventRecorderFor("sbom-advisory-operator")`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/controller main.go
git commit -m "Load advisories from a ConfigMap, merge over built-ins and re-evaluate on change"
```

---

### Task 6: Helm chart, RBAC, and app-platform packaging

**Files:**
- Create: `helm/sbom-advisory-operator/Chart.yaml`, `values.yaml`, `values.schema.json`, `README.md.gotmpl`, `templates/_helpers.tpl`, `templates/_resource.tpl`, `templates/deployment.yaml`, `templates/serviceaccount.yaml`, `templates/rbac.yaml`, `templates/configmap.yaml`
- Test: `helm/sbom-advisory-operator` rendered with `helm template` and linted with the repo's pre-commit.

**Interfaces:**
- Consumes: the binary flags from Task 5.
- Produces: an installable chart; `values.yaml` keys `advisories` (list, default `[]`; rendered verbatim as `{advisories: <list>}` into the ConfigMap key `advisories.yaml`), `image.{registry,name,tag,pullPolicy}`, `resources` (requests = limits: cpu `100m`, memory `256Mi`), `podSecurityContext` and `containerSecurityContext` copied from policy-meta-operator.

- [ ] **Step 1: Copy the chart skeleton from policy-meta-operator and rename**

Chart.yaml: `name: sbom-advisory-operator`, `description: Evaluates kubescape SBOMs against package version floors and publishes PolicyReports`, annotations `io.giantswarm.application.team: shield`, `audience: giantswarm`, `managed: "true"`. Remove every edgedb reference from deployment and values.

- [ ] **Step 2: Write `rbac.yaml` and `configmap.yaml`**

ClusterRole rules: `spdx.softwarecomposition.kubescape.io/sbomsyfts` get,list,watch; `wgpolicyk8s.io/policyreports` get,list,watch,create,update,patch,delete; `""/events` create,patch; `coordination.k8s.io/leases` get,list,watch,create,update,patch,delete. Namespaced Role: `""/configmaps` get,list,watch. ConfigMap named `{{ include "resource.default.name" . }}-advisories` is always rendered, with `advisories.yaml: {{ dict "advisories" .Values.advisories | toYaml }}`.

- [ ] **Step 3: Deployment**

Args: `--leader-elect`, `--advisories-configmap-name={{ include "resource.default.name" . }}-advisories`; env `POD_NAMESPACE` from `fieldRef metadata.namespace`; ports 8080 metrics / 8081 probes; liveness and readiness on `/healthz` and `/readyz`.

- [ ] **Step 4: Verify rendering and schema**

Run: `helm template test helm/sbom-advisory-operator | kubectl apply --dry-run=client -f -`
Expected: every resource `created (dry run)`.
Run: `helm template test helm/sbom-advisory-operator --set-json 'advisories=[{"id":"x","title":"t","severity":"low","category":"c","rules":[]}]' | grep -A4 'advisories.yaml'`
Expected: the ConfigMap carries the rendered list.
Run: `uvx pre-commit run --all-files`
Expected: all hooks pass (regenerate `values.schema.json` with the repo's schema tooling if a hook asks).

- [ ] **Step 5: Commit**

```bash
git add helm
git commit -m "Add Helm chart for sbom-advisory-operator"
```

---

### Task 7: End-to-end validation on graveler and README

**Files:**
- Modify: `README.md` (what it does, the advisory YAML schema and merge rules, how to add an advisory through Helm values, how to read the reports, the `sbom-unavailable` result)
- Modify: `CHANGELOG.md` (Unreleased: initial MVP)

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Push and let CI build the image**

```bash
git push -u origin main
```
Wait for the architect pipeline to publish `gsoci.azurecr.io/giantswarm/sbom-advisory-operator:<sha>` and the chart to the test catalog the generated CI targets. Use `devctl pr wait` / `devctl release wait` per `gs-base:devctl-wait` if a PR flow is used instead of pushing `main`.

- [ ] **Step 2: Install on graveler**

Install the chart directly on the graveler MC into namespace `sbom-advisory-operator` with `helm upgrade --install --create-namespace` using the `teleport.giantswarm.io-graveler` context and the CI-built image tag. No App CR for the validation run; catalog installation is part of adding it to the security bundle later.

- [ ] **Step 3: Verify counts against the graveler validation data (kept outside the repository, see the spec)**

Run:
```bash
kubectl get policyreports -n kubescape -l app.kubernetes.io/managed-by=sbom-advisory-operator -o json | jq -r '[.items[].results[] | "\(.rule) \(.result)"] | group_by(.) | map("\(.[0]) \(length)") | .[]'
```
Expected (within drift of images that changed since): `go-stdlib fail ~178`, `go-stdlib pass ~28`, `python-certifi fail 7`, `python-certifi pass 3`, `node-runtime fail 5`, `java-runtime fail 1`, `os-ca-certificates-* fail ~138`, `warn 5`, `pass ~14`, `sbom-unavailable error 0`. Roughly 200 reports total.

- [ ] **Step 4: Verify the policy-reporter UI and the Helm-values round trip**

Port-forward the policy-reporter UI service in `kyverno` and confirm source `sbom-advisory-operator` lists results with their messages for a report scoped to an SBOMSyft. Record in the README whether the scope renders usefully; if not, note pod mapping as the next iteration. Then:

```bash
helm upgrade sbom-advisory-operator helm/sbom-advisory-operator -n sbom-advisory-operator --reuse-values --set-json 'advisories=[{"id":"certifi-test","title":"test","severity":"low","category":"Trust Store","rules":[{"name":"certifi","match":{"type":"python","names":["certifi"]},"series":"none","compare":"numeric","floors":{"*":"2099.1.1"}}]}]'
```
Expected within a minute: `certifi-test/certifi fail` count equals the number of certifi-bearing images (10) while `python-certifi` counts are unchanged. Revert with `--set-json 'advisories=[]'`.

- [ ] **Step 5: Write README and CHANGELOG, commit, and uninstall from graveler**

```bash
git add README.md CHANGELOG.md
git commit -m "Document sbom-advisory-operator MVP"
git push
helm uninstall sbom-advisory-operator -n sbom-advisory-operator --kube-context teleport.giantswarm.io-graveler
```
Leaving the PolicyReports in place is fine; they are owned by the SBOMSyfts and vanish with them. Delete them explicitly if the cluster should be left exactly as found.

---

## Self-review notes

- Spec coverage: goals map to Tasks 4 (read + report), 3 (default + merge), 5 (re-evaluation), 6 (packaging); anti-goals to the `Reader`/`OnlyMetadata` constraint, `BuildUnavailablePolicyReport`, and `WaitForKubescapeAPI` in Task 4; acceptance 1-5 to Tasks 2-3, 7, 7, 7 and 4 step 9.
- Type consistency: `advisory.Result.Verdict` values `pass|fail|unknown` are mapped to `v1alpha2` `StatusPass|StatusFail|StatusWarn` only in `BuildPolicyReport`; `StatusError` is produced only by `BuildUnavailablePolicyReport`; `Advisories func() *advisory.Set` is the single seam between Tasks 4 and 5; `Match.Names` is a list everywhere.
- Phase 2 items (pod mapping, trivy SBOMReport input, advisory CRD, large-cluster tuning) are intentionally absent.
