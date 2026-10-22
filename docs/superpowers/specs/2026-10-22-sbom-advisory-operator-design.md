# sbom-advisory-operator — design (MVP)

Date: 2026-10-22. Author: Zach (Giant Swarm, team Shield) with Claude. Status: draft for approval.
Revision 2: incorporates the builder check (reference data, unavailable SBOMs, ConfigMap merge semantics,
policy-reporter ingestion, kubescape-absent clusters).

## Intent

When a trust-store or runtime fix ships without a CVE (the eMudhra intermediate CA compromise of
October 2026 is the trigger), vulnerability scanners stay silent. Kubescape already stores a syft SBOM for
every running image. A small operator can compare those SBOMs against a hand-maintained table of
"package X must be at least version Y" rules and publish the verdicts as PolicyReports, so the findings
show up in the policy-reporter UI, its metrics and the Muster policy-reporter tools that customers and
Giant Swarm already use.

The logic was validated by hand on 2026-10-22 against 200 SBOMSyft objects on the graveler management
cluster with a Python script. This operator ports that script to Go and runs it continuously.

## Reference data (in `reference/` next to this document)

- `emudhra_sbom_check.py` — the validated Python logic.
- `sboms.jsonl` — one line per graveler image: `{name, image, distro{id,versionID,prettyName}, nart,
  pkgs[{name,version,type}]}` with only the packages the rules care about.
- `check.txt` — the per-image verdicts (`VERDICT component version image [note]`) and totals.

Raw version shapes observed there, which the normalisers must handle:

| Package (syft type) | Version strings seen |
|---|---|
| `stdlib` (`go-module`) | `go1.27.3`, `go1.26.6`, `go1.26.5-X:jsonv2` (GOEXPERIMENT suffix) |
| `node` (`binary`) | `24.21.0`, `16.7.0` |
| `openjdk` (`binary`) | `25+36-LTS` (syft names the JDK binary `openjdk`, not `java`) |
| `certifi` (`python`) | `2026.10.19`, `2023.7.22` |
| `ca-certificates` (`deb`) | `20250419`, `20250419+deb13u1`, `20250419~deb12u1`, `20250419~deb12u1~deb11u1`, `20260601~24.04.1` |
| `ca-certificates` (`apk`) | `20250911-r0`, `20261020-r0`, `20260909-r2` |
| `ca-certificates` (`rpm`) | `2025.2.76-1.0.amzn2023.0.3` |
| other `binary` artifacts | version `UNKNOWN` (upper case) is common, for example `cli`, `gui`, `pagent` |

No dpkg epoch (`1:`) was seen; the comparator must still accept one.

## Goals

- Read every `SBOMSyft` (`spdx.softwarecomposition.kubescape.io/v1beta1`) in the cluster and evaluate it
  against a configurable list of advisories.
- Write one `PolicyReport` (`wgpolicyk8s.io/v1alpha2`) per SBOMSyft with one result per matched rule.
- Ship the eMudhra advisory as the built-in default so the operator is useful with zero configuration,
  and keep it active when a customer adds their own advisories.
- Re-evaluate every SBOM when the advisory ConfigMap changes.
- Package as a Giant Swarm app (Helm chart, catalog, generated CI), team Shield, so it can be added to
  the security bundle later.

## Non-goals (MVP)

- Mapping images to Pods or Deployments and writing reports into workload namespaces. Reports live next
  to the SBOMSyft in the kubescape namespace, scoped to the SBOMSyft. Pod mapping is phase 2, and becomes
  the fix if the policy-reporter UI turns out not to display non-workload scopes (checked in acceptance 3).
- Trivy-operator SBOMReport as a second input. Phase 2; the evaluation package is input-agnostic.
- A CRD for advisories. A ConfigMap is enough for an MVP; promote to a CRD once the schema settles.
- Content checks of trust bundles (fingerprint scans of mounted ConfigMaps or Secrets). Out of scope.
- Custom Prometheus metrics. policy-reporter already exports PolicyReport metrics.
- Sizing for large workload clusters with thousands of SBOMs. The MVP targets management clusters and
  small workload clusters (up to roughly 500 SBOMs); concurrency and rate limits are fixed, not tuned.

## Anti-goals

- Crashing or ballooning memory because SBOMSyft objects are up to 3 MB each. The operator must never
  cache SBOM bodies.
- Silently reporting "ok", or reporting nothing, for an image whose SBOM could not be evaluated, or for
  a distro or runtime series the advisory does not cover. Unknown must be visible, not green or absent.
- Crashlooping on a cluster where kubescape is not installed.

## Constraints and facts the builder must respect

- kubescape storage is an aggregated API server, not CRDs. `list` returns objects with an empty `spec`;
  only `get` returns the body. It does not support WatchList streaming (kubescape/storage#320).
  starboard-exporter works around both; see its `main.go:68-74` (ListerWatcher wrapper that reports
  WatchList as unsupported) and `utils/hydrating_cache.go`.
- kubescape storage can also store an SBOM as metadata only, by construction: oversize SBOMs get an
  empty `spec` and the annotation `kubescape.io/status: too-large`; other values are `incomplete`,
  `unsupported-schema`, `failed`; healthy objects carry `ready` (all 204 on graveler on 2026-10-22).
- Go module for the types: `github.com/kubescape/storage` (starboard-exporter pins v0.0.348). Types:
  `v1beta1.SBOMSyft{Spec.Syft: SyftDocument{Artifacts []SyftPackage, Distro LinuxRelease}}`;
  `SyftPackage.PackageBasicData{Name, Version, Type}`; `LinuxRelease{ID, VersionID}`.
- Annotations on SBOMSyft: `kubescape.io/image-tag`, `kubescape.io/image-id`, `kubescape.io/status`.
- Syft package `type` values seen: `deb`, `apk`, `rpm`, `python`, `go-module` (name `stdlib`), `binary`
  (names `node`, `openjdk`, `python`), `php-composer`, `rust-crate`.
- PolicyReport CRD: `wgpolicyk8s.io/v1alpha2` is installed by kyverno-crds (part of the security bundle).
  openreports.io is not installed. Field names per CRD: `scope`, `summary{pass,fail,warn,error,skip}`,
  `results[]{source,policy,rule,category,severity,result,message,properties,timestamp,resources}`;
  `result` enum pass/fail/warn/error/skip; `severity` enum critical/high/medium/low/info.
- Go types for PolicyReport: no maintained upstream module with the right import path exists; define a
  minimal copy of the v1alpha2 types in-repo (`api/wgpolicyk8s.io/v1alpha2`), ~100 lines, attributed.
- The policy-reporter shipped by kyverno-app on Giant Swarm clusters has no `sourceFilters` or namespace
  filters configured, so a new `source` is ingested without configuration changes. Whether its UI renders
  a `scope` of kind `SBOMSyft` usefully is unverified and is checked in acceptance 3.
- Version comparison must be distro-aware: `20250419~deb12u1 < 20250419~deb12u2 < 20250419 <
  20250419+deb13u1` under dpkg rules. Use the libraries Trivy uses: `github.com/knqyf263/go-deb-version`,
  `github.com/knqyf263/go-apk-version`, `github.com/knqyf263/go-rpm-version`; plain numeric-tuple
  comparison for everything else.
- Normalisers: `go` strips a leading `go` and anything from the first `-` (`go1.26.5-X:jsonv2` →
  `1.26.5`); `java` drops the build number after `+` and anything after `-`, and maps `1.8.0_N` to
  `8.0.N` (`25+36-LTS` → `25`, `17.0.21+9` → `17.0.21`).
- Conventions: mirror `giantswarm/policy-meta-operator` (go 1.26, controller-runtime 0.24.x, kubebuilder
  layout with `main.go` + `internal/controller`, Helm chart under `helm/<name>` with team-shield
  annotations, distroless image, `.abs/main.yaml`, generated CircleCI). Go style per `gs-godev:go-conventions`.
  Repository is created through `devctl repo create` (needs a devctl newer than 7.23.2) per
  `gs-base:repository-creation`.

## Advisory configuration

Advisories come from two layers that are merged by advisory `id`:

1. The built-in default set embedded in the binary (below).
2. The ConfigMap `<release>-advisories` in the operator namespace, key `advisories.yaml`, rendered by the
   Helm chart from the `advisories` value (a list, default empty). The chart always renders the
   ConfigMap, so GitOps or the App CR user values own it; nobody edits it by hand on managed clusters.

Merge rule: ConfigMap advisories are appended to the built-in set; a ConfigMap advisory whose `id`
matches a built-in one replaces it entirely; a ConfigMap entry `{id: <built-in id>, disabled: true}`
removes it. Built-in advisories therefore stay active until explicitly overridden or disabled.

```yaml
advisories:
  - id: emudhra-2026-10
    title: eMudhra intermediate CA compromise (October 2026)
    reference: https://emudhra.we-have-a-problem.com/
    severity: high                      # PolicyReport severity for fail results
    category: Trust Store
    rules:
      - name: os-ca-certificates-debian
        match: {type: deb, names: [ca-certificates], distro: debian}
        series: distro                  # key floors by distro versionID
        compare: dpkg
        floors: {"12": "20250419~deb12u2", "13": "20250419+deb13u1"}
        missingSeries: unknown          # versionID not in floors -> warn "unknown"
      - name: os-ca-certificates-ubuntu
        match: {type: deb, names: [ca-certificates], distro: ubuntu}
        series: distro
        compare: dpkg
        floors: {"22.04": "20260816ubuntu0.22.04.1", "24.04": "20260816ubuntu0.24.04.1",
                 "26.04": "20260816ubuntu0.26.04.1", "26.10": "20260816ubuntu0.26.10.1"}
        missingSeries: unknown
      - name: os-ca-certificates-alpine
        match: {type: apk, names: [ca-certificates, ca-certificates-bundle], distro: alpine}
        series: none                    # one floor for all
        compare: apk
        floors: {"*": "20261020-r0"}
      - name: os-ca-certificates-wolfi
        match: {type: apk, names: [ca-certificates, ca-certificates-bundle], distro: wolfi}
        series: none
        compare: apk
        floors: {"*": "20260909-r3"}
      - name: os-ca-certificates-rpm
        match: {type: rpm, names: [ca-certificates]}
        series: distro
        compare: rpm
        floors: {}                      # Red Hat CVE-2026-114406 / RHSB-2026-012: no fixed build yet
        missingSeries: unknown
      - name: python-certifi
        match: {type: python, names: [certifi]}
        series: none
        compare: numeric
        floors: {"*": "2026.10.19"}
      - name: go-stdlib
        match: {type: go-module, names: [stdlib]}
        normalize: go
        series: version:2               # key floors by major.minor of the normalised version
        compare: numeric
        floors: {"1.26": "1.26.10", "1.27": "1.27.3"}
        missingSeries: fail             # older minors have no fixed release
      - name: node-runtime
        match: {type: binary, names: [node]}
        series: version:1
        compare: numeric
        floors: {"22": "22.23.4", "24": "24.22.1", "26": "26.12.1"}
        missingSeries: fail
      - name: java-runtime
        match: {type: binary, names: [openjdk, java]}
        normalize: java
        series: version:1
        compare: numeric
        floors: {"8": "8.0.511", "11": "11.0.33", "17": "17.0.21", "21": "21.0.13", "25": "25.0.5", "27": "27.0.1"}
        missingSeries: unknown
      - name: composer-ca-bundle
        match: {type: php-composer, names: [composer/ca-bundle]}
        series: version:2
        compare: numeric
        floors: {"1.4": "1.4.16", "1.6": "1.6.0"}
        missingSeries: fail
      - name: rust-webpki-roots
        match: {type: rust-crate, names: [webpki-roots]}
        series: none
        compare: numeric
        floors: {"*": "1.0.10"}
```

Semantics:

- `match.type` is exact; `match.names` is a list matched case-insensitively against the package name;
  `match.distro` (optional) matches `Distro.ID`.
- `normalize` (optional, `go` or `java`) rewrites the package version before series and comparison.
- `series: distro` keys `floors` by `Distro.VersionID`, falling back to its major component.
  `series: version:N` keys by the first N numeric components of the (normalised) package version.
  `series: none` uses the `"*"` floor.
- Verdict per matched package: version below floor → `fail`; at or above → `pass`; series not in
  `floors` → `missingSeries` (`fail` or `unknown`); a version that cannot be parsed → `unknown`.
  `unknown` is written as PolicyReport `warn`.
- A rule that matches nothing in an SBOM produces no result. An SBOM whose body is present and complete
  but matches no rule produces no PolicyReport (and an existing one is deleted).

## PolicyReport output

One `PolicyReport` per SBOMSyft, same namespace, same name, owner reference to the SBOMSyft, label
`app.kubernetes.io/managed-by: sbom-advisory-operator`.

- `scope`: ObjectReference to the SBOMSyft (apiVersion, kind, name, namespace, uid).
- `results[]`: `source: sbom-advisory-operator`, `policy: <advisory id>`, `rule: <rule name>`,
  `category: <advisory category>`, `severity: <advisory severity>` (only on fail), `result:
  pass|fail|warn`, `message` such as `ca-certificates 20250419 is below the fixed version
  20250419+deb13u1 for debian 13 (eMudhra intermediate CA compromise (October 2026))`, `timestamp` =
  evaluation time, `properties: {image, package, version, type, series, floor, distro, reference}`.
- Unavailable SBOM: when `kubescape.io/status` is present and not `ready`, or the body has zero
  artifacts, the report has exactly one result: `policy: sbom-advisory-operator`, `rule:
  sbom-unavailable`, `result: error`, `category: Trust Store`, `message: SBOM is not evaluable (status:
  too-large)`, `properties: {image, status}`. This keeps the image visible in the compliance view.
- `summary`: counts of pass/fail/warn/error/skip over results.

## Controller behaviour

- At start, check discovery for `spdx.softwarecomposition.kubescape.io/v1beta1`. If absent, log
  `kubescape storage API not found, retrying in 60s`, keep the health and readiness probes serving, and
  retry; set up the controller only once the group exists. Never exit on absence.
- Watch SBOMSyft metadata only (`builder.OnlyMetadata`); on reconcile, `Get` the full object through
  the manager's API reader (never the cache), evaluate, write the PolicyReport with create-or-update,
  and drop the body. `MaxConcurrentReconciles: 2`.
- Register the WatchList-unsupported ListerWatcher wrapper for SBOMSyft, copied from starboard-exporter,
  until kubescape/storage#320 is fixed. If `OnlyMetadata` turns out unsupported by the aggregated server
  (checked in plan Task 4), fall back to a full-object informer with the same hydrating-cache pattern
  starboard-exporter uses, but with `needsHydration` always false, since the reconciler re-reads anyway.
- Watch the advisory ConfigMap; on change, re-parse, merge over the built-in set, and enqueue every
  SBOMSyft (metadata list) through the controller's default rate limiter.
- Advisory parse failures: log, keep the last good merged set, surface via a `Warning` Event with reason
  `InvalidAdvisories` on the ConfigMap.
- RBAC: `spdx.softwarecomposition.kubescape.io` sbomsyfts get/list/watch; `wgpolicyk8s.io` policyreports
  get/list/watch/create/update/patch/delete; `events` create/patch; `coordination.k8s.io` leases for
  leader election; namespaced Role for configmaps get/list/watch.

## Acceptance (MVP done when)

1. `go test ./...` passes with the version-comparison cases taken from `reference/check.txt`.
2. Deployed on graveler (kubescape present), `kubectl get policyreports -n kubescape -l
   app.kubernetes.io/managed-by=sbom-advisory-operator` returns roughly 200 reports and the totals match
   `reference/check.txt` within the drift of images that changed since: go-stdlib fail ≈178, certifi
   fail 7, node fail 5, java fail 1, os-ca-certificates fail ≈138 / warn (unknown) 5 / pass ≈14.
3. The policy-reporter UI lists source `sbom-advisory-operator` and shows per-result messages for a
   report scoped to an SBOMSyft. If the UI cannot display that scope, record it as the reason to pull pod
   mapping into the next iteration; it does not block the MVP merge.
4. Changing the `advisories` Helm value (for example adding an advisory that raises the certifi floor)
   changes the reports without a restart, and the built-in eMudhra results are still present.
5. Starting the operator against a kubeconfig whose cluster lacks kubescape logs the retry message and
   keeps `/healthz` returning `ok`.

## Left to the builder

- Exact Go package layout inside `internal/` beyond what the plan names.
- Whether to use server-side apply or get-then-update for the PolicyReport; both are acceptable.
- Log wording, Event reasons beyond `InvalidAdvisories`, and the jitter on requeue.
