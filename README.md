[![CircleCI](https://circleci.com/gh/giantswarm/sbom-advisory-operator.svg?style=shield)](https://circleci.com/gh/giantswarm/sbom-advisory-operator)

# sbom-advisory-operator

Evaluates the syft SBOMs that [kubescape](https://github.com/kubescape/kubescape) stores for every running
image against a list of *advisories* (package version floors) and publishes the verdicts as
`wgpolicyk8s.io/v1alpha2` PolicyReports, so they show up in policy-reporter and its metrics.

It exists for fixes that vulnerability scanners cannot see: a trust store or runtime that was updated
without a CVE. The built-in advisory covers the eMudhra intermediate CA compromise of October 2026.

## How it works

1. The operator watches `SBOMSyft` objects (`spdx.softwarecomposition.kubescape.io/v1beta1`) as metadata
   only, and fetches each body uncached when it reconciles. An SBOM body is held only for the duration
   of its reconcile, never in the cache.
2. Every advisory rule that matches a package in the SBOM yields one result: `pass`, `fail`, or `warn`
   (unknown: no fixed version is known for that distro or runtime series, or the version could not be
   parsed).
3. One PolicyReport per SBOMSyft is written next to it, owned by it, with `source:
   sbom-advisory-operator`. An SBOM whose body kubescape could not store (status `too-large`,
   `incomplete`, `failed`, `unsupported-schema`, or no artifacts) gets a single `error` result with rule
   `sbom-unavailable` so the image stays visible. An SBOM that matches no rule gets no report.
4. On clusters without kubescape the operator keeps its health probes up and looks for the API every
   minute instead of crashlooping.

In the policy-reporter UI the source appears as **Sbom-advisory-operator** with one namespace-scoped
resource of kind `SBOMSyft` per image under the `kubescape` namespace (verified on graveler, October
2026); the UI's workload mapping does not apply, so results are found by image name.

Read the reports:

```sh
kubectl get policyreports -n kubescape -l app.kubernetes.io/managed-by=sbom-advisory-operator
kubectl get policyreports -n kubescape -l app.kubernetes.io/managed-by=sbom-advisory-operator -o json \
  | jq -r '[.items[].results[] | "\(.rule) \(.result)"] | group_by(.) | map("\(.[0]) \(length)") | .[]'
```

## Metrics

The chart ships a ServiceMonitor that scrapes policy-reporter and keeps only
`policy_report_result{source="sbom-advisory-operator"}`, one series per result with the `policy`,
`rule`, `status`, `severity` and `category` labels and the SBOMSyft name in `name`. It carries
`observability.giantswarm.io/tenant: giantswarm_security_default`, so the series are written to the
security tenant of the management cluster that hosts the cluster: look in the **Giant Swarm
Security** Grafana organization there. They are not in the Giant Swarm or Shared organizations, not in
Grafana Cloud, and not readable through Muster's Prometheus tools, which query the default tenant.
The `policyReporterServiceMonitor` values override the target Service and the tenant; the object is
omitted on a cluster without the Prometheus Operator CRDs.

```promql
sum by (cluster_id, rule, status, severity) (policy_report_result{source="sbom-advisory-operator"})
```

From a management cluster without Grafana:

```sh
kubectl -n mimir port-forward svc/mimir-gateway 18080:80 &
curl -s -H 'X-Scope-OrgID: giantswarm_security_default' \
  http://localhost:18080/prometheus/api/v1/query \
  --data-urlencode 'query=sum by (cluster_id, rule, status) (policy_report_result{source="sbom-advisory-operator"})'
```

The operator's own controller-runtime metrics are scraped through the `sbom-advisory-operator`
Service into the default tenant (`serviceMonitor` values), so they appear in the Giant Swarm
organization and in Muster like any other platform component.

## Advisories

Advisories come from two layers merged by `id`: the built-in set embedded in the binary
([`internal/advisory/default_advisories.yaml`](internal/advisory/default_advisories.yaml)) and the
`advisories` Helm value, rendered into the ConfigMap `sbom-advisory-operator-advisories`. A value entry with the id of
a built-in advisory replaces it; `{id: <built-in id>, disabled: true}` removes it; other entries are
appended. Changing the ConfigMap re-evaluates every SBOM without a restart. Invalid YAML is rejected
with a `Warning` Event (`InvalidAdvisories`) on the ConfigMap and the previous set stays in effect.
Every floor must parse with its rule's comparator, or the whole set is rejected. Result timestamps
record the evaluation that last changed a report; an unchanged evaluation does not rewrite it.

```yaml
advisories:
  - id: my-incident-2026-11
    title: Example runtime fix without a CVE
    reference: https://example.com/advisory
    severity: high            # critical | high | medium | low | info, used on fail results
    category: Trust Store
    rules:
      - name: python-certifi
        match: {type: python, names: [certifi]}      # syft package type and names (case-insensitive)
        series: none                                 # none | distro | version:N
        compare: numeric                             # dpkg | apk | rpm | numeric
        floors: {"*": "2026.10.19"}
      - name: os-ca-certificates-debian
        match: {type: deb, names: [ca-certificates], distro: debian}
        series: distro                               # floors keyed by distro versionID
        compare: dpkg
        floors: {"12": "20250419~deb12u2", "13": "20250419+deb13u1"}
        missingSeries: unknown                       # fail | unknown (default) when the series has no floor
      - name: go-stdlib
        match: {type: go-module, names: [stdlib]}
        normalize: go                                # go | java: rewrite the version before comparing
        series: version:2                            # floors keyed by the first two numeric components
        compare: numeric
        floors: {"1.26": "1.26.10", "1.27": "1.27.3"}
        missingSeries: fail
```

Rule semantics:

- `series: none` uses the `"*"` floor; `series: distro` keys floors by the image's `Distro.VersionID`
  (falling back to its major component); `series: version:N` keys by the first N numeric components of
  the package version.
- A version below its floor is `fail`; at or above is `pass`; a series with no floor is `missingSeries`;
  a version with no digits is `warn`.
- `normalize: go` turns `go1.26.5-X:jsonv2` into `1.26.5`; `normalize: java` turns `25+36-LTS` into
  `25` and `1.8.0_412` into `8.0.412`.

## Installation

The chart lives at `helm/sbom-advisory-operator` and is published to the Giant Swarm catalog. It needs
the PolicyReport CRD, which kyverno-crds installs as part of the security bundle, and kubescape with
its vulnerability scanning enabled (the SBOMs come from kubescape's storage API).

```sh
helm upgrade --install sbom-advisory-operator helm/sbom-advisory-operator \
  --namespace sbom-advisory-operator --create-namespace
```

## Development

```sh
make test       # unit tests
make generate   # regenerate deepcopy code for api/
make build      # local binary
```

The design and the implementation plan, including the graveler validation data, are in
[`docs/superpowers`](docs/superpowers).
