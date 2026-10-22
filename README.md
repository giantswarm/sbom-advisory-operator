[![CircleCI](https://circleci.com/gh/giantswarm/sbom-advisory-operator.svg?style=shield)](https://circleci.com/gh/giantswarm/sbom-advisory-operator)

# sbom-advisory-operator

Evaluates the syft SBOMs that [kubescape](https://github.com/kubescape/kubescape) stores for every running
image against a list of *advisories* (package version floors) and publishes the verdicts as
`wgpolicyk8s.io/v1alpha2` PolicyReports, so they show up in policy-reporter and its metrics.

It exists for fixes that vulnerability scanners cannot see: a trust store or runtime that was updated
without a CVE. The built-in advisory covers the eMudhra intermediate CA compromise of October 2026.

## How it works

1. The operator watches `SBOMSyft` objects (`spdx.softwarecomposition.kubescape.io/v1beta1`) as metadata
   only, and fetches each body uncached when it reconciles. SBOM bodies are never held in memory.
2. Every advisory rule that matches a package in the SBOM yields one result: `pass`, `fail`, or `warn`
   (unknown: no fixed version is known for that distro or runtime series, or the version could not be
   parsed).
3. One PolicyReport per SBOMSyft is written next to it, owned by it, with `source:
   sbom-advisory-operator`. An SBOM whose body kubescape could not store (status `too-large`,
   `incomplete`, `failed`, `unsupported-schema`, or no artifacts) gets a single `error` result with rule
   `sbom-unavailable` so the image stays visible. An SBOM that matches no rule gets no report.
4. On clusters without kubescape the operator keeps its health probes up and looks for the API every
   minute instead of crashlooping.

Read the reports:

```sh
kubectl get policyreports -n kubescape -l app.kubernetes.io/managed-by=sbom-advisory-operator
kubectl get policyreports -n kubescape -l app.kubernetes.io/managed-by=sbom-advisory-operator -o json \
  | jq -r '[.items[].results[] | "\(.rule) \(.result)"] | group_by(.) | map("\(.[0]) \(length)") | .[]'
```

## Advisories

Advisories come from two layers merged by `id`: the built-in set embedded in the binary
([`internal/advisory/default_advisories.yaml`](internal/advisory/default_advisories.yaml)) and the
`advisories` Helm value, rendered into the ConfigMap `<release>-advisories`. A value entry with the id of
a built-in advisory replaces it; `{id: <built-in id>, disabled: true}` removes it; other entries are
appended. Changing the ConfigMap re-evaluates every SBOM without a restart. Invalid YAML is rejected
with a `Warning` Event (`InvalidAdvisories`) on the ConfigMap and the previous set stays in effect.

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
