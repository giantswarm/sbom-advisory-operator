# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).



## [Unreleased]

### Added

- Initial MVP: evaluate kubescape `SBOMSyft` objects against advisories (package version floors) and publish one `wgpolicyk8s.io/v1alpha2` PolicyReport per SBOM, with the eMudhra intermediate CA compromise (October 2026) as the built-in advisory.
- Advisories are merged from the built-in set and the `advisories` Helm value (ConfigMap); changes re-evaluate every SBOM.
- SBOMs kubescape could not store in full get a single `error` result (`sbom-unavailable`); clusters without kubescape are tolerated with a discovery retry loop.



[Unreleased]: https://github.com/giantswarm/sbom-advisory-operator/tree/main
