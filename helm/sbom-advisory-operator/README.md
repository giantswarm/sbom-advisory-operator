# sbom-advisory-operator

Evaluates kubescape SBOMs against package version floors and publishes PolicyReports

**Homepage:** <https://github.com/giantswarm/sbom-advisory-operator>

## Source Code

* <https://github.com/giantswarm/sbom-advisory-operator>

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| image.name | string | `"giantswarm/sbom-advisory-operator"` |  |
| image.tag | string | `""` |  |
| image.pullPolicy | string | `"IfNotPresent"` |  |
| registry.domain | string | `"gsoci.azurecr.io"` |  |
| replicas | int | `1` |  |
| ciliumNetworkPolicy.enabled | bool | `true` |  |
| advisories | list | `[]` |  |
| kubescapeDiscoveryInterval | string | `"60s"` |  |
| resources.requests.cpu | string | `"100m"` |  |
| resources.requests.memory | string | `"256Mi"` |  |
| resources.limits.cpu | string | `"100m"` |  |
| resources.limits.memory | string | `"256Mi"` |  |
| podSecurityContext.runAsUser | int | `65532` |  |
| podSecurityContext.runAsGroup | int | `65532` |  |
| podSecurityContext.runAsNonRoot | bool | `true` |  |
| podSecurityContext.seccompProfile.type | string | `"RuntimeDefault"` |  |
| containerSecurityContext.allowPrivilegeEscalation | bool | `false` |  |
| containerSecurityContext.capabilities.drop[0] | string | `"ALL"` |  |
| containerSecurityContext.privileged | bool | `false` |  |
| containerSecurityContext.readOnlyRootFilesystem | bool | `true` |  |
| containerSecurityContext.runAsNonRoot | bool | `true` |  |
| containerSecurityContext.seccompProfile.type | string | `"RuntimeDefault"` |  |
| nodeSelector | object | `{}` |  |
| tolerations | list | `[]` |  |
| policyReporterServiceMonitor.enabled | bool | `true` | Create the ServiceMonitor. |
| policyReporterServiceMonitor.tenant | string | `"giantswarm_security_default"` | Observability tenant the findings are written to (label observability.giantswarm.io/tenant). |
| policyReporterServiceMonitor.namespace | string | `"kyverno"` | Namespace of the policy-reporter Service. |
| policyReporterServiceMonitor.serviceSelector | object | `{"app.kubernetes.io/instance":"kyverno","app.kubernetes.io/name":"policy-reporter"}` | Labels selecting the policy-reporter Service. |
| policyReporterServiceMonitor.port | string | `"http"` | Named Service port that serves /metrics. |
| policyReporterServiceMonitor.interval | duration | `"60s"` | Scrape interval. |
| policyReporterServiceMonitor.scrapeTimeout | duration | `"45s"` | Scrape timeout. |

## CI values

`ci/ci-values.yaml` holds the values the CI render (`helm template` in app-build-suite) needs beyond the defaults, such as a `required` value without a default.
