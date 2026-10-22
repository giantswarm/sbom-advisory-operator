# sbom-advisory-operator

Please add description

**Homepage:** <https://github.com/giantswarm/sbom-advisory-operator>

## Source Code

* <https://github.com/some-org/some-repo>

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| image.name | string | `"giantswarm/sbom-advisory-operator"` |  |
| image.tag | string | `""` |  |
| registry.domain | string | `"gsoci.azurecr.io"` |  |

## CI values

`ci/ci-values.yaml` holds the values the CI render (`helm template` in app-build-suite) needs beyond the defaults, such as a `required` value without a default.
