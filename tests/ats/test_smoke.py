"""ATS smoke for the sbom-advisory-operator chart.

app-test-suite (ATS >= 1.0) installs the packaged chart on the job's kind
cluster with `helm upgrade --install --wait` (the namespace from
.ats/main.yaml) and runs this file with `pytest -m smoke`: the generated
execute-chart-tests job of every branch build.

The kind cluster has no kubescape, so the operator must come up anyway: it
keeps its health probes serving and polls discovery for the kubescape storage
API instead of crashlooping. The Deployment being ready is therefore the
cluster-level proof of that behaviour.
"""

import pykube
import pytest
from pytest_helm_charts.clusters import Cluster
from pytest_helm_charts.k8s.deployment import wait_for_deployments_to_run

DEPLOYMENT_NAME = "sbom-advisory-operator"
DEPLOYMENT_NAMESPACE = "default"


@pytest.mark.smoke
def test_api_working(kube_cluster: Cluster) -> None:
    """The kind cluster ATS runs against is reachable."""
    assert kube_cluster.kube_client is not None
    assert len(pykube.Node.objects(kube_cluster.kube_client)) >= 1


@pytest.mark.smoke
def test_operator_runs_without_kubescape(kube_cluster: Cluster) -> None:
    """The operator Deployment is ready on a cluster without the kubescape storage API."""
    deployments = wait_for_deployments_to_run(
        kube_cluster.kube_client, [DEPLOYMENT_NAME], DEPLOYMENT_NAMESPACE, timeout_sec=180
    )
    assert len(deployments) == 1
    assert deployments[0].obj["status"].get("readyReplicas", 0) == 1
