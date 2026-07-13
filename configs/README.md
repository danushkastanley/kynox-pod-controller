# Monitoring examples

These Helm values are starting points for a private monitoring stack. Review
them against the exact chart version and storage, identity, retention, and
network requirements of your cluster before deployment.

## Files

- `prometheus-values.yaml` scrapes the controller's `/metrics` endpoint and
  Kubernetes targets. Its service is cluster-internal and the admin API is off.
- `grafana-values.yaml` expects an existing `grafana-admin-credentials` Secret
  with `admin-user` and `admin-password` keys. It does not install plugins.
- `fluent-bit-values.yaml` expects TLS-enabled Elasticsearch plus a
  `fluent-bit-elasticsearch-credentials` Secret containing
  `ELASTICSEARCH_USER` and `ELASTICSEARCH_PASSWORD`.
- `fluent-bit-values-opensearch.yaml` expects TLS-enabled OpenSearch plus a
  `fluent-bit-opensearch-credentials` Secret containing `OPENSEARCH_USER` and
  `OPENSEARCH_PASSWORD`.

Do not commit generated values containing credentials. Prefer your platform's
external secret manager and restrict who can read monitoring data; security
event logs can contain sensitive process, path, network, and workload metadata.

## Before installation

1. Pin the Helm chart and container image versions or digests.
2. Replace service names, namespaces, and endpoints for your cluster.
3. Create the referenced Secrets outside Git.
4. Configure persistent storage and a retention period.
5. Apply least-privilege service accounts and NetworkPolicies.
6. Validate with `helm template` and a policy scanner before applying.

The bundled resource limits are conservative examples, not capacity guidance.
