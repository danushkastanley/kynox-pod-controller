# Deployment secrets

The manifests reference three mutual-TLS Secrets:

- `rasp-mtls-ca` with key `ca.crt`
- `rasp-controller-tls` with keys `tls.crt` and `tls.key`
- `rasp-agent-tls` with keys `tls.crt` and `tls.key`

Generate a dedicated private CA and short-lived workload certificates outside
Git. The controller certificate must cover the service DNS name and the client
certificate must be authorised for the agents you deploy. Create or synchronise
the Secrets through your cluster's secret manager; never paste private keys into
repository files.

The controller also reads optional alert credentials and the required classifier
administration token from `rasp-controller-secrets`. If that Secret or
`CLASSIFIER_ADMIN_TOKEN` is absent, the classifier mutation endpoints fail
closed.
