# Security policy

## Supported versions

Security fixes are provided for the latest tagged release and the default branch.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository. Do not
open a public issue or include secrets, certificates, cluster identifiers, logs
containing personal data, or working exploit details in a public discussion.

Include the affected version, impact, reproduction steps, and any suggested
mitigation. You should receive an acknowledgement within five working days.

## Deployment boundary

The controller is security-sensitive infrastructure. Mutual TLS is enabled by
default. Keep its gRPC, metrics, and classifier endpoints on trusted networks,
store alert credentials in Kubernetes Secrets, and use an immutable image tag or
digest. Plaintext gRPC is intended only for isolated local development.
