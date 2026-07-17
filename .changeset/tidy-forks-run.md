---
'@monocloud/auth-core': minor
'@monocloud/backend-node': minor
---

Add SPIFFE client authentication methods `spiffe_jwt` and `spiffe_x509` to `clientAuthMethod`.

- `spiffe_x509` authenticates via mutual TLS using an X.509-SVID (presented at the TLS transport layer, the same as `tls_client_auth`).
- `spiffe_jwt` sends a SPIFFE JWT-SVID (obtained from the SPIFFE Workload API and provided as the `clientSecret` string) as the `client_assertion`, with `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-spiffe`.
