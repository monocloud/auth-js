---
'@monocloud/auth-core': patch
---

- `validateCertificateBinding` on the token validation options is now the exported `CertificateBindingValidation` union instead of a boolean; `true` becomes `'required'`.
