---
'@monocloud/auth-node-core': patch
---

- Add `groupsClaim` to `MonoCloudOptionsBase`, `DEFAULT_OPTIONS`,
  `get-options` (env resolution), and the options validation schema;
  `MonoCloudCoreClient.isUserInGroup()` now defaults to the configured claim.
