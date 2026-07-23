---
'@monocloud/backend-node': patch
---

Remove the `delete` method from the `IIntrospectionCache` interface. The introspection cache is only ever read from (`get`) and written to (`set`) — the SDK never called `delete` — so requiring implementers to provide it (and enforcing it in options validation) served no purpose. Custom cache adapters no longer need a `delete` method; adapters that still implement one remain compatible.
