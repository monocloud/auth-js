---
'@monocloud/backend-node': patch
---

- Restore the `delete(key: string): Promise<void>` method on the `IIntrospectionCache` interface, removed in 0.3.4. Custom cache adapters must implement `delete` again — options validation enforces it at client construction. Adapters that kept their `delete` method are unaffected.
