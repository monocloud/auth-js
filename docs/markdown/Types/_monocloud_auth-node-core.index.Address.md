---
rootSdk: Node.js Core
title: "Address"
category: Types
description: "Represents a postal address as defined by the OpenID Connect standard address claim."
---

# Type: Address

Represents a postal address as defined by the OpenID Connect standard `address` claim.

## Indexable

> \[`key`: `string`\]: `unknown`

Additional provider-specific address fields.

## Properties

| Property                                      | Type     | Description                                                                                                        |
| --------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------ |
| `country?`               | `string` | Country name or ISO country code.                                                                                  |
| `formatted?`           | `string` | Full mailing address formatted for display or mailing labels.                                                      |
| `locality?`             | `string` | City or locality component.                                                                                        |
| `postal_code?`       | `string` | Postal or ZIP code.                                                                                                |
| `region?`                 | `string` | State, province, or region component.                                                                              |
| `street_address?` | `string` | Full street address component, which may include house number, street name, apartment, suite, or unit information. |
