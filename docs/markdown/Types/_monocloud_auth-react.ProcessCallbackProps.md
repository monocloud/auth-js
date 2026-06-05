---
rootSdk: React
title: "ProcessCallbackProps"
category: Types
description: "Props for the <ProcessCallback /> component."
---

# Type: ProcessCallbackProps

Props for the `<ProcessCallback />` component.

## Properties

| Property                          | Type                                               | Description                                                          |
| --------------------------------- | -------------------------------------------------- | -------------------------------------------------------------------- |
| `children?` | `ReactNode`                                        | Content rendered after the callback has been processed successfully. |
| `error?`       | `ReactNode` \| ((`error`: `Error`) => `ReactNode`) | Content rendered when callback processing fails.                     |
| `loading?`   | `ReactNode`                                        | Content rendered while the callback is being processed.              |
