/* eslint-disable import/no-extraneous-dependencies */
import { afterEach, vi } from 'vitest';
import { cleanup } from '@testing-library/react';

const { MockMonoCloudWebJSClient } = vi.hoisted(() => ({
  MockMonoCloudWebJSClient: function mockClient(options: unknown): unknown {
    (globalThis as Record<string, unknown>).mcMockClientOptions = options;
    return (globalThis as Record<string, unknown>).mcMockClient;
  },
}));

vi.mock('@monocloud/auth-web-js', async importOriginal => {
  const actual =
    await importOriginal<typeof import('@monocloud/auth-web-js')>();

  return {
    ...actual,
    MonoCloudWebJSClient: MockMonoCloudWebJSClient,
  };
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  (globalThis as Record<string, unknown>).mcMockClient = undefined;
  (globalThis as Record<string, unknown>).mcMockClientOptions = undefined;
});
