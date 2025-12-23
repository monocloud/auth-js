/* eslint-disable import/no-extraneous-dependencies */
import nock from 'nock';
import { vi, beforeEach, afterEach } from 'vitest';

beforeEach(() => {
  vi.spyOn(console, 'warn').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  nock.cleanAll();
  vi.clearAllMocks();
  vi.restoreAllMocks();
  vi.resetModules();
});
