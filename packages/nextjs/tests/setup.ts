/* eslint-disable import/no-extraneous-dependencies */
import { afterEach, beforeEach, vi } from 'vitest';
import nock from 'nock';
import { deleteDefaultConfig, setupDefaultConfig } from './common-helper';

Object.assign(global, {
  SDK_NAME: 'monocloud',
  SDK_VERSION: '1.0.0',
  SDK_DEBUGGER_NAME: 'monocloud',
});

beforeEach(() => {
  vi.spyOn(console, 'warn').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(() => {});
  setupDefaultConfig();
});

afterEach(() => {
  nock.cleanAll();
  deleteDefaultConfig();
  vi.clearAllMocks();
  vi.restoreAllMocks();
  vi.resetModules();
});
