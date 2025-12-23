/* eslint-disable import/no-extraneous-dependencies */
import { expect, it } from 'vitest';
import { MonoCloudNextClient } from '../src';

it('should registed public env variables to the env', () => {
  process.env.NEXT_PUBLIC_MONOCLOUD_AUTH_TEST_KEY = 'Hi how are you';

  new MonoCloudNextClient();

  expect(process.env.MONOCLOUD_AUTH_TEST_KEY).toBe('Hi how are you');
});
