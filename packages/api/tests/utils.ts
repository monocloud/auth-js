/* eslint-disable import/no-extraneous-dependencies */
import { expect } from 'vitest';
import {
  MonoCloudApiHttpError,
  MonoCloudApiError,
  MonoCloudApiValidationError,
  MonoCloudApiTokenError,
  MonoCloudApiOPError,
} from '../src';

export const assertError = async (
  promise: Promise<unknown>,
  errorClass:
    | typeof MonoCloudApiHttpError
    | typeof MonoCloudApiError
    | typeof MonoCloudApiValidationError
    | typeof MonoCloudApiTokenError
    | typeof MonoCloudApiOPError,
  error: string,
  errorDescription?: string
): Promise<void> => {
  try {
    await promise;
    throw new Error();
  } catch (e) {
    expect(e).toBeInstanceOf(errorClass);
    expect((e as any).message).toBe(error);
    if (errorClass === MonoCloudApiOPError) {
      expect((e as any).error).toBe(error);
      expect((e as any).errorDescription).toBe(errorDescription);
    }
  }
};

export const defaultOptions = {
  clientSecret: 'secret',
  audience: 'https://api.example.com',
};
