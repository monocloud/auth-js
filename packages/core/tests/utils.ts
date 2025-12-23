/* eslint-disable import/no-extraneous-dependencies */
import { expect } from 'vitest';
import {
  MonoCloudHttpError,
  MonoCloudAuthBaseError,
  MonoCloudValidationError,
  MonoCloudTokenError,
  MonoCloudOPError,
} from '../src';

export const assertError = async (
  promise: Promise<unknown>,
  errorClass:
    | typeof MonoCloudHttpError
    | typeof MonoCloudAuthBaseError
    | typeof MonoCloudValidationError
    | typeof MonoCloudTokenError
    | typeof MonoCloudOPError,
  error: string,
  errorDescription?: string
): Promise<void> => {
  try {
    await promise;
    throw new Error();
  } catch (e) {
    expect(e).toBeInstanceOf(errorClass);
    expect((e as any).message).toBe(error);
    if (errorClass === MonoCloudOPError) {
      expect((e as any).error).toBe(error);
      expect((e as any).errorDescription).toBe(errorDescription);
    }
  }
};
