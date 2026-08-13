/* eslint-disable import/no-extraneous-dependencies */
import { expect } from 'vitest';
import {
  MonoCloudHttpError,
  MonoCloudAuthBaseError,
  MonoCloudValidationError,
  MonoCloudTokenError,
  MonoCloudTokenErrorCode,
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

export const assertHttpError = async (
  promise: Promise<unknown>,
  error: string,
  status?: number,
  statusText?: string
): Promise<void> => {
  try {
    await promise;
    throw new Error();
  } catch (e) {
    expect(e).toBeInstanceOf(MonoCloudHttpError);
    expect((e as MonoCloudHttpError).message).toBe(error);
    expect((e as MonoCloudHttpError).status).toBe(status);
    expect((e as MonoCloudHttpError).statusText).toBe(statusText);
  }
};

export const assertTokenError = async (
  promise: Promise<unknown>,
  error: string,
  code: MonoCloudTokenErrorCode = 'invalid_token'
): Promise<void> => {
  try {
    await promise;
    throw new Error();
  } catch (e) {
    expect(e).toBeInstanceOf(MonoCloudTokenError);
    expect((e as MonoCloudTokenError).message).toBe(error);
    expect((e as MonoCloudTokenError).code).toBe(code);
  }
};
