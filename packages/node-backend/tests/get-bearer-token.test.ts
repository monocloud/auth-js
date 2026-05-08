/* eslint-disable import/no-extraneous-dependencies */
import { describe, expect, it } from 'vitest';
import { getBearerToken } from '../src/get-bearer-token';

describe('getBearerToken', () => {
  it('should return undefined when authorization header is not provided', () => {
    expect(getBearerToken()).toBeUndefined();
  });

  it('should return undefined when authorization header is empty', () => {
    expect(getBearerToken('')).toBeUndefined();
  });

  it('should return the access token when the scheme is Bearer', () => {
    expect(getBearerToken('Bearer some-token')).toBe('some-token');
  });

  it('should be case-insensitive for the Bearer scheme', () => {
    expect(getBearerToken('bearer some-token')).toBe('some-token');
    expect(getBearerToken('BEARER some-token')).toBe('some-token');
    expect(getBearerToken('BeArEr some-token')).toBe('some-token');
  });

  it('should trim leading and trailing whitespace', () => {
    expect(getBearerToken('   Bearer some-token   ')).toBe('some-token');
  });

  it('should split on multiple whitespace characters', () => {
    expect(getBearerToken('Bearer\tsome-token')).toBe('some-token');
    expect(getBearerToken('Bearer   some-token')).toBe('some-token');
  });

  it('should return undefined if the scheme is not Bearer', () => {
    expect(getBearerToken('Basic some-token')).toBeUndefined();
  });

  it('should return undefined if the access token is missing', () => {
    expect(getBearerToken('Bearer')).toBeUndefined();
    expect(getBearerToken('Bearer    ')).toBeUndefined();
  });

  it('should return undefined if there are extra tokens after the access token', () => {
    expect(getBearerToken('Bearer some-token extra')).toBeUndefined();
  });
});
