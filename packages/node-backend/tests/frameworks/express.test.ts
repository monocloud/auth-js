/* eslint-disable import/no-extraneous-dependencies */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MonoCloudTokenError } from '@monocloud/auth-core';
import type { NextFunction, Request, Response } from 'express';
import {
  createMockNext,
  createMockRequest,
  createMockResponse,
  MockHttpResponse,
} from '@monocloud/auth-test-utils';
import { protectApi } from '../../src/frameworks/express/express';
import { MonoCloudBackendNodeClient } from '../../src/monocloud-backend-node-client';
import { AuthenticatedExpressRequest } from '../../src/frameworks/express/types';
import {
  baseOptions,
  clearEnvs,
  mockValidateAccessToken,
  mockValidateAccessTokenRejection,
  setRequiredEnv,
  validClaims,
} from './helpers';

type ResMock = Response & MockHttpResponse;

describe('protectApi (express)', () => {
  beforeEach(() => {
    setRequiredEnv();
  });

  afterEach(() => {
    clearEnvs();
  });

  it('should create an internal client from environment variables when no client is provided', async () => {
    const validateSpy = mockValidateAccessToken();

    const middleware = protectApi()();
    const req = createMockRequest<AuthenticatedExpressRequest>({
      headers: { authorization: 'Bearer some-token' },
    });
    const res = createMockResponse<ResMock>();
    const next = createMockNext<NextFunction>();

    await middleware(req, res, next);

    expect(validateSpy).toHaveBeenCalledWith('some-token', expect.any(Object));
    expect(next).toHaveBeenCalledTimes(1);
    expect(res.status).not.toHaveBeenCalled();
    expect(req.claims).toEqual(validClaims);
  });

  it('should use the provided client when passed as first argument', async () => {
    const client = new MonoCloudBackendNodeClient(baseOptions);
    const validateSpy = vi
      .spyOn(client, 'validateAccessToken')
      .mockResolvedValue(validClaims);

    const middleware = protectApi(client)();
    const req = createMockRequest<Request>({
      headers: { authorization: 'Bearer token-123' },
    });
    const res = createMockResponse<ResMock>();
    const next = createMockNext<NextFunction>();

    await middleware(req, res, next);

    expect(validateSpy).toHaveBeenCalledWith('token-123', expect.any(Object));
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('should return 401 when no token is provided', async () => {
    const middleware = protectApi()();
    const req = createMockRequest<AuthenticatedExpressRequest>();
    const res = createMockResponse<ResMock>();
    const next = createMockNext<NextFunction>();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ message: 'unauthorized' });
    expect(next).not.toHaveBeenCalled();
    expect(req.claims).toBeUndefined();
  });

  it('should use the provided tokenResolver first', async () => {
    const tokenResolver = vi.fn().mockResolvedValue('resolver-token');
    const validateSpy = mockValidateAccessToken();

    const middleware = protectApi({ tokenResolver })();
    const req = createMockRequest<Request>({
      headers: { authorization: 'Bearer header-token' },
    });
    const res = createMockResponse<ResMock>();
    const next = createMockNext<NextFunction>();

    await middleware(req, res, next);

    expect(tokenResolver).toHaveBeenCalledWith(req);
    expect(validateSpy).toHaveBeenCalledWith(
      'resolver-token',
      expect.any(Object)
    );
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('should fall back to the Authorization header when tokenResolver returns undefined', async () => {
    const tokenResolver = vi.fn().mockResolvedValue(undefined);
    const validateSpy = mockValidateAccessToken();

    const middleware = protectApi({ tokenResolver })();
    const req = createMockRequest<Request>({
      headers: { authorization: 'Bearer header-token' },
    });
    const res = createMockResponse<ResMock>();
    const next = createMockNext<NextFunction>();

    await middleware(req, res, next);

    expect(validateSpy).toHaveBeenCalledWith(
      'header-token',
      expect.any(Object)
    );
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('should return 401 when the tokenResolver rejects', async () => {
    const tokenResolver = vi.fn().mockRejectedValue(new Error('boom'));

    const middleware = protectApi({ tokenResolver })();
    const req = createMockRequest<AuthenticatedExpressRequest>({
      headers: { authorization: 'Bearer header-token' },
    });
    const res = createMockResponse<ResMock>();
    const next = createMockNext<NextFunction>();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ message: 'unauthorized' });
    expect(next).not.toHaveBeenCalled();
    expect(req.claims).toBeUndefined();
  });

  it('should resolve the client certificate when validateCertificateBinding is true', async () => {
    const certificateResolver = vi.fn().mockResolvedValue('cert-value');
    const validateSpy = mockValidateAccessToken();

    const middleware = protectApi({ certificateResolver })({
      validateCertificateBinding: true,
    });
    const req = createMockRequest<Request>({
      headers: { authorization: 'Bearer some-token' },
    });
    const res = createMockResponse<ResMock>();
    const next = createMockNext<NextFunction>();

    await middleware(req, res, next);

    expect(certificateResolver).toHaveBeenCalledWith(req);
    expect(validateSpy).toHaveBeenCalledWith('some-token', {
      clientCertificate: 'cert-value',
      validateCertificateBinding: true,
      groups: undefined,
      scopes: undefined,
    });
  });

  it('should not call the certificate resolver when validateCertificateBinding is falsy', async () => {
    const certificateResolver = vi.fn();
    mockValidateAccessToken();

    const middleware = protectApi({ certificateResolver })();
    const req = createMockRequest<Request>({
      headers: { authorization: 'Bearer some-token' },
    });
    const res = createMockResponse<ResMock>();
    const next = createMockNext<NextFunction>();

    await middleware(req, res, next);

    expect(certificateResolver).not.toHaveBeenCalled();
  });

  it('should use the provided client and request options together', async () => {
    const client = new MonoCloudBackendNodeClient(baseOptions);
    const tokenResolver = vi.fn().mockResolvedValue('injected');
    const certificateResolver = vi.fn().mockResolvedValue('cert');
    const validateSpy = vi
      .spyOn(client, 'validateAccessToken')
      .mockResolvedValue(validClaims);

    const middleware = protectApi(client, {
      tokenResolver,
      certificateResolver,
    })({ validateCertificateBinding: true });

    const req = createMockRequest<Request>();
    const res = createMockResponse<ResMock>();
    const next = createMockNext<NextFunction>();

    await middleware(req, res, next);

    expect(tokenResolver).toHaveBeenCalled();
    expect(certificateResolver).toHaveBeenCalled();
    expect(validateSpy).toHaveBeenCalledWith('injected', {
      clientCertificate: 'cert',
      validateCertificateBinding: true,
      groups: undefined,
      scopes: undefined,
    });
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('should forward scopes and groups from validateOptions', async () => {
    const validateSpy = mockValidateAccessToken();

    const middleware = protectApi()({
      scopes: ['read'],
      groups: ['admin'],
    });
    const req = createMockRequest<Request>({
      headers: { authorization: 'Bearer t' },
    });
    const res = createMockResponse<ResMock>();
    const next = createMockNext<NextFunction>();

    await middleware(req, res, next);

    expect(validateSpy).toHaveBeenCalledWith('t', {
      clientCertificate: undefined,
      validateCertificateBinding: undefined,
      groups: ['admin'],
      scopes: ['read'],
    });
  });

  it('should return 401 when validation throws a generic error', async () => {
    mockValidateAccessTokenRejection(new Error('boom'));

    const middleware = protectApi()();
    const req = createMockRequest<AuthenticatedExpressRequest>({
      headers: { authorization: 'Bearer t' },
    });
    const res = createMockResponse<ResMock>();
    const next = createMockNext<NextFunction>();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ message: 'unauthorized' });
    expect(next).not.toHaveBeenCalled();
    expect(req.claims).toBeUndefined();
  });

  it('should return 403 when token is missing required scopes', async () => {
    mockValidateAccessTokenRejection(
      new MonoCloudTokenError('Token is missing required scopes')
    );

    const middleware = protectApi()();
    const req = createMockRequest<AuthenticatedExpressRequest>({
      headers: { authorization: 'Bearer t' },
    });
    const res = createMockResponse<ResMock>();
    const next = createMockNext<NextFunction>();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ message: 'forbidden' });
    expect(req.claims).toBeUndefined();
  });

  it('should return 403 when token is missing required groups', async () => {
    mockValidateAccessTokenRejection(
      new MonoCloudTokenError('Token is missing required groups')
    );

    const middleware = protectApi()();
    const req = createMockRequest<AuthenticatedExpressRequest>({
      headers: { authorization: 'Bearer t' },
    });
    const res = createMockResponse<ResMock>();
    const next = createMockNext<NextFunction>();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ message: 'forbidden' });
    expect(req.claims).toBeUndefined();
  });

  it('should return 401 on MonoCloudTokenError with a different message', async () => {
    mockValidateAccessTokenRejection(new MonoCloudTokenError('Invalid Issuer'));

    const middleware = protectApi()();
    const req = createMockRequest<AuthenticatedExpressRequest>({
      headers: { authorization: 'Bearer t' },
    });
    const res = createMockResponse<ResMock>();
    const next = createMockNext<NextFunction>();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ message: 'unauthorized' });
    expect(req.claims).toBeUndefined();
  });
});
