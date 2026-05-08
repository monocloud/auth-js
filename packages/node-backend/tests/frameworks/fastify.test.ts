/* eslint-disable import/no-extraneous-dependencies */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MonoCloudTokenError } from '@monocloud/auth-core';
import type { FastifyReply, FastifyRequest } from 'fastify';
import {
  createMockRequest,
  createMockResponse,
  MockHttpResponse,
} from '@monocloud/auth-test-utils';
import { protectApi } from '../../src/frameworks/fastify/fastify';
import { MonoCloudBackendNodeClient } from '../../src/monocloud-backend-node-client';
import { AuthenticatedFastifyRequest } from '../../src/frameworks/fastify/types';
import {
  baseOptions,
  clearEnvs,
  mockValidateAccessToken,
  mockValidateAccessTokenRejection,
  setRequiredEnv,
  validClaims,
} from './helpers';

type ReplyMock = FastifyReply & MockHttpResponse;

describe('protectApi (fastify)', () => {
  beforeEach(() => {
    setRequiredEnv();
  });

  afterEach(() => {
    clearEnvs();
  });

  it('should create an internal client from environment variables when no client is provided', async () => {
    const validateSpy = mockValidateAccessToken();

    const hook = protectApi()();
    const req = createMockRequest<AuthenticatedFastifyRequest>({
      headers: { authorization: 'Bearer some-token' },
    });
    const reply = createMockResponse<ReplyMock>();

    await hook(req, reply);

    expect(validateSpy).toHaveBeenCalledWith('some-token', expect.any(Object));
    expect(reply.status).not.toHaveBeenCalled();
    expect(req.claims).toEqual(validClaims);
  });

  it('should use the provided client when passed as first argument', async () => {
    const client = new MonoCloudBackendNodeClient(baseOptions);
    const validateSpy = vi
      .spyOn(client, 'validateAccessToken')
      .mockResolvedValue(validClaims);

    const hook = protectApi(client)();
    const req = createMockRequest<FastifyRequest>({
      headers: { authorization: 'Bearer token-123' },
    });
    const reply = createMockResponse<ReplyMock>();

    await hook(req, reply);

    expect(validateSpy).toHaveBeenCalledWith('token-123', expect.any(Object));
  });

  it('should return 401 when no token is provided', async () => {
    const hook = protectApi()();
    const req = createMockRequest<FastifyRequest>();
    const reply = createMockResponse<ReplyMock>();

    await hook(req, reply);

    expect(reply.status).toHaveBeenCalledWith(401);
    expect(reply.send).toHaveBeenCalledWith({ message: 'unauthorized' });
  });

  it('should use the provided tokenResolver first', async () => {
    const tokenResolver = vi.fn().mockResolvedValue('resolver-token');
    const validateSpy = mockValidateAccessToken();

    const hook = protectApi({ tokenResolver })();
    const req = createMockRequest<FastifyRequest>({
      headers: { authorization: 'Bearer header-token' },
    });
    const reply = createMockResponse<ReplyMock>();

    await hook(req, reply);

    expect(tokenResolver).toHaveBeenCalledWith(req);
    expect(validateSpy).toHaveBeenCalledWith(
      'resolver-token',
      expect.any(Object)
    );
  });

  it('should fall back to the Authorization header when tokenResolver returns undefined', async () => {
    const tokenResolver = vi.fn().mockResolvedValue(undefined);
    const validateSpy = mockValidateAccessToken();

    const hook = protectApi({ tokenResolver })();
    const req = createMockRequest<FastifyRequest>({
      headers: { authorization: 'Bearer header-token' },
    });
    const reply = createMockResponse<ReplyMock>();

    await hook(req, reply);

    expect(validateSpy).toHaveBeenCalledWith(
      'header-token',
      expect.any(Object)
    );
  });

  it('should return 401 when the tokenResolver rejects', async () => {
    const tokenResolver = vi.fn().mockRejectedValue(new Error('boom'));

    const hook = protectApi({ tokenResolver })();
    const req = createMockRequest<FastifyRequest>({
      headers: { authorization: 'Bearer header-token' },
    });
    const reply = createMockResponse<ReplyMock>();

    await hook(req, reply);

    expect(reply.status).toHaveBeenCalledWith(401);
    expect(reply.send).toHaveBeenCalledWith({ message: 'unauthorized' });
  });

  it('should resolve the client certificate when validateCertificateBinding is true', async () => {
    const certificateResolver = vi.fn().mockResolvedValue('cert-value');
    const validateSpy = mockValidateAccessToken();

    const hook = protectApi({ certificateResolver })({
      validateCertificateBinding: true,
    });
    const req = createMockRequest<FastifyRequest>({
      headers: { authorization: 'Bearer some-token' },
    });
    const reply = createMockResponse<ReplyMock>();

    await hook(req, reply);

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

    const hook = protectApi({ certificateResolver })();
    const req = createMockRequest<FastifyRequest>({
      headers: { authorization: 'Bearer some-token' },
    });
    const reply = createMockResponse<ReplyMock>();

    await hook(req, reply);

    expect(certificateResolver).not.toHaveBeenCalled();
  });

  it('should use the provided client and request options together', async () => {
    const client = new MonoCloudBackendNodeClient(baseOptions);
    const tokenResolver = vi.fn().mockResolvedValue('injected');
    const certificateResolver = vi.fn().mockResolvedValue('cert');
    const validateSpy = vi
      .spyOn(client, 'validateAccessToken')
      .mockResolvedValue(validClaims);

    const hook = protectApi(client, {
      tokenResolver,
      certificateResolver,
    })({ validateCertificateBinding: true });

    const req = createMockRequest<FastifyRequest>();
    const reply = createMockResponse<ReplyMock>();

    await hook(req, reply);

    expect(tokenResolver).toHaveBeenCalled();
    expect(certificateResolver).toHaveBeenCalled();
    expect(validateSpy).toHaveBeenCalledWith('injected', {
      clientCertificate: 'cert',
      validateCertificateBinding: true,
      groups: undefined,
      scopes: undefined,
    });
  });

  it('should forward scopes and groups from validateOptions', async () => {
    const validateSpy = mockValidateAccessToken();

    const hook = protectApi()({
      scopes: ['read'],
      groups: ['admin'],
    });
    const req = createMockRequest<FastifyRequest>({
      headers: { authorization: 'Bearer t' },
    });
    const reply = createMockResponse<ReplyMock>();

    await hook(req, reply);

    expect(validateSpy).toHaveBeenCalledWith('t', {
      clientCertificate: undefined,
      validateCertificateBinding: undefined,
      groups: ['admin'],
      scopes: ['read'],
    });
  });

  it('should return 401 when validation throws a generic error', async () => {
    mockValidateAccessTokenRejection(new Error('boom'));

    const hook = protectApi()();
    const req = createMockRequest<FastifyRequest>({
      headers: { authorization: 'Bearer t' },
    });
    const reply = createMockResponse<ReplyMock>();

    await hook(req, reply);

    expect(reply.status).toHaveBeenCalledWith(401);
    expect(reply.send).toHaveBeenCalledWith({ message: 'unauthorized' });
  });

  it('should return 403 when token is missing required scopes', async () => {
    mockValidateAccessTokenRejection(
      new MonoCloudTokenError('Token is missing required scopes')
    );

    const hook = protectApi()();
    const req = createMockRequest<FastifyRequest>({
      headers: { authorization: 'Bearer t' },
    });
    const reply = createMockResponse<ReplyMock>();

    await hook(req, reply);

    expect(reply.status).toHaveBeenCalledWith(403);
    expect(reply.send).toHaveBeenCalledWith({ message: 'forbidden' });
  });

  it('should return 403 when token is missing required groups', async () => {
    mockValidateAccessTokenRejection(
      new MonoCloudTokenError('Token is missing required groups')
    );

    const hook = protectApi()();
    const req = createMockRequest<FastifyRequest>({
      headers: { authorization: 'Bearer t' },
    });
    const reply = createMockResponse<ReplyMock>();

    await hook(req, reply);

    expect(reply.status).toHaveBeenCalledWith(403);
    expect(reply.send).toHaveBeenCalledWith({ message: 'forbidden' });
  });

  it('should return 401 on MonoCloudTokenError with a different message', async () => {
    mockValidateAccessTokenRejection(new MonoCloudTokenError('Invalid Issuer'));

    const hook = protectApi()();
    const req = createMockRequest<FastifyRequest>({
      headers: { authorization: 'Bearer t' },
    });
    const reply = createMockResponse<ReplyMock>();

    await hook(req, reply);

    expect(reply.status).toHaveBeenCalledWith(401);
    expect(reply.send).toHaveBeenCalledWith({ message: 'unauthorized' });
  });
});
