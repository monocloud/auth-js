/* eslint-disable import/no-extraneous-dependencies */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  MonoCloudHttpError,
  MonoCloudOPError,
  MonoCloudTokenError,
  MonoCloudValidationError,
} from '@monocloud/auth-core';
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

  it('should return 401 with a bearer challenge when no token is provided', async () => {
    const hook = protectApi()();
    const req = createMockRequest<FastifyRequest>();
    const reply = createMockResponse<ReplyMock>();

    await hook(req, reply);

    expect(reply.status).toHaveBeenCalledWith(401);
    expect(reply.header).toHaveBeenCalledWith('WWW-Authenticate', 'Bearer');
    expect(reply.send).toHaveBeenCalledWith({ message: 'unauthorized' });
  });

  it('should return 401 when the tokenResolver returns a whitespace-only token', async () => {
    const tokenResolver = vi.fn().mockResolvedValue('   ');
    const validateSpy = mockValidateAccessToken();

    const hook = protectApi({ tokenResolver })();
    const req = createMockRequest<FastifyRequest>();
    const reply = createMockResponse<ReplyMock>();

    await hook(req, reply);

    expect(reply.status).toHaveBeenCalledWith(401);
    expect(reply.header).toHaveBeenCalledWith('WWW-Authenticate', 'Bearer');
    expect(validateSpy).not.toHaveBeenCalled();
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

  it('should return 401 with an invalid_token challenge when validation throws a generic error', async () => {
    mockValidateAccessTokenRejection(new Error('boom'));

    const hook = protectApi()();
    const req = createMockRequest<FastifyRequest>({
      headers: { authorization: 'Bearer t' },
    });
    const reply = createMockResponse<ReplyMock>();

    await hook(req, reply);

    expect(reply.status).toHaveBeenCalledWith(401);
    expect(reply.header).toHaveBeenCalledWith(
      'WWW-Authenticate',
      'Bearer error="invalid_token"'
    );
    expect(reply.send).toHaveBeenCalledWith({ message: 'unauthorized' });
  });

  it('should return 403 when token is missing required scopes', async () => {
    mockValidateAccessTokenRejection(
      new MonoCloudTokenError(
        'Token is missing required scopes',
        'insufficient_scope'
      )
    );

    const hook = protectApi()();
    const req = createMockRequest<FastifyRequest>({
      headers: { authorization: 'Bearer t' },
    });
    const reply = createMockResponse<ReplyMock>();

    await hook(req, reply);

    expect(reply.status).toHaveBeenCalledWith(403);
    expect(reply.header).toHaveBeenCalledWith(
      'WWW-Authenticate',
      'Bearer error="insufficient_scope"'
    );
    expect(reply.send).toHaveBeenCalledWith({ message: 'forbidden' });
  });

  it('should return 403 when token is missing required groups', async () => {
    mockValidateAccessTokenRejection(
      new MonoCloudTokenError(
        'Token is missing required groups',
        'insufficient_groups'
      )
    );

    const hook = protectApi()();
    const req = createMockRequest<FastifyRequest>({
      headers: { authorization: 'Bearer t' },
    });
    const reply = createMockResponse<ReplyMock>();

    await hook(req, reply);

    expect(reply.status).toHaveBeenCalledWith(403);
    expect(reply.header).toHaveBeenCalledWith(
      'WWW-Authenticate',
      'Bearer error="insufficient_scope"'
    );
    expect(reply.send).toHaveBeenCalledWith({ message: 'forbidden' });
  });

  it.each(['insufficient_scope', 'insufficient_groups'] as const)(
    'should return 403 based on the %s code even when the message differs',
    async code => {
      mockValidateAccessTokenRejection(
        new MonoCloudTokenError('Some reworded message', code)
      );

      const hook = protectApi()();
      const req = createMockRequest<FastifyRequest>({
        headers: { authorization: 'Bearer t' },
      });
      const reply = createMockResponse<ReplyMock>();

      await hook(req, reply);

      expect(reply.status).toHaveBeenCalledWith(403);
      expect(reply.header).toHaveBeenCalledWith(
        'WWW-Authenticate',
        'Bearer error="insufficient_scope"'
      );
      expect(reply.send).toHaveBeenCalledWith({ message: 'forbidden' });
    }
  );

  it('should trim the token returned by the tokenResolver', async () => {
    const tokenResolver = vi.fn().mockResolvedValue('  padded-token  ');
    const validateSpy = mockValidateAccessToken();

    const hook = protectApi({ tokenResolver })();
    const req = createMockRequest<FastifyRequest>();
    const reply = createMockResponse<ReplyMock>();

    await hook(req, reply);

    expect(validateSpy).toHaveBeenCalledWith(
      'padded-token',
      expect.any(Object)
    );
    expect(reply.status).not.toHaveBeenCalled();
  });

  it('should return 401 on MonoCloudTokenError with an invalid_token code', async () => {
    mockValidateAccessTokenRejection(new MonoCloudTokenError('Invalid Issuer'));

    const hook = protectApi()();
    const req = createMockRequest<FastifyRequest>({
      headers: { authorization: 'Bearer t' },
    });
    const reply = createMockResponse<ReplyMock>();

    await hook(req, reply);

    expect(reply.status).toHaveBeenCalledWith(401);
    expect(reply.header).toHaveBeenCalledWith(
      'WWW-Authenticate',
      'Bearer error="invalid_token"'
    );
    expect(reply.send).toHaveBeenCalledWith({ message: 'unauthorized' });
  });

  it.each([
    ['network failure', new MonoCloudHttpError('fetch failed')],
    ['a 500 from the server', new MonoCloudHttpError('boom', 500)],
    ['a 502 from the server', new MonoCloudHttpError('boom', 502)],
    ['a 429 from the server', new MonoCloudHttpError('boom', 429)],
  ])(
    'should return 503 without a challenge on a transient failure (%s)',
    async (_, error) => {
      mockValidateAccessTokenRejection(error);

      const hook = protectApi()();
      const req = createMockRequest<FastifyRequest>({
        headers: { authorization: 'Bearer t' },
      });
      const reply = createMockResponse<ReplyMock>();

      await hook(req, reply);

      expect(reply.status).toHaveBeenCalledWith(503);
      expect(reply.header).not.toHaveBeenCalled();
      expect(reply.send).toHaveBeenCalledWith({
        message: 'service unavailable',
      });
    }
  );

  it.each([
    ['a 404 from the server', new MonoCloudHttpError('boom', 404)],
    [
      'rejected client credentials',
      new MonoCloudOPError('invalid_client', 'Client authentication failed'),
    ],
    [
      'missing configuration',
      new MonoCloudValidationError(
        'introspection_endpoint is required but not available in the issuer metadata'
      ),
    ],
  ])(
    'should return 500 without a challenge on a permanent failure (%s)',
    async (_, error) => {
      mockValidateAccessTokenRejection(error);

      const hook = protectApi()();
      const req = createMockRequest<FastifyRequest>({
        headers: { authorization: 'Bearer t' },
      });
      const reply = createMockResponse<ReplyMock>();

      await hook(req, reply);

      expect(reply.status).toHaveBeenCalledWith(500);
      expect(reply.header).not.toHaveBeenCalled();
      expect(reply.send).toHaveBeenCalledWith({
        message: 'internal server error',
      });
    }
  );
});
