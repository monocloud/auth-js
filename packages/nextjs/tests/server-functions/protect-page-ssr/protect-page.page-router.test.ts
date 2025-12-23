/* eslint-disable import/no-extraneous-dependencies */
import { CookieJar } from 'tough-cookie';
import { NextApiRequest, NextApiResponse } from 'next';
import { describe, it, beforeEach, afterEach, expect, vi } from 'vitest';
import { MonoCloudNextClient } from '../../../src';
import {
  defaultSessionCookieValue,
  setSessionCookie,
  userWithGroupsSessionCookieValue,
} from '../../common-helper';
import {
  get,
  startNodeServer,
  stopNodeServer,
} from '../../page-router-helpers';

describe('MonoCloud.protectPage() - Page Router', () => {
  let monoCloud: MonoCloudNextClient;
  beforeEach(() => {
    monoCloud = new MonoCloudNextClient();
  });

  afterEach(async () => {
    await stopNodeServer();
  });

  it('should return serverside props with the current user when the request is authenticated', async () => {
    const serverSideProps = monoCloud.protectPage();

    const handler = async (
      req: NextApiRequest,
      res: NextApiResponse
    ): Promise<void> => {
      const result: any = await serverSideProps({
        req,
        res,
        query: req.query,
        resolvedUrl: req.url ?? '/',
      });

      res.end();

      expect(result.props.user).toEqual(defaultSessionCookieValue.user);
    };

    const baseUrl = await startNodeServer(handler);

    const cookieJar = new CookieJar();

    await setSessionCookie(cookieJar, `${baseUrl}/`);

    await get(baseUrl, '/', cookieJar);
  });

  it('should execute custom getServerSideProps()', async () => {
    const getServerSideProps = (
      context: any
    ): Promise<{ props: { custom: string } }> => {
      expect(context.req).toBeDefined();
      expect(context.res).toBeDefined();
      return Promise.resolve({ props: { custom: 'prop' } });
    };

    const serverSideProps = monoCloud.protectPage({ getServerSideProps });

    const handler = async (
      req: NextApiRequest,
      res: NextApiResponse
    ): Promise<void> => {
      const result: any = await serverSideProps({
        req,
        res,
        query: req.query,
        resolvedUrl: req.url ?? '/',
      });

      res.end();

      expect(result.props.user).toEqual(defaultSessionCookieValue.user);
      expect(result.props.custom).toEqual('prop');
    };

    const baseUrl = await startNodeServer(handler);

    const cookieJar = new CookieJar();

    await setSessionCookie(cookieJar, `${baseUrl}/`);

    await get(baseUrl, '/', cookieJar);
  });

  it('should handle promises as props in getServerSideProps()', async () => {
    const getServerSideProps = (
      context: any
    ): Promise<{ props: Promise<{ custom: string }> }> => {
      expect(context.req).toBeDefined();
      expect(context.res).toBeDefined();
      return Promise.resolve({ props: Promise.resolve({ custom: 'prop' }) });
    };

    const serverSideProps = monoCloud.protectPage({ getServerSideProps });

    const handler = async (
      req: NextApiRequest,
      res: NextApiResponse
    ): Promise<void> => {
      const result: any = await serverSideProps({
        req,
        res,
        query: req.query,
        resolvedUrl: req.url ?? '/',
      });

      res.end();

      expect(result.props).toBeInstanceOf(Promise);

      await expect(result.props).resolves.toEqual({
        user: defaultSessionCookieValue.user,
        custom: 'prop',
      });
    };

    const baseUrl = await startNodeServer(handler);

    const cookieJar = new CookieJar();

    await setSessionCookie(cookieJar, `${baseUrl}/`);

    await get(baseUrl, '/', cookieJar);
  });

  it('should not execute custom getServerSideProps for unauthenticated requests', async () => {
    const getServerSideProps = vi.fn();

    const serverSideProps = monoCloud.protectPage({ getServerSideProps });

    const handler = async (
      req: NextApiRequest,
      res: NextApiResponse
    ): Promise<void> => {
      const result: any = await serverSideProps({
        req,
        res,
        query: req.query,
        resolvedUrl: req.url ?? '/',
      });

      res.end();

      expect(result.redirect).toEqual({
        permanent: false,
        destination: 'https://example.org/api/auth/signin?return_url=%2F',
      });
      expect(getServerSideProps).toHaveBeenCalledTimes(0);
    };

    const baseUrl = await startNodeServer(handler);

    await get(baseUrl, '/');
  });

  [
    [{}, { props: {} }],
    [{ props: { custom: true } }, { props: { custom: true } }],
    [null, { props: {} }],
  ].forEach(([ret, expected]: any, i) => {
    it(`can customize onAccessDenied if user is not authenticated ${i + 1}/3`, async () => {
      const serverSideProps = monoCloud.protectPage({
        onAccessDenied: () => ret,
      });

      const handler = async (
        req: NextApiRequest,
        res: NextApiResponse
      ): Promise<void> => {
        const result: any = await serverSideProps({
          req,
          res,
          query: req.query,
          resolvedUrl: req.url ?? '/',
        });

        res.end();

        expect(result).toEqual(expected);
      };

      const baseUrl = await startNodeServer(handler);

      await get(baseUrl, '/');
    });
  });

  it('should redirect to sign in when there is no session', async () => {
    const serverSideProps = monoCloud.protectPage();

    const handler = async (
      req: NextApiRequest,
      res: NextApiResponse
    ): Promise<void> => {
      const result: any = await serverSideProps({
        req,
        res,
        query: req.query,
        resolvedUrl: req.url ?? '/',
      });

      res.end();

      expect(result.redirect).toEqual({
        permanent: false,
        destination: 'https://example.org/api/auth/signin?return_url=%2F',
      });
    };

    const baseUrl = await startNodeServer(handler);

    await get(baseUrl, '/');
  });

  it('should redirect to sign in when there is no session', async () => {
    const serverSideProps = monoCloud.protectPage({
      authParams: {
        acrValues: ['test'],
        prompt: 'none',
        authenticatorHint: 'apple',
        display: 'page',
        loginHint: 'username',
        maxAge: 3600,
        resource: 'https://api.example.org',
        scopes: 'openid profile',
        uiLocales: 'en',
      },
    });

    const handler = async (
      req: NextApiRequest,
      res: NextApiResponse
    ): Promise<void> => {
      const result: any = await serverSideProps({
        req,
        res,
        query: req.query,
        resolvedUrl: req.url ?? '/',
      });

      res.end();

      expect(result.redirect).toEqual({
        permanent: false,
        destination:
          'https://example.org/api/auth/signin?return_url=%2F&scope=openid+profile&resource=https%3A%2F%2Fapi.example.org&acr_values=test&display=page&prompt=none&authenticator_hint=apple&ui_locales=en&max_age=3600&login_hint=username',
      });
    };

    const baseUrl = await startNodeServer(handler);

    await get(baseUrl, '/');
  });

  it('should pickup return url from the resolvedUrl of the request', async () => {
    const serverSideProps = monoCloud.protectPage();

    const handler = async (
      req: NextApiRequest,
      res: NextApiResponse
    ): Promise<void> => {
      const result: any = await serverSideProps({
        req,
        res,
        query: req.query,
        resolvedUrl: req.url ?? '/',
      });

      res.end();

      expect(result.redirect).toEqual({
        permanent: false,
        destination: 'https://example.org/api/auth/signin?return_url=%2Ftest',
      });
    };

    const baseUrl = await startNodeServer(handler);

    await get(baseUrl, '/test');
  });

  it('should pickup return url from options', async () => {
    const serverSideProps = monoCloud.protectPage({ returnUrl: '/overrides' });

    const handler = async (
      req: NextApiRequest,
      res: NextApiResponse
    ): Promise<void> => {
      const result: any = await serverSideProps({
        req,
        res,
        query: req.query,
        resolvedUrl: req.url ?? '/',
      });

      res.end();

      expect(result.redirect).toEqual({
        permanent: false,
        destination:
          'https://example.org/api/auth/signin?return_url=%2Foverrides',
      });
    };

    const baseUrl = await startNodeServer(handler);

    await get(baseUrl, '/test');
  });

  describe('groups', () => {
    it('should return props with user if the user belongs to any of the listed groups', async () => {
      const serverSideProps = monoCloud.protectPage({ groups: ['test'] });

      const user = { ...defaultSessionCookieValue.user, groups: ['test'] };

      const handler = async (
        req: NextApiRequest,
        res: NextApiResponse
      ): Promise<void> => {
        const result: any = await serverSideProps({
          req,
          res,
          query: req.query,
          resolvedUrl: req.url ?? '/',
        });

        res.end();

        expect(result.props.user).toEqual(user);
      };

      const baseUrl = await startNodeServer(handler);

      const cookieJar = new CookieJar();

      await setSessionCookie(cookieJar, `${baseUrl}/`, {
        ...defaultSessionCookieValue,
        user,
      });

      await get(baseUrl, '/', cookieJar);
    });

    it('can customize the groups claim', async () => {
      const serverSideProps = monoCloud.protectPage({
        groups: ['test'],
        groupsClaim: 'CUSTOM_GROUPS',
      });

      const user = {
        ...defaultSessionCookieValue.user,
        CUSTOM_GROUPS: ['test'],
      };

      const handler = async (
        req: NextApiRequest,
        res: NextApiResponse
      ): Promise<void> => {
        const result: any = await serverSideProps({
          req,
          res,
          query: req.query,
          resolvedUrl: req.url ?? '/',
        });

        res.end();

        expect(result.props.user).toEqual(user);
      };

      const baseUrl = await startNodeServer(handler);

      const cookieJar = new CookieJar();

      await setSessionCookie(cookieJar, `${baseUrl}/`, {
        ...defaultSessionCookieValue,
        user,
      });

      await get(baseUrl, '/', cookieJar);
    });

    it('should return props with accessDenied - true if the user does not belongs to any of the listed groups', async () => {
      const serverSideProps = monoCloud.protectPage({
        groups: ['NOPE'],
      });

      const handler = async (
        req: NextApiRequest,
        res: NextApiResponse
      ): Promise<void> => {
        const result: any = await serverSideProps({
          req,
          res,
          query: req.query,
          resolvedUrl: req.url ?? '/',
        });

        res.end();

        expect(result.props).toEqual({ accessDenied: true });
      };

      const baseUrl = await startNodeServer(handler);

      const cookieJar = new CookieJar();

      await setSessionCookie(
        cookieJar,
        `${baseUrl}/`,
        userWithGroupsSessionCookieValue
      );

      await get(baseUrl, '/', cookieJar);
    });

    [
      [{}, { props: {} }],
      [{ props: { custom: true } }, { props: { custom: true } }],
      [null, { props: { accessDenied: true } }],
    ].forEach(([ret, expected]: any, i) => {
      it(`can set custom onAccessDenied getServerSideProps ${i + 1}/2`, async () => {
        const serverSideProps = monoCloud.protectPage({
          groups: ['NOPE'],
          onAccessDenied: () => ret,
        });

        const handler = async (
          req: NextApiRequest,
          res: NextApiResponse
        ): Promise<void> => {
          const result: any = await serverSideProps({
            req,
            res,
            query: req.query,
            resolvedUrl: req.url ?? '/',
          });

          res.end();

          expect(result).toEqual(expected);
        };

        const baseUrl = await startNodeServer(handler);

        const cookieJar = new CookieJar();

        await setSessionCookie(
          cookieJar,
          `${baseUrl}/`,
          userWithGroupsSessionCookieValue
        );

        await get(baseUrl, '/', cookieJar);
      });
    });
  });
});
