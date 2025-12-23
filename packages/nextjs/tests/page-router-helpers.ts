/* eslint-disable @typescript-eslint/no-non-null-assertion */
/* eslint-disable require-await */
import {
  createServer as createHttpServer,
  IncomingMessage,
  Server,
  ServerResponse,
  request as nodeRequest,
} from 'http';
import { AddressInfo } from 'node:net';
import { NextApiRequest, NextApiResponse } from 'next';
import * as cookie from 'cookie';
import { promisify } from 'node:util';
import { Cookie, CookieJar } from 'tough-cookie';
import { json, urlencoded } from 'body-parser';
import { TestPageRes } from './common-helper';

const parseRequestBody = async (
  req: IncomingMessage,
  res: ServerResponse
): Promise<IncomingMessage> => {
  if (req.headers['content-type'] === 'application/json') {
    const mockJson = promisify(json());
    await mockJson(req, res);
  } else {
    const mockUrlEncoded = promisify(urlencoded({ extended: true }));
    await mockUrlEncoded(req, res);
  }
  return req;
};

const toApiReq = async (req: IncomingMessage): Promise<NextApiRequest> => {
  const request: any = await parseRequestBody(req, new ServerResponse(req));

  request.query = Object.fromEntries(
    new URLSearchParams(
      new URL(req.url!, 'http://example.org').search
    ).entries()
  );

  request.cookies = cookie.parse(req.headers.cookie ?? '');

  return request;
};

const toApiRes = async (res: ServerResponse): Promise<NextApiResponse> => {
  const response = res as NextApiResponse;

  response.status = (status: number): NextApiResponse => {
    response.statusCode = status;
    return response;
  };

  response.send = response.end.bind(response);

  response.json = (data: any): void => {
    response.setHeader('Content-Type', 'application/json; charset=utf-8');
    response.send(JSON.stringify(data));
  };

  response.redirect = (
    statusOrUrl: string | number,
    url?: string
  ): NextApiResponse => {
    if (typeof statusOrUrl === 'string') {
      // eslint-disable-next-line no-param-reassign
      url = statusOrUrl;
      // eslint-disable-next-line no-param-reassign
      statusOrUrl = 307;
    }

    response.writeHead(statusOrUrl, { Location: url });
    response.write(url);
    response.end();
    return response;
  };

  return response;
};

let server: Server<typeof IncomingMessage, typeof ServerResponse>;

export const startNodeServer = async (handler: any): Promise<string> => {
  server = createHttpServer(async (req, res) => {
    const apiReq = await toApiReq(req);
    const apiRes = await toApiRes(res);
    await handler(apiReq, apiRes);
  });

  const port = await new Promise(resolve =>
    server.listen(0, () => resolve((server.address() as AddressInfo).port))
  );

  return `http://localhost:${port}`;
};

// Stops the running Page Router server
export const stopNodeServer = async (): Promise<void> => {
  await new Promise(resolve =>
    server.close(resolve as (err?: Error) => object)
  );
};

const request = (
  url: string,
  method = 'GET',
  {
    body,
    cookieJar,
  }: {
    body?: Record<string, string> | string;
    cookieJar?: CookieJar;
  }
): Promise<TestPageRes> =>
  new Promise((resolve, reject) => {
    // eslint-disable-next-line no-param-reassign
    cookieJar = cookieJar ?? new CookieJar();

    const {
      pathname,
      port,
      protocol,
      search = '',
      hostname: host,
    } = new URL(url);
    const req = nodeRequest(
      {
        method,
        host,
        port,
        path: pathname + search,
        protocol,
      },
      res => {
        // eslint-disable-next-line @typescript-eslint/prefer-nullish-coalescing
        (res.headers['set-cookie'] || []).forEach((c: string) => {
          const parsedCookie = Cookie.parse(c);
          if (parsedCookie?.value === '') {
            const jsonCookies = cookieJar!.serializeSync();

            const existing = jsonCookies?.cookies.find(
              x => x.key === parsedCookie.key
            );

            if (existing) {
              existing.value = '';
              existing.expires = parsedCookie.expires;
            }

            // eslint-disable-next-line no-param-reassign
            cookieJar = CookieJar.deserializeSync(jsonCookies ?? '');
            return;
          }
          cookieJar!.setCookieSync(c, url);
        });
        const buffers: Buffer[] = [];
        res.on('data', chunk => {
          buffers.push(chunk);
        });
        res.on('end', () => {
          const str = Buffer.concat(buffers).toString();
          let data;
          try {
            data = str ? JSON.parse(str) : str;
          } catch {
            data = str;
          }
          resolve(
            new TestPageRes(
              res,
              data,
              `${protocol}//${host}${pathname}`,
              cookieJar!
            )
          );
        });
      }
    );
    if (typeof body === 'string') {
      req.setHeader('content-type', 'application/x-www-form-urlencoded');
    } else {
      req.setHeader('content-type', 'application/json');
    }
    if (cookieJar) {
      req.setHeader('cookie', cookieJar.getCookieStringSync(url));
    }
    req.on('error', reject);
    if (body) {
      req.write(typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.end();
  });

export const get = async (
  baseURL: string,
  path: string,
  cookieJar?: CookieJar
): Promise<TestPageRes> => {
  return request(`${baseURL}${path}`, 'GET', { cookieJar });
};

export const post = async (
  baseURL: string,
  path: string,
  {
    body,
    cookieJar,
  }: {
    body: Record<string, any> | string;
    cookieJar?: CookieJar;
  }
): Promise<TestPageRes> =>
  request(`${baseURL}${path}`, 'POST', { body, cookieJar });
