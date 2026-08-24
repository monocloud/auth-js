import { MonoCloudHttpError } from './errors/monocloud-http-error';
import { MonoCloudValidationError } from './errors/monocloud-validation-error';
import { IssuerMetadata, MonoCloudRawResponse } from './types';
import { isPresent } from './utils/internal';

export const JWT_ASSERTION_CLOCK_SKEW = 5;

export function assertMetadataProperty<K extends keyof IssuerMetadata>(
  metadata: IssuerMetadata,
  property: K
): asserts metadata is IssuerMetadata & Required<Pick<IssuerMetadata, K>> {
  if (metadata[property] === undefined || metadata[property] === null) {
    throw new MonoCloudValidationError(
      `${property as string} endpoint is required but not available in the issuer metadata`
    );
  }
}

export const innerFetch = async (
  input: string,
  reqInit: RequestInit = {},
  customFetch?: typeof fetch,
  timeout?: number
): Promise<Response> => {
  const fetcher = customFetch ?? fetch;

  let timedOut = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let init = { ...reqInit };

  if (isPresent(timeout) && timeout > 0) {
    const controller = new AbortController();

    init = { ...init, signal: controller.signal };

    timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeout);
  }

  try {
    return await fetcher(input, init);
  } catch (e) {
    if (timedOut) {
      throw new MonoCloudHttpError(
        `Request to ${input} timed out after ${timeout}ms`
      );
    }

    /* v8 ignore next -- @preserve */
    throw new MonoCloudHttpError(
      (e as any).message ?? 'Unexpected Network Error'
    );
  } finally {
    clearTimeout(timer);
  }
};

export const readRawResponse = async (
  res: Response
): Promise<MonoCloudRawResponse> => {
  let body: string;

  /* v8 ignore start -- @preserve */
  try {
    body = await res.text();
  } catch {
    body = '';
  }
  /* v8 ignore stop */

  return {
    status: res.status,
    statusText: res.statusText,
    headers: Object.fromEntries(
      [...res.headers].filter(([name]) => name !== 'set-cookie')
    ),
    body,
  };
};

export const readErrorResponse = async <T = any>(
  res: Response
): Promise<{ raw: MonoCloudRawResponse; json: Partial<T> }> => {
  const raw = await readRawResponse(res);

  let json: Partial<T> = {};

  try {
    const parsed = JSON.parse(raw.body);
    if (parsed !== null && typeof parsed === 'object') {
      json = parsed;
    }
  } catch {
    json = {};
  }

  return { raw, json };
};

export const deserializeJson = async <T = any>(res: Response): Promise<T> => {
  const raw = await readRawResponse(res);

  try {
    return JSON.parse(raw.body);
  } catch (e) {
    throw new MonoCloudHttpError(
      /* v8 ignore next -- @preserve */
      `Failed to parse response body as JSON ${(e as any).message ? `: ${(e as any).message}` : ''}`,
      raw
    );
  }
};
