import { MonoCloudHttpError } from './errors/monocloud-http-error';
import { MonoCloudValidationError } from './errors/monocloud-validation-error';
import { IssuerMetadata } from './types';

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
  customFetch?: typeof fetch
): Promise<Response> => {
  try {
    const fetcher = customFetch ?? fetch;
    return await fetcher(input, reqInit);
  } catch (e) {
    /* v8 ignore next -- @preserve */
    throw new MonoCloudHttpError(
      (e as any).message ?? 'Unexpected Network Error'
    );
  }
};

export const deserializeJson = async <T = any>(res: Response): Promise<T> => {
  try {
    return await res.json();
  } catch (e) {
    throw new MonoCloudHttpError(
      /* v8 ignore next -- @preserve */
      `Failed to parse response body as JSON ${(e as any).message ? `: ${(e as any).message}` : ''}`
    );
  }
};
