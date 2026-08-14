import {
  MonoCloudHttpError,
  MonoCloudOPError,
  MonoCloudTokenError,
  MonoCloudValidationError,
} from '@monocloud/auth-core';

interface ProtectErrorResponse {
  status: number;
  message: string;
  wwwAuthenticate?: string;
}

const UNAUTHORIZED: ProtectErrorResponse = {
  status: 401,
  message: 'unauthorized',
  wwwAuthenticate: 'Bearer error="invalid_token"',
};

const FORBIDDEN: ProtectErrorResponse = {
  status: 403,
  message: 'forbidden',
  wwwAuthenticate: 'Bearer error="insufficient_scope"',
};

const UNAVAILABLE: ProtectErrorResponse = {
  status: 503,
  message: 'service unavailable',
};

const SERVER_ERROR: ProtectErrorResponse = {
  status: 500,
  message: 'internal server error',
};

export const mapProtectError = (error: unknown): ProtectErrorResponse => {
  if (error instanceof MonoCloudTokenError) {
    return error.code === 'insufficient_scope' ||
      error.code === 'insufficient_groups'
      ? FORBIDDEN
      : UNAUTHORIZED;
  }

  if (error instanceof MonoCloudHttpError) {
    return error.status === undefined ||
      error.status >= 500 ||
      error.status === 429
      ? UNAVAILABLE
      : SERVER_ERROR;
  }

  if (
    error instanceof MonoCloudOPError ||
    error instanceof MonoCloudValidationError
  ) {
    return SERVER_ERROR;
  }

  return UNAUTHORIZED;
};
