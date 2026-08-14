import { vi } from 'vitest';

export interface MockHttpRequest {
  headers: Record<string, string | string[] | undefined>;
  [key: string]: unknown;
}

export interface MockHttpResponse {
  status: ReturnType<typeof vi.fn>;
  json: ReturnType<typeof vi.fn>;
  send: ReturnType<typeof vi.fn>;
  set: ReturnType<typeof vi.fn>;
  header: ReturnType<typeof vi.fn>;
  statusCode?: number;
  body?: unknown;
  headers?: Record<string, string>;
}

export const createMockRequest = <T = MockHttpRequest>(
  overrides: Partial<MockHttpRequest> & {
    headers?: Record<string, string | string[] | undefined>;
  } = {}
): T =>
  ({
    ...overrides,
    headers: overrides.headers ?? {},
  }) as T;

export const createMockResponse = <T = MockHttpResponse>(): T => {
  const res: MockHttpResponse = {
    status: vi.fn(),
    json: vi.fn(),
    send: vi.fn(),
    set: vi.fn(),
    header: vi.fn(),
  };

  res.status.mockImplementation((code: number) => {
    res.statusCode = code;
    return res;
  });

  const setHeader = (name: string, value: string): MockHttpResponse => {
    res.headers = { ...res.headers, [name]: value };
    return res;
  };

  res.set.mockImplementation(setHeader);
  res.header.mockImplementation(setHeader);

  res.json.mockImplementation((body: unknown) => {
    res.body = body;
    return res;
  });

  res.send.mockImplementation((body: unknown) => {
    res.body = body;
    return res;
  });

  return res as T;
};

export const createMockNext = <T = ReturnType<typeof vi.fn>>(): T =>
  vi.fn() as T;
