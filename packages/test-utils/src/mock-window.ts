import { expect, vi } from 'vitest';

export class MockWindow {
  private origin?: string;

  private hash = '';

  private search = '';

  private pathname = '/';

  private href = 'http://localhost:3000/';

  private hrefSetCalled = false;

  private hrefSet = vi.fn();

  private expectedHrefValue?: string;

  private queryKeyValuePresenceCheck: Record<string, string> = {};

  private queryKeyPresenceCheck: string[] = [];

  private queryShouldNotBePresentCheck: string[] = [];

  private location: Location;

  private history: History;

  private ogPostMessage?: typeof window.postMessage;

  public mockedPostMessage: typeof window.postMessage = vi.fn();

  public parentPostMessage: typeof window.postMessage = vi.fn();

  constructor() {
    this.location = window.location;
    this.history = window.history;
  }

  mockPostMessage(): MockWindow {
    this.ogPostMessage = postMessage;

    window.postMessage = this.mockedPostMessage;
    return this;
  }

  mockParentSide(mode: 'Silent' | 'Popup'): MockWindow {
    if (mode === 'Popup') {
      vi.spyOn(window, 'opener', 'get').mockReturnValue({
        postMessage: this.parentPostMessage,
      });
    } else {
      vi.spyOn(window, 'parent', 'get').mockReturnValue({
        postMessage: this.parentPostMessage,
      } as unknown as Window);

      vi.spyOn(window, 'top', 'get').mockReturnValue({} as unknown as Window);
    }
    return this;
  }

  expectOrigin(origin: string): MockWindow {
    this.origin = origin;
    return this;
  }

  expectQueryKey(key: string): MockWindow {
    this.queryKeyPresenceCheck.push(key);
    return this;
  }

  doNotExpectQueryKey(key: string): MockWindow {
    this.queryShouldNotBePresentCheck.push(key);
    return this;
  }

  expectQuery(key: string, value: string): MockWindow {
    this.queryKeyValuePresenceCheck[key] = value;
    return this;
  }

  expectHrefCalled(href: string): MockWindow {
    this.expectedHrefValue = href;
    return this;
  }

  setHash(hash: string): MockWindow {
    this.hash = hash;
    return this;
  }

  setSearch(search: string): MockWindow {
    this.search = search;
    return this;
  }

  setPathname(pathname: string): MockWindow {
    this.pathname = pathname;
    return this;
  }

  assert(): void {
    const assign = vi.fn(u => {
      const url = new URL(u as string);
      if (this.origin) {
        expect(`${url.origin}${url.pathname}`).toBe(this.origin);
      }

      if (this.expectedHrefValue) {
        expect(this.hrefSet).toBeCalledWith(this.expectedHrefValue);
      }

      Object.entries(this.queryKeyValuePresenceCheck ?? {}).forEach(
        ([key, value]) => {
          expect(url.searchParams.get(key)).toBe(value);
        }
      );

      this.queryKeyPresenceCheck?.forEach(key => {
        expect(url.searchParams.has(key), `${key} is not present`).toBe(true);
      });

      this.queryShouldNotBePresentCheck?.forEach(key => {
        expect(url.searchParams.has(key), `${key} is present`).toBe(false);
      });
    });

    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const mockWindowInstance = this;

    Object.defineProperty(window, 'location', {
      writable: true,
      value: {
        assign,
        hash: this.hash,
        search: this.search,
        pathname: this.pathname,
        get href() {
          const href =
            (mockWindowInstance.href.endsWith('/')
              ? mockWindowInstance.href.substring(
                  0,
                  mockWindowInstance.href.length - 1
                )
              : mockWindowInstance.href) ?? '';

          const path =
            (mockWindowInstance.pathname.startsWith('/')
              ? mockWindowInstance.pathname
              : `/${mockWindowInstance.pathname}`) ?? '/';

          let query = '';
          if (mockWindowInstance.search !== '') {
            query = mockWindowInstance.search.startsWith('?')
              ? mockWindowInstance.search
              : `?${mockWindowInstance.search}`;
          }

          let fragment = '';
          if (mockWindowInstance.hash !== '') {
            fragment = mockWindowInstance.hash.startsWith('#')
              ? mockWindowInstance.hash
              : `#${mockWindowInstance.hash}`;
          }

          return mockWindowInstance.hrefSetCalled
            ? mockWindowInstance.href
            : `${href}${path}${query}${fragment}`;
        },
        set href(href) {
          mockWindowInstance.hrefSetCalled = true;
          mockWindowInstance.hrefSet(href);
          mockWindowInstance.href = href;
        },
      },
    });

    Object.defineProperty(window, 'history', {
      writable: true,
      value: {
        replaceState: vi.fn(),
      },
    });
  }

  restore(): void {
    window.location = this.location as string & Location;
    window.history = this.history;

    if (this.ogPostMessage) {
      window.postMessage = this.ogPostMessage;
    }
  }
}
