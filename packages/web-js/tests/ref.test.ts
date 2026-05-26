// eslint-disable-next-line import/no-extraneous-dependencies
import { describe, it, expect } from 'vitest';
import { Ref } from '../src/ref';
import { MonoCloudJsError } from '../src';

describe('Ref', () => {
  it('throws MonoCloudJsError when silent iframe contentWindow is null', () => {
    const iframe = {
      contentWindow: null,
    } as unknown as HTMLIFrameElement;

    const ref = new Ref('silent', iframe);

    expect(() => ref.getWindow()).toThrow(MonoCloudJsError);
    expect(() => ref.getWindow()).toThrow(
      'Iframe contentWindow is unavailable'
    );
  });
});
