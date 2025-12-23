/* eslint-disable import/no-extraneous-dependencies */
import 'url-search-params-polyfill';
import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/react';
import React from 'react';
import { SignIn } from '../../src/components/signin';

describe('<SignIn/> - Base Path', () => {
  it('should pickup base path from __NEXT_ROUTER_BASEPATH', () => {
    // eslint-disable-next-line no-underscore-dangle
    process.env.__NEXT_ROUTER_BASEPATH = '/test';

    const { container } = render(<SignIn>Sign In</SignIn>);
    const anchorElements = container.querySelectorAll('a');
    const anchor = anchorElements.item(0);
    const href = anchor.getAttribute('href');

    expect(href).toBe('/test/api/auth/signin');
  });
});
