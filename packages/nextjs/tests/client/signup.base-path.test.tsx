/* eslint-disable import/no-extraneous-dependencies */
import 'url-search-params-polyfill';
import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/react';
import React from 'react';
import { SignUp } from '../../src/components/signup';

describe('<SignUp/> - Base Path', () => {
  it('should pickup base path from __NEXT_ROUTER_BASEPATH', () => {
    // eslint-disable-next-line no-underscore-dangle
    process.env.__NEXT_ROUTER_BASEPATH = '/test';

    const { container } = render(<SignUp>Sign Up</SignUp>);
    const anchorElements = container.querySelectorAll('a');
    const anchor = anchorElements.item(0);
    const href = anchor.getAttribute('href');

    expect(href).toBe('/test/api/auth/signin?prompt=create');
  });
});
