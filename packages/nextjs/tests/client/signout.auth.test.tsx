/* eslint-disable import/no-extraneous-dependencies */
import 'url-search-params-polyfill';
import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/react';
import React from 'react';
import { SignOut } from '../../src/components/signout';

describe('<SignOut/> - NEXT_PUBLIC_MONOCLOUD_AUTH_SIGNOUT_URL', () => {
  it('should pickup the custom sign out endpoint set through the env', () => {
    process.env.NEXT_PUBLIC_MONOCLOUD_AUTH_SIGNOUT_URL = '/test';

    const { container } = render(<SignOut>Sign Out</SignOut>);
    const anchorElements = container.querySelectorAll('a');
    const anchor = anchorElements.item(0);
    const href = anchor.getAttribute('href');

    expect(href).toBe('/test');
  });
});
