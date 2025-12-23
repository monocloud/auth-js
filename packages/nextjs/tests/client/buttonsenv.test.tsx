/* eslint-disable import/no-extraneous-dependencies */
import { render } from '@testing-library/react';
import React from 'react';
import { describe, it, expect } from 'vitest';
import { SignIn } from '../../src/components/signin';
import { SignOut } from '../../src/components/signout';
import { SignUp } from '../../src/components/signup';

describe('<SignIn/>', () => {
  it('should a link to signin endpoint when env set', () => {
    process.env.NEXT_PUBLIC_MONOCLOUD_AUTH_SIGNIN_URL = '/test';
    const { container } = render(<SignIn>Sign In</SignIn>);
    const anchorElements = container.querySelectorAll('a');
    const anchor = anchorElements.item(0);
    const href = anchor.getAttribute('href');

    expect(anchorElements.length).toBe(1);
    expect(anchor.attributes.length).toBe(1);
    expect(href).toBe('/test');
    expect(anchor.text).toBe('Sign In');
  });
});

describe('<SignUp/>', () => {
  it('should render a link to signin endpoint with prompt query param set to create when env set', () => {
    process.env.NEXT_PUBLIC_MONOCLOUD_AUTH_SIGNIN_URL = '/test';
    const { container } = render(<SignUp>Sign Up</SignUp>);
    const anchorElements = container.querySelectorAll('a');
    const anchor = anchorElements.item(0);
    const href = anchor.getAttribute('href');

    expect(anchorElements.length).toBe(1);
    expect(anchor.attributes.length).toBe(1);
    expect(href).toBe('/test?prompt=create');
    expect(anchor.text).toBe('Sign Up');
  });
});

describe('<SignOut/>', () => {
  it('should render a link to signout endpoint', () => {
    process.env.NEXT_PUBLIC_MONOCLOUD_AUTH_SIGNOUT_URL = '/test';
    const { container } = render(<SignOut>Sign Out</SignOut>);
    const anchorElements = container.querySelectorAll('a');
    const anchor = anchorElements.item(0);
    const href = anchor.getAttribute('href');

    expect(anchorElements.length).toBe(1);
    expect(anchor.attributes.length).toBe(1);
    expect(href).toBe('/test');
    expect(anchor.text).toBe('Sign Out');
  });
});
