/* eslint-disable import/no-extraneous-dependencies */
import { render, waitFor } from '@testing-library/react';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import React, { JSX } from 'react';
import {
  fetch500,
  fetchNoContent,
  fetchOk,
  fetchOkGroups,
  wrapper,
} from '../client-helper';
import { Protected } from '../../src/components/client/protected';

export const ProtectedComponent = ({
  groups,
  groupsClaim,
  fallback,
  groupFallback,
}: {
  groups?: string[];
  groupsClaim?: string;
  fallback?: React.ReactNode;
  groupFallback?: React.ReactNode;
}): JSX.Element => {
  return (
    <Protected
      groups={groups}
      groupsClaim={groupsClaim}
      fallback={fallback}
      groupFallback={groupFallback}
    >
      <p>Great Success!!!</p>
    </Protected>
  );
};

describe('<Protected/> (Client)', () => {
  let ogFetch: any;
  beforeEach(() => {
    ogFetch = global.fetch;
  });

  afterEach(() => {
    global.fetch = ogFetch;
  });

  it('should render the protected component if user is authenticated', async () => {
    fetchOk();

    const { container } = render(<ProtectedComponent />, {
      wrapper,
    });

    await waitFor(() => {
      expect(container.textContent).toContain('Great Success!!!');
    });
  });

  it('should not render the protected component inside if user is not authenticated', async () => {
    fetchNoContent();

    const { container } = render(<ProtectedComponent />, {
      wrapper,
    });

    await waitFor(() => {
      expect(container.textContent).not.toContain('Great Success!!!');
    });
  });

  it('should not render the protected component inside if there was an authentication error', async () => {
    fetch500();

    const { container } = render(<ProtectedComponent />, {
      wrapper,
    });

    await waitFor(() => {
      expect(container.textContent).not.toContain('Great Success!!!');
    });
  });

  it('should render fallback if the user is not authenticated', async () => {
    fetchNoContent();

    const { container } = render(
      <ProtectedComponent fallback={<>Great Failure!!!</>} />,
      {
        wrapper,
      }
    );

    await waitFor(() => {
      expect(container.textContent).toContain('Great Failure!!!');
    });
  });

  it('should render fallback if there was an authentication error', async () => {
    fetch500();

    const { container } = render(
      <ProtectedComponent fallback={<>Great Failure!!!</>} />,
      {
        wrapper,
      }
    );

    await waitFor(() => {
      expect(container.textContent).toContain('Great Failure!!!');
    });
  });

  it('should render the protected component if user belong to any of the specified groups', async () => {
    fetchOkGroups();

    const { container } = render(<ProtectedComponent groups={['testName']} />, {
      wrapper,
    });

    await waitFor(() => {
      expect(container.textContent).toContain('Great Success!!!');
    });
  });

  it('should not render the protected component inside if user does not belong to any of the specified groups', async () => {
    fetchOkGroups();

    const { container } = render(<ProtectedComponent groups={['NOPE']} />, {
      wrapper,
    });

    await waitFor(() => {
      expect(container.textContent).not.toContain('Great Success!!!');
    });
  });

  it('should NOT render fallback if the user does not belong to any groups', async () => {
    fetchOkGroups();

    const { container } = render(
      <ProtectedComponent groups={['NOPE']} fallback={<>Great Failure!!!</>} />,
      {
        wrapper,
      }
    );

    await waitFor(() => {
      expect(container.textContent).not.toContain('Great Failure!!!');
    });
  });

  it('should render groupFallback if the user does not belong to any groups', async () => {
    fetchOkGroups();

    const { container } = render(
      <ProtectedComponent
        groups={['NOPE']}
        groupFallback={<>Group Specific Failure!!!</>}
      />,
      {
        wrapper,
      }
    );

    await waitFor(() => {
      expect(container.textContent).toContain('Group Specific Failure!!!');
    });
  });

  it('should prioritize groupFallback over fallback when user is authenticated but unauthorized', async () => {
    fetchOkGroups();

    const { container } = render(
      <ProtectedComponent
        groups={['NOPE']}
        fallback={<>Generic Failure</>}
        groupFallback={<>Group Specific Failure!!!</>}
      />,
      {
        wrapper,
      }
    );

    await waitFor(() => {
      expect(container.textContent).toContain('Group Specific Failure!!!');
    });
  });

  it('should be able to customize the groups claim', async () => {
    fetchOkGroups();

    const { container } = render(
      <ProtectedComponent groups={['testId']} groupsClaim="CUSTOM_GROUPS" />,
      {
        wrapper,
      }
    );

    await waitFor(() => {
      expect(container.textContent).toContain('Great Success!!!');
    });
  });
});
