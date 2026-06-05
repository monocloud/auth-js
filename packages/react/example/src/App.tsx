/* eslint-disable react/react-in-jsx-scope */
import {
  Protected,
  SignIn,
  SignOut,
  SignUp,
  useAuth,
  useClient,
} from '@monocloud/auth-react';
import { JSX } from 'react';

export const App = (): JSX.Element => {
  const {
    isLoading,
    isAuthenticated,
    user,
    session,
    error,
    getTokens,
    refreshSession,
    refetchUserInfo,
    signInSilent,
  } = useAuth();
  const client = useClient();

  if (isLoading) {
    return <p className="status">Loading…</p>;
  }

  const handleGetTokens = async (): Promise<void> => {
    const tokens = await getTokens();
    // eslint-disable-next-line no-console
    console.log('tokens', tokens);
  };

  const handleRevoke = async (): Promise<void> => {
    const tokens = await getTokens();
    await client.oidcClient.revokeToken(tokens.accessToken);
  };

  return (
    <main>
      <h1>MonoCloud React SDK</h1>

      <p className="status">
        Authenticated: <strong>{String(isAuthenticated)}</strong>
      </p>
      {error && <p className="error">Error: {error.message}</p>}

      <div className="actions">
        <SignIn>Sign In</SignIn>
        <SignUp>Sign Up</SignUp>
        <SignOut federatedSignOut>Sign Out (Federated)</SignOut>
        <SignOut federatedSignOut={false}>Sign Out (Local)</SignOut>
        <button onClick={() => void signInSilent().catch(() => undefined)}>
          Silent Sign In
        </button>
        <button onClick={() => void refreshSession()}>Refresh Session</button>
        <button onClick={() => void refetchUserInfo()}>Refetch User</button>
        <button onClick={() => void handleGetTokens()}>Get Tokens</button>
        <button onClick={() => void handleRevoke()}>Revoke Access Token</button>
      </div>

      <section>
        <h2>Session</h2>
        <pre>{JSON.stringify(session ?? {}, null, 2)}</pre>
      </section>

      <Protected fallback={<p>Sign in to view the protected content.</p>}>
        <section>
          <h2>Protected content</h2>
          <pre>{JSON.stringify(user, null, 2)}</pre>
        </section>
      </Protected>
    </main>
  );
};
