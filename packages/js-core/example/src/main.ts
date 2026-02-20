/* eslint-disable @typescript-eslint/no-non-null-assertion */
import './style.css';
import {
  InteractionMode,
  MonoCloudJSCoreClient,
  MonoCloudJSCoreClientOptions,
  RefreshMode,
  GetTokensOptions,
} from '@monocloud/auth-js-core';

/**
 * This is a simple example of how to use the MonoCloudJSCoreClient in a vanilla JS application.
 * The example demonstrates how to sign in, sign out, refresh the session, refetch the userinfo and get tokens.
 *
 * You have to enable the following settings in your client with Single Page Application preset:
 *  - Allowed Callback URLs: http://localhost:5173/
 *  - Allowed Signout URLs: http://localhost:5173/
 *  - Allowed Origins (CORS): http://localhost:5173
 *  - Scopes (at least): openid, profile, email
 *  - Allow Offline Access: On
 */

const options: MonoCloudJSCoreClientOptions = {
  tenantDomain: 'https://<tenant-domain>',
  clientId: '<client-id>',
  appUrl: 'http://localhost:5173',
  callbackPath: '/',
  signOutCallbackPath: '/',
  federatedSignOut: true,
  defaultAuthParams: {
    scopes: 'openid profile email offline_access',
    // resource: <space seprated resources>
  },
  resources: [
    // {
    //   resource: '<space seprated resources>'
    //   scopes: '<space separated scopes>',
    // },
  ],
};

const client = new MonoCloudJSCoreClient(options);

let processingCallback = true;

const updateJson = (elementId: string, value: unknown): void => {
  const element = document.getElementById(elementId)!;
  const newValue = JSON.stringify(value, null, 2);
  element.textContent = newValue;
};

const updateValue = (elementId: string, value: string): void => {
  const element = document.getElementById(elementId)!;
  element.textContent = value;
};

const noUserMessage = document.getElementById('no-user-message')!;

const updateUI = async (): Promise<void> => {
  const userData = document.getElementById('user-data')!;
  const session = await client.getSession();

  if (session && !processingCallback) {
    noUserMessage.classList.add('hidden');
    userData.classList.remove('hidden');
    updateValue('id-token-value', session.idToken ?? 'null');
    updateJson('access-tokens-value', session.accessTokens);
    updateValue('refresh-token-value', session.refreshToken ?? 'null');
    updateJson('user-value', session.user);
    updateJson('session-value', session);
  } else {
    if (!processingCallback) {
      noUserMessage.classList.remove('hidden');
    }
    userData.classList.add('hidden');
  }
};

client
  .processCallback()
  .then(() => {
    processingCallback = false;
    const processCallbackMessage = document.getElementById('loading')!;
    processCallbackMessage.classList.add('hidden');
    noUserMessage.classList.remove('hidden');
    return updateUI();
  })
  .then();

document.getElementById('sign-in-btn')!.addEventListener('click', async () => {
  const mode = (document.getElementById('sign-in-mode') as HTMLSelectElement)
    .value as InteractionMode;
  await client.signIn({ mode });
  await updateUI();
});

document.getElementById('sign-out-btn')!.addEventListener('click', async () => {
  (document.getElementById('token-resource') as HTMLInputElement).value = '';
  (document.getElementById('token-scopes') as HTMLInputElement).value = '';
  (document.getElementById('force-refresh') as HTMLInputElement).checked =
    false;

  const mode = (document.getElementById('sign-out-mode') as HTMLSelectElement)
    .value as InteractionMode;
  const federated = (
    document.getElementById('federated-signout') as HTMLInputElement
  ).checked;
  options.federatedSignOut = federated;
  await client.signOut({ mode });
  await updateUI();
});

document
  .getElementById('refresh-session-btn')!
  .addEventListener('click', async () => {
    const mode = (document.getElementById('refresh-mode') as HTMLSelectElement)
      .value as RefreshMode;
    await client.refreshSession({ mode });
    await updateUI();
  });

document
  .getElementById('refetch-user-btn')!
  .addEventListener('click', async () => {
    await client.refetchUserInfo();
    await updateUI();
  });

document
  .getElementById('get-tokens-btn')!
  .addEventListener('click', async () => {
    const resource = (
      document.getElementById('token-resource') as HTMLInputElement
    ).value.trim();
    const scopes = (
      document.getElementById('token-scopes') as HTMLInputElement
    ).value.trim();
    const forceRefresh = (
      document.getElementById('force-refresh') as HTMLInputElement
    ).checked;

    const getTokensOptions: GetTokensOptions = {
      forceRefresh,
    };

    if (resource) {
      getTokensOptions.resource = resource;
    }

    if (scopes) {
      getTokensOptions.scopes = scopes;
    }

    try {
      const tokens = await client.getTokens(getTokensOptions);
      // eslint-disable-next-line no-console
      console.log('Tokens received:', tokens);

      await updateUI();

      alert('Tokens retrieved successfully!');
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error('Error getting tokens:', error);
    }
  });

await updateUI();
