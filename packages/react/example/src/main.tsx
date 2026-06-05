/* eslint-disable @typescript-eslint/no-non-null-assertion */
/* eslint-disable react/react-in-jsx-scope */
import { MonoCloudAuthProvider } from '@monocloud/auth-react';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import './index.css';

/*
 * Before running this example, configure a Single Page Application client in
 * your MonoCloud dashboard with the following settings (using the dev origin
 * http://localhost:5173):
 *
 *   - Allowed Callback URLs:   http://localhost:5173
 *   - Allowed Sign-out URLs:   http://localhost:5173
 *   - Allowed Origins (CORS):  http://localhost:5173
 *   - Allow Access Tokens via the Browser:  ON
 *   - Allow Offline Access:                 ON  (required for offline_access)
 */
createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <MonoCloudAuthProvider
      tenantDomain="https://<your-tenant-domain>"
      clientId="<your-client-id>"
      defaultAuthParams={{ scopes: 'openid profile email offline_access' }}
    >
      <App />
    </MonoCloudAuthProvider>
  </StrictMode>
);
