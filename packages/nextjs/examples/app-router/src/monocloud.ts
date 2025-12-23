import { MonoCloudNextClient } from '@monocloud/auth-nextjs';

export const monoCloud = new MonoCloudNextClient({ resources: [{
  resource: 'https://api.monocloud.com/admin',
  scopes: 'admin'
}, {
  resource: 'https://api.monocloud.com/identity',
  scopes: 'identity'
}] });
