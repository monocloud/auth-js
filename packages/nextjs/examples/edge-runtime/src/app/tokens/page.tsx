import { monoCloud } from '@/monocloud';

export default monoCloud.protectPage(async function ServerSide() {
  const session = await monoCloud.getSession();
  const tokens = await monoCloud.getTokens();

  return (
    <div className="mt-5 ml-5 px-10">
      <h1 className="text-2xl font-bold mb-4">Tokens</h1>
      <div className="grid grid-cols-2">
        <div>
          <h2 className="text-xl font-semibold mb-2">User Profile:</h2>
          <pre className="text-sm">
            {JSON.stringify(session?.user, undefined, 2)}
          </pre>
        </div>
        <div>
          <h2 className="text-xl font-semibold mb-2 mt-4">Tokens</h2>
          <div className="mb-4">
            <div className="text-lg font-semibold mb-2">Id Token</div>
            <div className="break-all">{tokens?.idToken ?? 'No Token'}</div>
          </div>
          <div className="mb-4">
            <div className="text-lg font-semibold mb-2">Access Token</div>
            <div className="break-all">{tokens?.accessToken ?? 'No Token'}</div>
          </div>
          <div>
            <div className="text-lg font-semibold mb-2">Refresh Token</div>
            <div className="break-all">
              {tokens?.refreshToken ?? 'No Token'}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
});

export const runtime = 'edge';
