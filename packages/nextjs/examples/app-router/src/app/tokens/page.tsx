import { monoCloud } from '../../monocloud';

export default monoCloud.protectPage(async function ServerSide() {
  const session = await monoCloud.getSession();
   await monoCloud.getTokens();
  await monoCloud.getTokens({ scopes: 'openid' })

  return (
    <div className="mt-5 ml-5 px-10 pb-10">
      <h1 className="text-2xl font-bold mb-4">Tokens</h1>
      <div className="grid grid-cols-2">
        <div>
          <h2 className="text-xl font-semibold mb-2">Session</h2>
          <pre className="text-sm">
            {JSON.stringify(session, undefined, 2)}
          </pre>
        </div>
      </div>
    </div>
  );
});
