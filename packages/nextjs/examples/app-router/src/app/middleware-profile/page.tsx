import { monoCloud } from '../../monocloud';

export default async function MiddlewareProfile() {
  const session = await monoCloud.getSession();

  return (
    <div className="mt-5 ml-5">
      <h1 className="text-2xl font-bold mb-4">Middleware</h1>
      <h2 className="text-xl font-semibold mb-2">Session:</h2>
      <pre className="text-sm whitespace-pre-wrap">
        {JSON.stringify(session, undefined, 2)}
      </pre>
    </div>
  );
}
