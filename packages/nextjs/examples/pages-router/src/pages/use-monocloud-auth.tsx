import { useMonoCloudAuth } from '@monocloud/auth-nextjs/client';

export default function UseMonoCloudAuthPage() {
  const { user } = useMonoCloudAuth();

  return (
    <div className="mt-5 ml-5">
      <h1 className="text-2xl font-bold mb-4">useMonoCloudAuth() Hook</h1>
      <pre className="text-sm">{JSON.stringify(user, undefined, 2)}</pre>
    </div>
  );
}
