'use client';

import { useAuth } from '@monocloud/auth-nextjs/client';

const Page = () => {
  const { user } = useAuth();

  return (
    <div className="mt-5 ml-5">
      <h1 className="text-2xl font-bold mb-4">useAuth() Hook</h1>
      <pre className="text-sm">{JSON.stringify(user, undefined, 2)}</pre>
    </div>
  );
};

export default Page;
