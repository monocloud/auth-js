import { monoCloud } from '@/monocloud';
import {
  SignIn,
  SignOut,
  SignUp,
} from '@monocloud/auth-nextjs/components';
import Link from 'next/link';

export const Header = async () => {
  const session = await monoCloud.getSession();

  return (
    <nav className="flex bg-blue-900 text-white justify-between p-6">
      {session?.user ? <h1>Hello {session.user.email}</h1> : <h1>Welcome</h1>}
      <div className="flex gap-4">
        <Link href="/">Home</Link>
        <Link href="/client">Client</Link>
        <Link href="/client/use-monocloud-auth">useMonoCloudAuth() Hook</Link>
        <Link href="/server">Server</Link>
        <Link href="/api-profile">Api</Link>
        <Link href="/middleware-profile">Middleware</Link>
        <Link href="/tokens">Tokens</Link>
      </div>
      <div className="flex gap-4">
        {session?.user ? (
          <SignOut>Sign Out</SignOut>
        ) : (
          <>
            <SignIn>Sign In</SignIn>
            <SignUp>Sign Up</SignUp>
          </>
        )}
      </div>
    </nav>
  );
};
