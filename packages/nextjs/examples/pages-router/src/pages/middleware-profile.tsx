import { getSession, MonoCloudUser } from '@monocloud/auth-nextjs';
import { GetServerSideProps, InferGetServerSidePropsType } from 'next';

type Props = { user: MonoCloudUser | null };

export default function MiddlewareProfile({
  user,
}: Props) {
  return (
    <div className="mt-5 ml-5">
      <h1 className="text-2xl font-bold mb-4">Middleware</h1>
      <h2 className="text-xl font-semibold mb-2">Session:</h2>
      <pre className="text-sm whitespace-pre-wrap">
        {JSON.stringify(user, undefined, 2)}
      </pre>
    </div>
  );
}

export const getServerSideProps: GetServerSideProps = async ctx => {
  const session = await getSession(ctx.req, ctx.res);

  return {
    props: {
      user: session?.user ?? null,
    },
  };
};

