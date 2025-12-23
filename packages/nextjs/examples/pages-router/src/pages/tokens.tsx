import { monoCloud } from '@/monocloud';
import { InferGetServerSidePropsType } from 'next';

export default function ServerSide({
  user,
  tokens,
}: InferGetServerSidePropsType<typeof getServerSideProps>) {
  return (
    <div className="mt-5 ml-5 px-10">
      <h1 className="text-2xl font-bold mb-4">Tokens</h1>
      <div className="grid grid-cols-2">
        <div>
          <h2 className="text-xl font-semibold mb-2">User Profile:</h2>
          <pre className="text-sm">{JSON.stringify(user, undefined, 2)}</pre>
        </div>
        <div>
          <h2 className="text-xl font-semibold mb-2 mt-4">Tokens</h2>
          <div className="mb-4">
            <div className="text-lg font-semibold mb-2">Id Token</div>
            <div className="break-all">{tokens?.idToken}</div>
          </div>
          <div className="mb-4">
            <div className="text-lg font-semibold mb-2">Access Token</div>
            <div className="break-all">{tokens?.accessToken}</div>
          </div>
          <div>
            <div className="text-lg font-semibold mb-2">Refresh Token</div>
            <div className="break-all">{tokens?.refreshToken}</div>
          </div>
        </div>
      </div>
    </div>
  );
}

export const getServerSideProps = monoCloud.protectPage({
  getServerSideProps: async ctx => {
    const tokens = await monoCloud.getTokens(ctx.req, ctx.res);

    return {
      props: {
        tokens: {
          idToken: tokens.idToken ?? 'No Token',
          accessToken: tokens.accessToken ?? 'No Token',
          refreshToken: tokens.refreshToken ?? 'No Token',
        },
      },
    };
  },
});
