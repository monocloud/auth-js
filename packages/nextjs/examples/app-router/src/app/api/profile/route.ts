import { monoCloud } from '@/monocloud';
import { NextResponse } from 'next/server';

export const GET = monoCloud.protectApi(async () => {
  await monoCloud.getTokens({forceRefresh: true});
  const session = await monoCloud.getSession();
  return NextResponse.json(session);
});

export const dynamic = 'force-dynamic';
