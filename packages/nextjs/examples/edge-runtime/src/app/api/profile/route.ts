import { monoCloud } from '@/monocloud';
import { NextResponse } from 'next/server';

export const GET = monoCloud.protectApi(async () => {
  const session = await monoCloud.getSession();
  return NextResponse.json(session?.user);
});

export const dynamic = 'force-dynamic';
export const runtime = 'edge';
