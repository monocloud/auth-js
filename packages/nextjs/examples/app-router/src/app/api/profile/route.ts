import { monoCloud } from '@/monocloud';
import { NextResponse } from 'next/server';

export const GET = monoCloud.protectApi(async () => {
  const session = await monoCloud.getSession();
  return NextResponse.json(session);
});

export const dynamic = 'force-dynamic';
