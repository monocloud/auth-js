/* eslint-disable @typescript-eslint/no-explicit-any */
import { protectApi, getSession } from '@monocloud/auth-nextjs';
import { NextResponse } from 'next/server';

export const GET: any = protectApi(async () => {
  const session = await getSession();
  return NextResponse.json(session);
});

export const dynamic = 'force-dynamic';
