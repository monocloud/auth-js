import { protectApi, getSession } from '@monocloud/auth-nextjs';
import { NextApiRequest, NextApiResponse } from 'next';

export default protectApi(
  async (req: NextApiRequest, res: NextApiResponse) => {
    const session = await getSession(req, res);
    return res.json(session?.user);
  }
);
