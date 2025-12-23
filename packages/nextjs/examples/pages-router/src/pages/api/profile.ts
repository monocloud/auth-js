import { monoCloud } from '@/monocloud';
import { NextApiRequest, NextApiResponse } from 'next';

export default monoCloud.protectApi(
  async (req: NextApiRequest, res: NextApiResponse) => {
    const session = await monoCloud.getSession(req, res);
    return res.json(session?.user);
  }
);
