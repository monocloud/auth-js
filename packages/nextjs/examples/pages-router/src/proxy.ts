import { monoCloud } from './monocloud';

export default monoCloud.authMiddleware({
  protectedRoutes: ['/middleware-profile'],
});

export const config = {
  matcher: ['/((?!.+\\.[\\w]+$|_next).*)', '/', '/(api|trpc)(.*)'],
};
