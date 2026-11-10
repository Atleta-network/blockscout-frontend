import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';

import * as csp from 'nextjs/csp/index';
import * as middlewares from 'nextjs/middlewares/index';

export async function proxy(req: NextRequest) {
  const isPageRequest = req.headers.get('accept')?.includes('text/html');
  const start = Date.now();

  if (!isPageRequest) {
    return;
  }

  const accountResponse = middlewares.account(req);
  if (accountResponse) {
    return accountResponse;
  }

  // Keep the nonce request-specific; the base CSP is cached across requests.
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64');
  const cspHeader = (await csp.get(req)).replace('script-src ', `script-src 'nonce-${ nonce }' `);
  const requestHeaders = new Headers(req.headers);
  requestHeaders.set('x-nonce', nonce);
  requestHeaders.set('Content-Security-Policy', cspHeader);

  const res = NextResponse.next({
    request: { headers: requestHeaders },
  });

  middlewares.appProfile(req, res);
  middlewares.colorTheme(req, res);
  middlewares.addressFormat(req, res);
  middlewares.scamTokens(req, res);
  middlewares.poorReputationTokens(req, res);

  const end = Date.now();

  res.headers.append('Content-Security-Policy', cspHeader);
  res.headers.append('Server-Timing', `middleware;dur=${ end - start }`);
  res.headers.append('Docker-ID', process.env.HOSTNAME || '');

  return res;
}

/**
 * Configure which routes should pass through the proxy.
 */
export const config = {
  matcher: [ '/', '/:notunderscore((?!_next).+)' ],
  // matcher: [
  //   '/((?!.*\\.|api\\/|node-api\\/).*)', // exclude all static + api + node-api routes
  // ],
};
