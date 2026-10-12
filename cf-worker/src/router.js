import { resolveKeys } from './key-source.js';
import { renderPage } from './view.js';
const securityHeaders = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
};

/** Repository keys are bundled; configured empty-primary fallback resolves one snapshot per response. */
export function createHandler(release, {fetchImpl = globalThis.fetch} = {}) {
  return async function fetch(request, env) {
    const url = new URL(request.url);
    const headers = new Headers(securityHeaders);
    headers.set('Cache-Control', 'no-store');
    headers.set('X-Conf-Sshd-Revision', release.revision);
    headers.set('X-Conf-Sshd-Test-Fixture', String(Boolean(release.testFixture)));
    if (!['GET', 'HEAD'].includes(request.method)) {
      headers.set('Allow', 'GET, HEAD');
      return new Response('Method not allowed.\n', {status: 405, headers});
    }
    const respond = (body, type, status = 200) => {
      headers.set('Content-Type', type);
      return new Response(request.method === 'HEAD' ? null : body, {status, headers});
    };
    if (url.pathname === '/script.sh') return respond(release.script, 'text/plain; charset=utf-8');
    let snapshot;
    if (['/ssh.keys','/release.json','/'].includes(url.pathname)) {
      const accept = request.headers.get('Accept') || '';
      const legacyScript = url.pathname === '/' && !accept.toLowerCase().includes('text/html') && /(?:curl|libcurl)\//i.test(request.headers.get('User-Agent') || '');
      if (!legacyScript) {
        try {
          snapshot = {...release, ...await resolveKeys(release, fetchImpl)};
          headers.set('X-Conf-Sshd-Key-Digest', snapshot.sha256);
          headers.set('X-Conf-Sshd-Key-Source', snapshot.source.type);
        } catch (error) {
          if (error.code !== 'KEY_SOURCES_UNAVAILABLE') throw error;
          if (url.pathname !== '/') return respond('No valid public key source is currently available. Existing server keys must be preserved.\n', 'text/plain; charset=utf-8', 503);
          snapshot = {...release,keys:[],keyCount:0,sha256:null,source:{type:'unavailable'}};
        }
      }
    }
    if (url.pathname === '/ssh.keys') return respond(snapshot.keysText, 'text/plain; charset=utf-8');
    if (url.pathname === '/release.json') {
      return respond(JSON.stringify({schema:1,revision:snapshot.revision,publishedAt:snapshot.publishedAt,
        keyCount:snapshot.keyCount,allowEmpty:snapshot.allowEmpty,sha256:snapshot.sha256,keyRevision:snapshot.sha256,
        source:snapshot.source,fetchedAt:snapshot.fetchedAt,testFixture:Boolean(release.testFixture)})+'\n','application/json; charset=utf-8');
    }
    if (url.pathname === '/') {
      headers.set('Vary', 'Accept, User-Agent');
      const accept = request.headers.get('Accept') || '';
      const agent = request.headers.get('User-Agent') || '';
      // Explicit HTML wins; keep historic curl | sh entry point as a compatibility alias.
      if (!accept.toLowerCase().includes('text/html') && /(?:curl|libcurl)\//i.test(agent)) {
        return respond(release.script, 'text/plain; charset=utf-8');
      }
      if (!release.pageTemplate) return respond('Homepage unavailable.\n', 'text/plain; charset=utf-8', 503);
      return respond(renderPage(release.pageTemplate,snapshot),'text/html; charset=utf-8',snapshot.source.type === 'unavailable' ? 503 : 200);
    }
    // Only fingerprinted static assets are exposed; API typos never fall back to HTML.
    if (/^\/assets\/[a-zA-Z0-9._-]+\.(?:css|js)$/.test(url.pathname)) {
      const asset = await env.ASSETS.fetch(request);
      if (!asset.ok) return respond('Not found.\n', 'text/plain; charset=utf-8', 404);
      for (const [key, value] of asset.headers) headers.set(key, value);
      for (const [key, value] of Object.entries(securityHeaders)) headers.set(key, value);
      headers.set('Cache-Control', /\.[a-f0-9]{12}\./.test(url.pathname) ? 'public, max-age=31536000, immutable' : 'no-cache');
      return new Response(request.method === 'HEAD' ? null : asset.body, {status: 200, headers});
    }
    return respond('Not found.\n', 'text/plain; charset=utf-8', 404);
  };
}
