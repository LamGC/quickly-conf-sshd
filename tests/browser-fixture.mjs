import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { commandsFor, pathsFor, renderPage } from "../cf-worker/src/view.js";

/** Real page rendering and real local assets, with no live Worker or upstream calls. */
export async function startBrowserFixture() {
  const [template, style, script, fixtureKey] = await Promise.all([
    readFile(new URL("../site/index.html", import.meta.url), "utf8"),
    readFile(new URL("../site/assets/style.css", import.meta.url)),
    readFile(new URL("../site/assets/app.js", import.meta.url)),
    readFile(new URL("./fixtures/keys.pub", import.meta.url), "utf8"),
  ]);
  const [type, encoded] = fixtureKey.trim().split(/\s+/);
  const comment = 'HOMEPAGE-MUST-NOT-LEAK-COMMENT CI test <img src=x onerror="window.__injected=true"> & "quoted" 中文 ' + "long-comment-".repeat(90);
  const text = `${type} ${encoded} ${comment}`;
  const key = {
    type,
    text,
    label: comment,
    fingerprint: "SHA256:" + createHash("sha256").update(Buffer.from(encoded, "base64")).digest("base64").replace(/=+$/, ""),
  };
  const config = { baseUrl: "https://keys.example.test", repositoryUrl: "https://github.com/example/quickly-conf-sshd", signedRelease: {listId: "fixture-signing-list"}, clientDefaults: {gpgVerification: "off"} };
  const base = {
    schema: 1,
    revision: "0123456789abcdef0123456789abcdef01234567",
    publishedAt: "2026-10-12T12:34:56.000Z",
    keyCount: 1,
    allowEmpty: false,
    sha256: createHash("sha256").update(text + "\n").digest("hex"),
    testFixture: true,
    ...config,
    commands: commandsFor(config),
    paths: pathsFor(config),
    keys: [key],
    signedMetadata: null,
  };
  const snapshots = {
    repository: { ...base, publicCertificate: "HOMEPAGE-MUST-NOT-LEAK-CERTIFICATE", source: { type: "repository" } },
    gist: { ...base, keyRevision: "d".repeat(64), signedMetadata: {listId: "fixture-signing-list", sequence: 42, documentSha256: "d".repeat(64)}, keysText: text, signedDocument: text, signature: "-----BEGIN PGP SIGNATURE-----\nComment: HOMEPAGE-MUST-NOT-LEAK-SIGNATURE\n\nAQID\n-----END PGP SIGNATURE-----\n", signedBundle: text, source: {type: "gist", id: "f".repeat(32), gistRevision: "e".repeat(40), url: "https://gist.github.com/example/" + "f".repeat(32) + "/" + "e".repeat(40), extraPrivateComment: comment} },
    "signature-disabled": { ...base, signedRelease: null, signatureAvailable: true, signedMetadata: {listId: "runtime-metadata-only"}, paths: pathsFor({...config, signedRelease: null}), source: {type: "repository"} },
    fallback: { ...base, source: { type: "fallback", url: "https://keys.example.test/team.keys?comment=<script>window.__injected=true</script>" } },
    unavailable: { ...base, keys: [], keyCount: 0, sha256: null, source: { type: "unavailable" } },
    pending: { ...base, keys: [], keyCount: 0, sha256: null, source: { type: "pending" } },
    "explicit-empty": { ...base, allowEmpty: true, signedMetadata: {listId: "fixture-signing-list", sequence: 43, revoke: true}, keys: [], keyCount: 0, sha256: createHash("sha256").update("").digest("hex"), source: { type: "explicit-empty" } },
  };
  const pages = new Map(Object.entries(snapshots).map(([name, snapshot]) => ["/" + name, renderPage(template, snapshot)]));
  const requests = [];
  const server = createServer((request, response) => {
    const pathname = new URL(request.url, "http://127.0.0.1").pathname;
    requests.push(pathname);
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
    if (pathname === "/assets/style.css" || pathname === "/assets/app.js") {
      const isStyle = pathname.endsWith(".css");
      response.setHeader("Content-Type", isStyle ? "text/css; charset=utf-8" : "text/javascript; charset=utf-8");
      response.end(isStyle ? style : script);
      return;
    }
    if (pathname === "/favicon.ico") {
      response.statusCode = 204;
      response.end();
      return;
    }
    const page = pages.get(pathname === "/" ? "/repository" : pathname);
    if (page) {
      response.statusCode = pathname === "/unavailable" ? 503 : 200;
      response.setHeader("Content-Type", "text/html; charset=utf-8");
      response.end(page);
      return;
    }
    response.statusCode = 404;
    response.end("Fixture route not found\n");
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => { server.off("error", reject); resolve(); });
  });
  return {
    origin: `http://127.0.0.1:${server.address().port}`,
    snapshots,
    requests,
    close: () => new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
      server.closeAllConnections();
    }),
  };
}
