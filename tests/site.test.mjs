import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";
import { commandsFor, renderPage } from "../cf-worker/src/view.js";
import { makeSignedDocument, parsePublishedSignedRelease } from "../cf-worker/src/signed-release.js";

const script = await readFile(new URL("../site/assets/app.js", import.meta.url), "utf8");
const html = await readFile(new URL("../site/index.html", import.meta.url), "utf8");
const css = await readFile(new URL("../site/assets/style.css", import.meta.url), "utf8");
const config = { baseUrl: "https://example.test", repositoryUrl: "https://github.com/example/repo", defaultCron: "*/15 * * * *" };
const commands = commandsFor(config);

class Element {
  constructor(id, text = "") {
    this.id = id;
    this.textContent = text;
    this.dataset = {};
    this.attributes = new Map();
    this.listeners = new Map();
    this.classList = { add: (name) => this.attributes.set("class", name) };
    this.disabled = false;
    this.open = false;
    this.value = "";
    this.focused = false;
    this.selected = false;
  }
  setAttribute(name, value) { this.attributes.set(name, value); }
  getAttribute(name) { return this.attributes.get(name) ?? null; }
  removeAttribute(name) { this.attributes.delete(name); }
  addEventListener(name, handler) { this.listeners.set(name, handler); }
  dispatch(name) { return this.listeners.get(name)?.({ target: this }); }
  focus() { this.focused = true; }
  select() { this.selected = true; }
  showModal() { this.open = true; }
  close() { this.open = false; this.dispatch("close"); }
}

function setup({ commandTexts = commands.map(({command}) => command), savedTheme, brokenStorage = false, clipboard = async () => {}, missingTarget = false } = {}) {
  const root = new Element("root");
  const ids = ["theme-picker", "copy-status", "copy-fallback", "fallback-text", "close-copy-fallback"];
  const elements = new Map(ids.map((id) => [id, new Element(id)]));
  const codeElements = commandTexts.map((text, index) => new Element(`command-${index}`, text));
  const pres = codeElements.map((code) => new Element(`pre-${code.id}`));
  const buttons = codeElements.map((code) => {
    const button = new Element(`copy-${code.id}`);
    button.dataset.copyTarget = code.id;
    button.setAttribute("aria-label", `复制 ${code.id}`);
    return button;
  });
  for (const element of codeElements) elements.set(element.id, element);
  if (missingTarget) elements.delete(codeElements[0].id);
  const requestedIds = [];
  const document = {
    documentElement: root,
    getElementById: (id) => { requestedIds.push(id); return elements.get(id) || null; },
    querySelectorAll: (selector) => ({ ".code-block pre": pres, "[data-copy-target]": buttons })[selector] || [],
  };
  const stored = new Map(savedTheme ? [["quickly-conf-sshd-theme", savedTheme]] : []);
  const timers = new Map();
  let timerId = 0;
  const context = vm.createContext({
    document,
    navigator: clipboard === null ? {} : { clipboard: { writeText: clipboard } },
    localStorage: {
      getItem: (key) => { if (brokenStorage) throw new Error("Denied"); return stored.get(key) || null; },
      setItem: (key, value) => { if (brokenStorage) throw new Error("Denied"); stored.set(key, value); },
    },
    setTimeout: (callback) => { timers.set(++timerId, callback); return timerId; },
    clearTimeout: (id) => timers.delete(id),
  });
  vm.runInContext(script, context);
  return { root, elements, codeElements, buttons, pres, stored, requestedIds, flushTimers: () => {
    const pending = [...timers.values()];
    timers.clear();
    pending.forEach((callback) => callback());
  } };
}

function snapshot(overrides = {}) {
  return {revision: "a".repeat(40), publishedAt: "2026-10-12T00:00:00Z", keys: [], keyCount: 1, sha256: "b".repeat(64), keyRevision: "c".repeat(64), commands, ...config, ...overrides};
}
function embeddedMetadata(page) {
  return JSON.parse(page.match(/<script id="release-data" type="application\/json">([\s\S]*?)<\/script>/)[1]);
}

test("homepage prerenders metadata and commands, never a public-key listing", () => {
  for (const token of ["RELEASE_JSON", "COMMANDS_HTML", "REVISION", "PUBLISHED_AT", "KEY_COUNT", "REPOSITORY_URL", "RELEASE_LABEL", "PREVIEW_NOTICE", "SOURCE_LABEL", "SOURCE_STATUS", "SIGNATURE_STATUS", "CERTIFICATE_STATUS", "CERTIFICATE_LINK", "CONTENT_REVISION", "KEYS_NOTICE"]) {
    assert.ok(html.includes(`@@${token}@@`), `${token} placeholder is required`);
  }
  assert.match(html, /<html lang="zh-CN">/);
  assert.match(html, /href="\/assets\/style\.css"/);
  assert.match(html, /src="\/assets\/app\.js" defer/);
  assert.match(html, /<script id="release-data" type="application\/json">/);
  assert.match(html, /aria-live="polite"/);
  assert.match(html, /<noscript>/);
  assert.match(html, /不代表所有服务器均已同步/);
  assert.match(html, /不会要求上传或输入私钥/);
  assert.match(html, /公钥不是秘密/);
  assert.match(html, /原始 API 与公开 Git \/ Gist/);
  assert.doesNotMatch(html, /KEYS_HTML|key-list|key-card|copy-all|github\.io|https?:[^"']+\.(?:css|js)["']/);
});

test("homepage projection excludes raw keys, fingerprints, comments and signed document content", () => {
  const secretMarker = "must-not-appear-in-homepage";
  const key = {text: `ssh-ed25519 ${secretMarker} comment`, fingerprint: `SHA256:${secretMarker}`, label: `${secretMarker}<script>`, type: "ssh-ed25519"};
  const page = renderPage(html, snapshot({keys: [key], keysText: key.text, signedDocument: key.text, signature: `-----BEGIN PGP SIGNATURE-----\nComment: ${secretMarker}\n\nAQID\n-----END PGP SIGNATURE-----\n`, publicCertificate: secretMarker, signedBundle: secretMarker, signedMetadata: {listId: secretMarker}, source: {type: "gist", url: "https://gist.github.com/example/example", keys: [key], fingerprint: key.fingerprint}}));
  assert.doesNotMatch(page, new RegExp(secretMarker));
  assert.doesNotMatch(page, /ssh-ed25519|SHA256:|data-copy-target="key-|id="key-\d|class="key-card"/);
  const embedded = embeddedMetadata(page);
  assert.deepEqual(Object.keys(embedded).sort(), ["schema", "revision", "publishedAt", "keyCount", "sha256", "keyRevision", "source", "sourceStatus", "signaturePresent", "signatureStatus", "certificatePresent", "certificateStatus", "repositoryUrl", "testFixture"].sort());
  assert.deepEqual(embedded.source, {type: "gist", url: "https://gist.github.com/example/example"});
  assert.equal(embedded.keyCount, 1);
  assert.equal(embedded.keyRevision, "c".repeat(64));
  assert.equal(embedded.signaturePresent, true);
  assert.match(embedded.signatureStatus, /待客户端验证/);
  assert.doesNotMatch(embedded.signatureStatus, /已验签|已验证签名|verified/i);
  assert.match(page, /不代表 Worker 已验证签名/);
});

test("source states and signature presence describe one snapshot without claiming verification", () => {
  for (const [type, status] of [["repository", "可用"], ["git", "可用"], ["gist", "可用"], ["fallback", "备用源可用"], ["unavailable", "暂不可用"], ["pending", "待获取"], ["explicit-empty", "明确撤销"]]) {
    const unavailable = ["unavailable", "pending"].includes(type);
    const empty = unavailable || type === "explicit-empty";
    const state = snapshot({source: {type, url: 'https://example.test/list?text=<script>window.__injected=true</script>'}, keyCount: empty ? 0 : 1, allowEmpty: type === "explicit-empty", sha256: empty ? null : "b".repeat(64), keyRevision: empty ? null : "c".repeat(64)});
    const page = renderPage(html, state);
    const embedded = embeddedMetadata(page);
    assert.equal(embedded.sourceStatus, status);
    assert.equal(embedded.keyCount, empty ? 0 : 1);
    assert.equal(embedded.signaturePresent, false);
    assert.equal(embedded.signatureStatus, "未提供签名包");
    assert.doesNotMatch(page, /<script>window\.__injected/);
    if (unavailable) assert.match(page, /未发布撤销指令.*保留上次成功密钥/);
    if (type === "explicit-empty") assert.match(page, /明确撤销全部受管理公钥/);
  }
  assert.equal(embeddedMetadata(renderPage(html, snapshot({signature: "unvalidated signature alone"}))).signaturePresent, false);
  assert.match(renderPage(html, snapshot({source: {type: "gist"}, keyCount: 0, allowEmpty: true})), /class="source-status">明确撤销/);
});

test("a parsed valid document with missing or malformed signature stays unsigned on the homepage", async () => {
  const fixture = await readFile(new URL("./fixtures/keys.pub", import.meta.url), "utf8");
  const document = await makeSignedDocument(fixture, {listId: "homepage-regression", sequence: 1, issuedAt: 1, expiresAt: 2});
  for (const signature of [null, "malformed-detached-signature"]) {
    const parsed = await parsePublishedSignedRelease(document, signature, {checkFreshness: false});
    assert.ok(parsed.metadata);
    assert.equal(parsed.signature, null);
    const page = renderPage(html, snapshot({keys: parsed.keys, keysText: parsed.document, signedDocument: parsed.document, signedMetadata: parsed.metadata, signature: parsed.signature, signedBundle: parsed.bundle}));
    const metadata = embeddedMetadata(page);
    assert.equal(metadata.signaturePresent, false);
    assert.equal(metadata.signatureStatus, "未提供签名包");
    assert.equal(metadata.certificatePresent, false);
    assert.ok(!page.includes(parsed.keys[0].text));
    assert.ok(!page.includes(document));
    assert.doesNotMatch(page, /malformed-detached-signature|conf-sshd-signed-v1/);
  }
});

test("signature and certificate availability are independent and never expose their bytes", () => {
  const document = "document-bytes-must-not-appear";
  const signature = "-----BEGIN PGP SIGNATURE-----\nComment: signature-bytes-must-not-appear\n\nAQID\n-----END PGP SIGNATURE-----\n";
  const certificate = "-----BEGIN PGP PUBLIC KEY BLOCK-----\ncertificate-bytes-must-not-appear\n-----END PGP PUBLIC KEY BLOCK-----\n";
  const paired = {keysText: document, signedDocument: document, signedMetadata: {listId: "test-list"}};
  const cases = [
    {name: "document alone", data: paired, signature: false, certificate: false},
    {name: "malformed detached signature", data: {...paired, signature: "malformed-signature-must-not-appear"}, signature: false, certificate: false},
    {name: "valid pair without certificate", data: {...paired, signature}, signature: true, certificate: false},
    {name: "certificate without signature", data: {...paired, publicCertificate: certificate}, signature: false, certificate: true},
    {name: "valid pair with certificate", data: {...paired, signature, publicCertificate: certificate}, signature: true, certificate: true},
    {name: "wrong document pair", data: {...paired, keysText: "different-document", signature}, signature: false, certificate: false},
    {name: "explicit unavailable flags", data: {...paired, signature, publicCertificate: certificate, signatureAvailable: false, publicCertificateAvailable: false}, signature: false, certificate: false},
    {name: "explicit available flags", data: {signatureAvailable: true, publicCertificateAvailable: true}, signature: true, certificate: true},
    {name: "unavailable keys retain independent certificate", data: {...paired, source: {type: "unavailable"}, signatureAvailable: true, publicCertificate: certificate}, signature: false, certificate: true},
  ];
  for (const entry of cases) {
    const page = renderPage(html, snapshot(entry.data));
    const metadata = embeddedMetadata(page);
    assert.equal(metadata.signaturePresent, entry.signature, entry.name);
    assert.equal(metadata.certificatePresent, entry.certificate, entry.name);
    assert.equal(metadata.signatureStatus, entry.signature ? "签名包已提供（待客户端验证）" : "未提供签名包", entry.name);
    assert.equal(metadata.certificateStatus, entry.certificate ? "公开证书已提供（安装时核验）" : "未提供公开证书", entry.name);
    assert.equal(page.includes('href="/public-key.gpg"'), entry.certificate, entry.name);
    assert.doesNotMatch(page, /must-not-appear|BEGIN PGP|AQID/, entry.name);
    assert.equal(metadata.signedMetadata, undefined);
    assert.equal(metadata.signature, undefined);
    assert.equal(metadata.publicCertificate, undefined);
  }
});

test("commands use an explicit installer and fixed installed client; no self-update command", () => {
  const byId = Object.fromEntries(commands.map((command) => [command.id, command]));
  assert.equal(byId.install.command, "curl -fsSL 'https://example.test/script.sh' | sh -s -- --install --download-script -c");
  assert.equal(byId.once.command, 'sh "$HOME/.conf-sshd/conf-sshd.sh" -o');
  assert.equal(byId.preview.command, 'sh "$HOME/.conf-sshd/conf-sshd.sh" -o --dry-run');
  assert.equal(byId.help.command, "curl -fsSL 'https://example.test/script.sh' | sh -s -- -h");
  assert.match(byId.help.description, /不建立信任/);
  assert.match(byId.install.description, /备份.*保留本地配置/);
  assert.match(byId.install.description, /首次安装或明确重装都会信任你执行的脚本/);
  assert.match(byId.install.description, /推荐先独立核验安装脚本/);
  assert.doesNotMatch(byId.install.description, /重装须使用.*本地脚本/);
  assert.equal(byId.update, undefined);
  for (const id of ["root-off", "root-on", "uninstall"]) {
    assert.equal(byId[id].advanced, true);
    assert.ok(byId[id].command.startsWith('sh "$HOME/.conf-sshd/conf-sshd.sh"'));
  }
  assert.ok(commands.every(({command}) => !/(?:^|\s)-u(?:\s|$)|--update/.test(command)));
  assert.match(html, /预期 SHA-256.*pin/);
  assert.match(html, /验签默认关闭/);
  assert.match(html, /--install --gpg-verification on/);
  assert.match(html, /远端发布内容不能关闭本地验签/);
  assert.match(html, /本地终端确认完整指纹，不能跳过确认/);
  assert.match(html, /日常同步不联网刷新证书/);
  assert.doesNotMatch(html, /--confirm-trust/);
  assert.match(html, /不请求签名/);
  assert.match(html, /两者均返回 200/);
  assert.match(html, /href="\/ssh\.keys\.sig"/);
  assert.doesNotMatch(html, /\/key-release/);
});

test("default follows system and explicit light/dark/system choices persist", () => {
  const page = setup();
  const select = page.elements.get("theme-picker");
  assert.equal(select.value, "system");
  assert.equal(page.root.getAttribute("data-theme"), null);
  for (const theme of ["dark", "light", "system"]) {
    select.value = theme;
    select.dispatch("change");
    assert.equal(page.root.getAttribute("data-theme"), theme === "system" ? null : theme);
    assert.equal(page.stored.get("quickly-conf-sshd-theme"), theme);
  }
  assert.equal(setup({ savedTheme: "dark" }).root.getAttribute("data-theme"), "dark");
  assert.equal(setup({ savedTheme: "unexpected" }).root.getAttribute("data-theme"), null);
});

test("storage restrictions do not prevent theme selection or enhancement", () => {
  const page = setup({ brokenStorage: true });
  const select = page.elements.get("theme-picker");
  select.value = "dark";
  select.dispatch("change");
  assert.equal(page.root.getAttribute("data-theme"), "dark");
  assert.equal(page.root.getAttribute("class"), "enhanced");
  for (const pre of page.pres) assert.equal(pre.getAttribute("tabindex"), "0");
});

test("individual command copies retain every byte, including shell quotes and punctuation", async () => {
  const exact = `sh "$HOME/${"long-path-".repeat(250)}/conf-sshd.sh" -o --dry-run`;
  const copied = [];
  const page = setup({ commandTexts: [commands[0].command, exact], clipboard: async (text) => copied.push(text) });
  await page.buttons[0].dispatch("click");
  await page.buttons[1].dispatch("click");
  assert.deepEqual(copied, [commands[0].command, exact]);
  assert.equal(page.buttons[0].dataset.state, "success");
  assert.match(page.buttons[0].getAttribute("aria-label"), /已复制/);
  assert.equal(page.buttons[0].disabled, false);
  assert.equal(page.buttons[0].getAttribute("aria-busy"), null);
  page.flushTimers();
  assert.equal(page.elements.get("copy-status").textContent, "已复制完整内容。");
  assert.equal(page.buttons[0].dataset.state, undefined);
  assert.equal(page.buttons[0].getAttribute("aria-label"), "复制 command-0");
});

test("page enhancement neither requests key data nor reads embedded release metadata", () => {
  const page = setup();
  assert.ok(!page.requestedIds.includes("release-data"));
  assert.ok(!page.requestedIds.includes("copy-all-keys"));
  assert.doesNotMatch(script, /release-data|release\.keys|key-card|allKeysButton|JSON\.parse|\bfetch\s*\(|XMLHttpRequest|WebSocket|EventSource/);
});

test("missing command targets disable only their own copy buttons", async () => {
  const copied = [];
  const page = setup({missingTarget: true, clipboard: async (text) => copied.push(text)});
  assert.equal(page.buttons[0].disabled, true);
  await page.buttons[0].dispatch("click");
  await page.buttons[1].dispatch("click");
  assert.deepEqual(copied, [page.codeElements[1].textContent]);
});

test("denied or unavailable clipboard offers exact command for manual copy and returns focus", async () => {
  for (const clipboard of [null, async () => { throw new Error("NotAllowedError"); }]) {
    const exact = commands[0].command;
    const page = setup({ commandTexts: [exact], clipboard });
    await page.buttons[0].dispatch("click");
    const dialog = page.elements.get("copy-fallback");
    const textarea = page.elements.get("fallback-text");
    assert.equal(dialog.open, true);
    assert.equal(textarea.value, exact);
    assert.equal(textarea.selected, true);
    assert.equal(textarea.focused, true);
    assert.equal(page.buttons[0].dataset.state, undefined);
    assert.equal(page.buttons[0].disabled, false);
    page.flushTimers();
    assert.match(page.elements.get("copy-status").textContent, /手动复制/);
    page.elements.get("close-copy-fallback").dispatch("click");
    assert.equal(dialog.open, false);
    assert.equal(page.buttons[0].focused, true);
  }
});

test("repeated clicks while clipboard is pending make a single request and retries can recover", async () => {
  let resolveCopy;
  let calls = 0;
  const page = setup({ clipboard: () => {
    calls += 1;
    return new Promise((resolve) => { resolveCopy = resolve; });
  } });
  const first = page.buttons[0].dispatch("click");
  assert.equal(page.buttons[0].disabled, true);
  await page.buttons[0].dispatch("click");
  assert.equal(calls, 1);
  resolveCopy();
  await first;
  assert.equal(page.buttons[0].disabled, false);
  const second = page.buttons[0].dispatch("click");
  resolveCopy();
  await second;
  assert.equal(calls, 2);
  assert.equal(page.buttons[0].dataset.state, "success");
});

test("CSS covers system theme, narrow viewports, touch copies, focus, and reduced motion", () => {
  for (const pattern of [/prefers-color-scheme: dark/, /:root\[data-theme="dark"\]/, /max-width: 680px/, /hover: hover/, /pointer: fine/, /focus-within/, /focus-visible/, /overflow-x: auto/, /prefers-reduced-motion/]) assert.match(css, pattern);
  assert.doesNotMatch(script, /innerHTML|insertAdjacentHTML|\beval\s*\(/);
});

test("touch and narrow layouts explicitly override desktop copy-button hiding", () => {
  const override = css.match(/@media \(hover: none\), \(pointer: coarse\), \(any-pointer: coarse\), \(max-width: 680px\) \{[\s\S]*?\n\}/);
  assert.ok(override, "touch, hybrid, and narrow layouts need an explicit visibility rule");
  assert.match(override[0], /\.code-block > \.copy-button \{ opacity: 1; transition: none; \}/);
  assert.ok(override.index > css.indexOf("@media (hover: hover) and (pointer: fine)"), "touch visibility must win the CSS cascade");
});
