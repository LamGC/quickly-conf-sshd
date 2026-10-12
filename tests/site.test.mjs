import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const script = await readFile(new URL("../site/assets/app.js", import.meta.url), "utf8");
const html = await readFile(new URL("../site/index.html", import.meta.url), "utf8");
const css = await readFile(new URL("../site/assets/style.css", import.meta.url), "utf8");

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

function setup({ keys = ["ssh-ed25519 AAAA exact comment"], savedTheme, brokenStorage = false, clipboard = async () => {}, rawRelease } = {}) {
  const root = new Element("root");
  const ids = ["theme-picker", "copy-status", "copy-fallback", "fallback-text", "close-copy-fallback", "copy-all-keys", "release-data"];
  const elements = new Map(ids.map((id) => [id, new Element(id)]));
  const keyElements = keys.map((text, index) => new Element(`key-${index}`, text));
  const codeElements = [...keyElements, new Element("command-install", "curl -fsSL https://example.test/script.sh | sh -s -- -c")];
  const pres = codeElements.map((code) => new Element(`pre-${code.id}`));
  const buttons = codeElements.map((code) => {
    const button = new Element(`copy-${code.id}`);
    button.dataset.copyTarget = code.id;
    button.setAttribute("aria-label", `复制 ${code.id}`);
    return button;
  });
  for (const element of codeElements) elements.set(element.id, element);
  elements.get("release-data").textContent = rawRelease ?? JSON.stringify({ keys: keys.map((text) => ({ text })) });
  elements.get("copy-all-keys").setAttribute("aria-label", "复制全部公钥");
  const document = {
    documentElement: root,
    getElementById: (id) => elements.get(id) || null,
    querySelectorAll: (selector) => ({
      ".code-block pre": pres,
      "[data-copy-target]": buttons,
      ".key-card pre code": keyElements,
    })[selector] || [],
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
  return { root, elements, keyElements, codeElements, buttons, pres, stored, flushTimers: () => {
    const pending = [...timers.values()];
    timers.clear();
    pending.forEach((callback) => callback());
  } };
}

test("homepage prerenders content, release metadata, and independent local assets", () => {
  for (const token of ["RELEASE_JSON", "KEYS_HTML", "COMMANDS_HTML", "REVISION", "PUBLISHED_AT", "KEY_COUNT", "REPOSITORY_URL", "RELEASE_LABEL", "PREVIEW_NOTICE", "SOURCE_LABEL", "SOURCE_STATUS", "CONTENT_REVISION", "KEYS_NOTICE"]) {
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
  assert.doesNotMatch(html, /github\.io|https?:[^"']+\.(?:css|js)["']/);
  assert.doesNotMatch(html, /copy-all-commands/);
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

test("individual key and command copies retain every byte, including comments and punctuation", async () => {
  const exact = `ssh-ed25519 ${"A".repeat(2000)} user <script> & \"quoted\" 中文`;
  const copied = [];
  const page = setup({ keys: [exact], clipboard: async (text) => copied.push(text) });
  await page.buttons[0].dispatch("click");
  await page.buttons[1].dispatch("click");
  assert.deepEqual(copied, [exact, page.codeElements[1].textContent]);
  assert.equal(page.buttons[0].dataset.state, "success");
  assert.match(page.buttons[0].getAttribute("aria-label"), /已复制/);
  assert.equal(page.buttons[0].disabled, false);
  assert.equal(page.buttons[0].getAttribute("aria-busy"), null);
  page.flushTimers();
  assert.equal(page.elements.get("copy-status").textContent, "已复制完整内容。");
  assert.equal(page.buttons[0].dataset.state, undefined);
  assert.equal(page.buttons[0].getAttribute("aria-label"), "复制 key-0");
});

test("copy all contains only raw public keys and a final LF, never commands", async () => {
  const keys = ["ssh-ed25519 AAAA key one", "ssh-rsa BBBB key two"];
  const copied = [];
  const page = setup({ keys, clipboard: async (text) => copied.push(text) });
  await page.elements.get("copy-all-keys").dispatch("click");
  assert.deepEqual(copied, [`${keys.join("\n")}\n`]);
  assert.ok(!copied[0].includes("curl"));
});

test("missing or malformed release metadata falls back to prerendered keys", async () => {
  for (const rawRelease of ["not json", "{}", '{"keys":[null]}']) {
    const copied = [];
    const page = setup({ keys: ["ssh-ed25519 AAAA fallback"], rawRelease, clipboard: async (text) => copied.push(text) });
    await page.elements.get("copy-all-keys").dispatch("click");
    assert.deepEqual(copied, ["ssh-ed25519 AAAA fallback\n"]);
  }
  assert.equal(setup({ keys: [] }).elements.get("copy-all-keys").disabled, true);
});

test("denied or unavailable clipboard offers exact text for manual copy and returns focus", async () => {
  for (const clipboard of [null, async () => { throw new Error("NotAllowedError"); }]) {
    const exact = "ssh-ed25519 AAAA comment <not markup>";
    const page = setup({ keys: [exact], clipboard });
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

test("unavailable or explicitly revoked key sets leave copy-all disabled and make no clipboard request", async () => {
  for (const sourceStatus of ["暂不可用", "明确撤销"]) {
    const copied = [];
    const page = setup({ keys: [], rawRelease: JSON.stringify({ keys: [], sourceStatus }), clipboard: async (text) => copied.push(text) });
    assert.equal(page.elements.get("copy-all-keys").disabled, true);
    await page.elements.get("copy-all-keys").dispatch("click");
    assert.deepEqual(copied, []);
  }
  assert.match(html, /公钥来源/);
  assert.match(html, /代码版本/);
  assert.match(html, /公钥版本/);
  assert.match(html, /class="keys-notice" role="note"/);
});

test("CSS covers system theme, narrow viewports, touch copies, focus, and reduced motion", () => {
  assert.match(css, /prefers-color-scheme: dark/);
  assert.match(css, /:root\[data-theme="dark"\]/);
  assert.match(css, /max-width: 680px/);
  assert.match(css, /hover: hover/);
  assert.match(css, /pointer: fine/);
  assert.match(css, /focus-within/);
  assert.match(css, /focus-visible/);
  assert.match(css, /overflow-x: auto/);
  assert.match(css, /prefers-reduced-motion/);
  assert.doesNotMatch(script, /innerHTML|insertAdjacentHTML|\beval\s*\(|\bfetch\s*\(/);
});


test("touch and narrow layouts explicitly override desktop copy-button hiding", () => {
  const override = css.match(/@media \(hover: none\), \(pointer: coarse\), \(any-pointer: coarse\), \(max-width: 680px\) \{[\s\S]*?\n\}/);
  assert.ok(override, "touch, hybrid, and narrow layouts need an explicit visibility rule");
  assert.match(override[0], /\.code-block > \.copy-button \{ opacity: 1; transition: none; \}/);
  assert.ok(override.index > css.indexOf("@media (hover: hover) and (pointer: fine)"), "touch visibility must win the CSS cascade");
});
