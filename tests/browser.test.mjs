import assert from "node:assert/strict";
import { access, mkdir } from "node:fs/promises";
import { constants } from "node:fs";
import { delimiter, join } from "node:path";
import test from "node:test";
import { startBrowserFixture } from "./browser-fixture.mjs";

async function browserExecutable() {
  const candidates = process.env.CHROMIUM_PATH ? [process.env.CHROMIUM_PATH] : [
    "/usr/bin/google-chrome", "/usr/bin/google-chrome-stable", "/usr/bin/chromium", "/usr/bin/chromium-browser",
    ...(process.env.PATH || "").split(delimiter).flatMap((directory) => ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"].map((name) => join(directory, name))),
  ];
  for (const candidate of new Set(candidates)) {
    try { await access(candidate, constants.X_OK); return candidate; } catch { /* Check the next installed browser. */ }
  }
  throw new Error("BROWSER_TESTS=1 requires an installed Chromium/Google Chrome. Set CHROMIUM_PATH to its executable.");
}

async function capture(page, name) {
  if (!process.env.BROWSER_ARTIFACTS_DIR) return;
  await mkdir(process.env.BROWSER_ARTIFACTS_DIR, { recursive: true });
  await page.screenshot({ path: join(process.env.BROWSER_ARTIFACTS_DIR, name + ".png"), fullPage: true });
}

async function guardedContext(browser, fixture, options = {}) {
  const context = await browser.newContext(options);
  const externalRequests = [];
  await context.route("**/*", (route) => {
    if (new URL(route.request().url()).origin === fixture.origin) return route.continue();
    externalRequests.push(route.request().url());
    return route.abort("blockedbyclient");
  });
  return { context, externalRequests };
}

async function installClipboardMock(context) {
  await context.addInitScript(() => {
    window.__clipboardTest = { values: [], reject: false };
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: async (text) => {
        if (window.__clipboardTest.reject) throw new DOMException("Fixture clipboard denied", "NotAllowedError");
        window.__clipboardTest.values.push(text);
      } },
    });
  });
}

async function noPageOverflow(page, width) {
  const metrics = await page.evaluate(() => ({
    viewport: window.innerWidth,
    document: document.documentElement.scrollWidth,
    body: document.body.scrollWidth,
  }));
  assert.equal(metrics.viewport, width);
  assert.ok(metrics.document <= width && metrics.body <= width, JSON.stringify(metrics));
}

// Opt in on a CI runner with a real browser. Ordinary npm test requires no browser or downloads.
test("real browser homepage integration", { skip: process.env.BROWSER_TESTS !== "1", timeout: 180_000 }, async (t) => {
  const { chromium } = await import("playwright-core");
  const executablePath = await browserExecutable();
  const fixture = await startBrowserFixture();
  let browser;
  try {
    browser = await chromium.launch({ executablePath, headless: true, args: ["--no-sandbox"] });

    for (const width of [390, 1440]) {
      await t.test(`${width}px layout, themes, clipboard, keyboard and fallback`, async () => {
        const { context, externalRequests } = await guardedContext(browser, fixture, {
          viewport: { width, height: 900 },
          colorScheme: "light",
          hasTouch: width < 600,
          isMobile: width < 600,
        });
        try {
          await installClipboardMock(context);
          const page = await context.newPage();
          const errors = [];
          page.on("pageerror", (error) => errors.push(error.message));
          await page.goto(fixture.origin + "/repository");
          await page.waitForSelector("html.enhanced");
          await noPageOverflow(page, width);
          assert.deepEqual(await page.locator("main > section.content-section").evaluateAll((sections) => sections.map((section) => section.id)), ["quick-start", "key-status", "signature", "paths"]);
          const install = fixture.snapshots.repository.commands.find((command) => command.id === "install").command;
          assert.equal(await page.locator("#command-install").textContent(), install);
          assert.equal(await page.locator(".key-card, [data-copy-target^='key-'], #copy-all-keys, #copy-all-commands").count(), 0);
          const contents = await page.content();
          assert.ok(!contents.includes(fixture.snapshots.repository.keys[0].text));
          assert.ok(!contents.includes(fixture.snapshots.repository.keys[0].fingerprint));
          assert.doesNotMatch(contents, /HOMEPAGE-MUST-NOT-LEAK|ssh-ed25519|SHA256:/);
          assert.equal(await page.evaluate(() => window.__injected), undefined);
          assert.equal(await page.locator("#command-install").locator("xpath=..").evaluate((pre) => pre.scrollWidth > pre.clientWidth), true);
          assert.equal(await page.locator("#theme-picker").inputValue(), "system");
          assert.equal(await page.locator("html").getAttribute("data-theme"), null);
          const lightBackground = await page.locator("body").evaluate((body) => getComputedStyle(body).backgroundColor);
          await capture(page, `homepage-${width}-light`);

          await page.selectOption("#theme-picker", "dark");
          assert.equal(await page.locator("html").getAttribute("data-theme"), "dark");
          const darkBackground = await page.locator("body").evaluate((body) => getComputedStyle(body).backgroundColor);
          assert.notEqual(darkBackground, lightBackground);
          await capture(page, `homepage-${width}-dark`);
          await page.reload();
          assert.equal(await page.locator("#theme-picker").inputValue(), "dark");
          assert.equal(await page.locator("html").getAttribute("data-theme"), "dark");
          await page.emulateMedia({ colorScheme: "dark" });
          await page.selectOption("#theme-picker", "light");
          assert.equal(await page.locator("body").evaluate((body) => getComputedStyle(body).backgroundColor), lightBackground);
          await page.selectOption("#theme-picker", "system");
          assert.equal(await page.locator("html").getAttribute("data-theme"), null);
          assert.equal(await page.locator("body").evaluate((body) => getComputedStyle(body).backgroundColor), darkBackground);
          await page.emulateMedia({ colorScheme: "light" });
          assert.equal(await page.locator("body").evaluate((body) => getComputedStyle(body).backgroundColor), lightBackground);
          assert.equal(await page.evaluate(() => localStorage.getItem("quickly-conf-sshd-theme")), "system");

          const commandButton = page.locator('[data-copy-target="command-install"]');
          if (width < 600) {
            assert.equal(await commandButton.evaluate((button) => getComputedStyle(button).opacity), "1", "touch copy buttons stay visible");
          } else {
            await page.locator("#page-title").hover();
            await page.waitForFunction(() => getComputedStyle(document.querySelector('[data-copy-target="command-install"]')).opacity === "0");
          }
          await commandButton.focus();
          await page.waitForFunction(() => getComputedStyle(document.querySelector('[data-copy-target="command-install"]')).opacity === "1");
          await page.keyboard.press("Enter");
          await page.waitForFunction(() => document.querySelector('[data-copy-target="command-install"]').dataset.state === "success");
          assert.equal(await page.evaluate(() => window.__clipboardTest.values[0]), install);
          assert.match(await commandButton.getAttribute("aria-label"), /已复制/);
          await page.waitForFunction(() => document.getElementById("copy-status").textContent.includes("已复制"));

          assert.equal(await page.locator("#copy-all-commands").count(), 0);
          await page.locator("details summary").click();
          for (const command of fixture.snapshots.repository.commands.filter((entry) => entry.id !== "install")) {
            const button = page.locator(`[data-copy-target="command-${command.id}"]`);
            await button.focus();
            await page.keyboard.press("Enter");
            await page.waitForFunction((id) => document.querySelector(`[data-copy-target="command-${id}"]`).dataset.state === "success", command.id);
            assert.equal(await page.evaluate(() => window.__clipboardTest.values.at(-1)), command.command);
          }
          for (const path of fixture.snapshots.repository.paths) {
            assert.equal(await page.locator(`#path-${path.id}`).textContent(), path.url);
            const button = page.locator(`[data-copy-target="path-${path.id}"]`);
            await button.focus();
            await page.keyboard.press("Enter");
            await page.waitForFunction((id) => document.querySelector(`[data-copy-target="path-${id}"]`).dataset.state === "success", path.id);
            assert.equal(await page.evaluate(() => window.__clipboardTest.values.at(-1)), path.url);
          }
          await noPageOverflow(page, width);

          await page.evaluate(() => { window.__clipboardTest.reject = true; });
          await commandButton.focus();
          await page.keyboard.press("Enter");
          await page.waitForSelector("#copy-fallback[open]");
          assert.equal(await page.locator("#fallback-text").inputValue(), install);
          assert.deepEqual(await page.locator("#fallback-text").evaluate((textarea) => ({
            start: textarea.selectionStart, end: textarea.selectionEnd, focused: document.activeElement === textarea,
          })), { start: 0, end: install.length, focused: true });
          assert.equal(await commandButton.getAttribute("data-state"), null, "failed copy must not show success");
          await capture(page, `homepage-${width}-manual-copy`);
          await page.keyboard.press("Escape");
          assert.equal(await page.locator("#copy-fallback").evaluate((dialog) => dialog.open), false);
          assert.equal(await commandButton.evaluate((button) => document.activeElement === button), true);
          await page.keyboard.press("Enter");
          await page.waitForSelector("#copy-fallback[open]");
          await page.locator("#close-copy-fallback").click();
          assert.equal(await commandButton.evaluate((button) => document.activeElement === button), true);
          assert.deepEqual(errors, []);
          assert.deepEqual(externalRequests, []);
        } finally { await context.close(); }
      });
    }

    await t.test("source states expose metadata only and never fetch key or certificate APIs", async () => {
      const { context, externalRequests } = await guardedContext(browser, fixture, { viewport: { width: 390, height: 844 } });
      try {
        await installClipboardMock(context);
        const page = await context.newPage();
        for (const [state, sourceText] of [["repository", "可用"], ["gist", "可用"], ["fallback", "备用源可用"], ["unavailable", "暂不可用"], ["pending", "待获取"], ["explicit-empty", "明确撤销"]]) {
          const response = await page.goto(fixture.origin + "/" + state);
          assert.equal(response.status(), state === "unavailable" ? 503 : 200);
          await page.waitForSelector("html.enhanced");
          assert.equal(await page.locator(".source-status").textContent(), sourceText);
          const snapshot = fixture.snapshots[state];
          assert.equal(await page.locator(".key-count").textContent(), String(snapshot.keyCount));
          assert.equal(await page.locator(".key-card, #copy-all-keys, [data-copy-target^='key-']").count(), 0);
          const embedded = await page.locator("#release-data").evaluate((element) => JSON.parse(element.textContent));
          assert.equal(embedded.source.type, state);
          assert.equal(embedded.keys, undefined);
          assert.equal(embedded.keyRevision, snapshot.keyRevision || snapshot.sha256);
          assert.equal(embedded.signaturePresent, Boolean(snapshot.signature && snapshot.signedDocument === snapshot.keysText));
          assert.equal(embedded.certificatePresent, Boolean(snapshot.publicCertificate));
          assert.equal(await page.locator(".signature-status").textContent(), snapshot.signature ? "签名包已提供（待客户端验证）" : "未提供签名包");
          assert.equal(await page.locator(".certificate-status").textContent(), snapshot.publicCertificate ? "公开证书已提供（安装时核验）" : "未提供公开证书");
          assert.equal(await page.locator('a[href="/public-key.gpg"]').count(), snapshot.publicCertificate ? 1 : 0);
          assert.equal(await page.locator(".release-revision").first().textContent(), snapshot.revision.slice(0, 12));
          assert.equal(await page.locator(".release-revision").nth(1).textContent(), (snapshot.keyRevision || snapshot.sha256)?.slice(0, 12) || "—");
          const content = await page.content();
          assert.doesNotMatch(content, /HOMEPAGE-MUST-NOT-LEAK|ssh-ed25519|SHA256:|\"keys\"\s*:/);
          if (state === "fallback") {
            assert.equal(await page.locator(".source-label").textContent(), "备用源：" + snapshot.source.url);
            assert.equal(await page.locator(".source-label script").count(), 0);
          }
          if (state === "gist") assert.equal(await page.locator(".source-label").textContent(), "Gist：" + snapshot.source.url);
          if (state === "unavailable" || state === "pending") assert.match(await page.locator(".keys-notice").textContent(), /未发布撤销指令.*保留上次成功密钥/);
          if (state === "explicit-empty") assert.match(await page.locator(".keys-notice").textContent(), /明确撤销全部受管理公钥/);
          assert.equal(await page.evaluate(() => window.__injected), undefined);
          await noPageOverflow(page, 390);
          // Repository appearance is already captured in both viewports above: 12 screenshots in total.
          if (state !== "repository") await capture(page, "source-" + state);
        }
        await page.goto(fixture.origin + "/signature-disabled");
        assert.deepEqual(await page.locator("main > section.content-section").evaluateAll((sections) => sections.map((section) => section.id)), ["quick-start", "key-status", "paths"]);
        assert.equal(await page.locator("#signature, #path-signature, #path-certificate").count(), 0, "runtime signature metadata must not enable the Signature section");
        assert.equal(await page.locator("#path-root-script").textContent(), fixture.snapshots.repository.baseUrl + "/");
        assert.deepEqual(externalRequests, []);
      } finally { await context.close(); }
    });

    await t.test("no-JavaScript page retains metadata, commands, source states and system theme", async () => {
      const { context, externalRequests } = await guardedContext(browser, fixture, {
        viewport: { width: 390, height: 844 }, javaScriptEnabled: false, colorScheme: "dark",
      });
      try {
        const page = await context.newPage();
        await page.goto(fixture.origin + "/repository");
        assert.equal(await page.locator("#key-status").isVisible(), true);
        assert.equal(await page.locator(".key-card, [data-copy-target^='key-'], #copy-all-keys").count(), 0);
        assert.equal(await page.locator("#command-install").isVisible(), true);
        assert.equal(await page.locator("#path-root-script").isVisible(), true);
        assert.equal(await page.locator("#path-homepage").textContent(), fixture.snapshots.repository.baseUrl + "/");
        assert.equal(await page.locator('[data-copy-target="command-install"]').isVisible(), false);
        assert.equal(await page.locator("#theme-picker").isVisible(), false);
        assert.match(await page.locator("noscript").textContent(), /手动选择复制/);
        await page.locator("details summary").click();
        assert.equal(await page.locator("#command-uninstall").isVisible(), true);
        assert.equal(await page.locator(".repository-link").getAttribute("href"), fixture.snapshots.repository.repositoryUrl);
        await capture(page, "homepage-no-javascript");
        await page.goto(fixture.origin + "/unavailable");
        assert.equal(await page.locator(".source-status").textContent(), "暂不可用");
        assert.match(await page.locator(".keys-notice").textContent(), /保留上次成功密钥/);
        assert.deepEqual(externalRequests, []);
      } finally { await context.close(); }
    });
    assert.ok(fixture.requests.every((path) => !["/ssh.keys", "/ssh.keys.sig", "/public-key.gpg", "/key-release", "/release.json"].includes(path)), "homepage must not fetch public-key or certificate material");
  } finally {
    await browser?.close();
    await fixture.close();
  }
});
