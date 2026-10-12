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
          assert.equal(await page.locator("#key-0").textContent(), fixture.snapshots.repository.keys[0].text);
          assert.equal(await page.locator(".key-card img").count(), 0, "key comments must remain text");
          assert.equal(await page.evaluate(() => window.__injected), undefined);
          assert.equal(await page.locator(".key-card pre").evaluate((pre) => pre.scrollWidth > pre.clientWidth), true);
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

          const keyButton = page.locator('[data-copy-target="key-0"]');
          if (width < 600) {
            assert.equal(await keyButton.evaluate((button) => getComputedStyle(button).opacity), "1", "touch copy buttons stay visible");
          } else {
            await page.locator("#page-title").hover();
            await page.waitForFunction(() => getComputedStyle(document.querySelector('[data-copy-target="key-0"]')).opacity === "0");
          }
          await keyButton.focus();
          await page.waitForFunction(() => getComputedStyle(document.querySelector('[data-copy-target="key-0"]')).opacity === "1");
          await page.keyboard.press("Enter");
          await page.waitForFunction(() => document.querySelector('[data-copy-target="key-0"]').dataset.state === "success");
          assert.equal(await page.evaluate(() => window.__clipboardTest.values[0]), fixture.snapshots.repository.keys[0].text);
          assert.match(await keyButton.getAttribute("aria-label"), /已复制/);
          await page.waitForFunction(() => document.getElementById("copy-status").textContent.includes("已复制"));

          await page.locator("#copy-all-keys").click();
          const allKeys = fixture.snapshots.repository.keys.map((key) => key.text).join("\n") + "\n";
          assert.equal(await page.evaluate(() => window.__clipboardTest.values[1]), allKeys);
          assert.equal(await page.locator("#copy-all-commands").count(), 0);
          await page.locator("details summary").click();
          await page.locator('[data-copy-target="command-uninstall"]').focus();
          await page.keyboard.press("Enter");
          const uninstall = fixture.snapshots.repository.commands.find((command) => command.id === "uninstall").command;
          assert.equal(await page.evaluate(() => window.__clipboardTest.values.at(-1)), uninstall);
          await noPageOverflow(page, width);

          await page.evaluate(() => { window.__clipboardTest.reject = true; });
          await keyButton.focus();
          await page.keyboard.press("Enter");
          await page.waitForSelector("#copy-fallback[open]");
          assert.equal(await page.locator("#fallback-text").inputValue(), fixture.snapshots.repository.keys[0].text);
          assert.deepEqual(await page.locator("#fallback-text").evaluate((textarea) => ({
            start: textarea.selectionStart, end: textarea.selectionEnd, focused: document.activeElement === textarea,
          })), { start: 0, end: fixture.snapshots.repository.keys[0].text.length, focused: true });
          assert.equal(await keyButton.getAttribute("data-state"), null, "failed copy must not show success");
          await capture(page, `homepage-${width}-manual-copy`);
          await page.keyboard.press("Escape");
          assert.equal(await page.locator("#copy-fallback").evaluate((dialog) => dialog.open), false);
          assert.equal(await keyButton.evaluate((button) => document.activeElement === button), true);
          await page.keyboard.press("Enter");
          await page.waitForSelector("#copy-fallback[open]");
          await page.locator("#close-copy-fallback").click();
          assert.equal(await keyButton.evaluate((button) => document.activeElement === button), true);
          assert.deepEqual(errors, []);
          assert.deepEqual(externalRequests, []);
        } finally { await context.close(); }
      });
    }

    await t.test("all source states render the same snapshot into metadata, keys and copy data", async () => {
      const { context, externalRequests } = await guardedContext(browser, fixture, { viewport: { width: 390, height: 844 } });
      try {
        await installClipboardMock(context);
        const page = await context.newPage();
        for (const [state, sourceText] of [["repository", "可用"], ["fallback", "备用源可用"], ["unavailable", "暂不可用"], ["pending", "暂不可用"], ["explicit-empty", "明确撤销"]]) {
          const response = await page.goto(fixture.origin + "/" + state);
          assert.equal(response.status(), state === "unavailable" ? 503 : 200);
          await page.waitForSelector("html.enhanced");
          assert.equal(await page.locator(".source-status").textContent(), sourceText);
          const snapshot = fixture.snapshots[state];
          assert.equal(await page.locator(".key-count").textContent(), String(snapshot.keys.length));
          assert.equal(await page.locator("#copy-all-keys").isDisabled(), snapshot.keys.length === 0);
          const embedded = await page.locator("#release-data").evaluate((element) => JSON.parse(element.textContent));
          assert.equal(embedded.source.type, state);
          assert.deepEqual(embedded.keys, snapshot.keys);
          assert.equal(embedded.keyRevision, snapshot.sha256);
          assert.equal(await page.locator(".release-revision").first().textContent(), snapshot.revision.slice(0, 12));
          assert.equal(await page.locator(".release-revision").nth(1).textContent(), snapshot.sha256?.slice(0, 12) || "—");
          if (state === "fallback") {
            assert.equal(await page.locator(".source-label").textContent(), "备用源：" + snapshot.source.url);
            assert.equal(await page.locator(".source-label script").count(), 0);
            await page.locator("#copy-all-keys").click();
            assert.equal(await page.evaluate(() => window.__clipboardTest.values[0]), snapshot.keys.map((key) => key.text).join("\n") + "\n");
          }
          if (state === "unavailable" || state === "pending") {
            assert.match(await page.locator(".keys-notice").textContent(), /未发布撤销指令.*保留上次成功密钥/);
            assert.equal(await page.locator(".key-card").count(), 0);
          }
          if (state === "explicit-empty") assert.match(await page.locator(".keys-notice").textContent(), /明确撤销全部受管理公钥/);
          assert.equal(await page.evaluate(() => window.__injected), undefined);
          await noPageOverflow(page, 390);
          await capture(page, "source-" + state);
        }
        assert.deepEqual(externalRequests, []);
      } finally { await context.close(); }
    });

    await t.test("no-JavaScript page retains keys, commands, source states and system theme", async () => {
      const { context, externalRequests } = await guardedContext(browser, fixture, {
        viewport: { width: 390, height: 844 }, javaScriptEnabled: false, colorScheme: "dark",
      });
      try {
        const page = await context.newPage();
        await page.goto(fixture.origin + "/repository");
        assert.equal(await page.locator("#key-0").isVisible(), true);
        assert.equal(await page.locator("#command-install").isVisible(), true);
        assert.equal(await page.locator("#copy-all-keys").isVisible(), false);
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
  } finally {
    await browser?.close();
    await fixture.close();
  }
});
