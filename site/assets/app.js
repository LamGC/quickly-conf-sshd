(() => {
  "use strict";

  const themeKey = "quickly-conf-sshd-theme";
  const root = document.documentElement;
  const themePicker = document.getElementById("theme-picker");
  const status = document.getElementById("copy-status");
  const dialog = document.getElementById("copy-fallback");
  const fallbackText = document.getElementById("fallback-text");
  const closeFallback = document.getElementById("close-copy-fallback");
  const validThemes = new Set(["system", "light", "dark"]);
  const resetTimers = new WeakMap();
  let fallbackTrigger = null;
  let statusTimer;

  function applyTheme(theme) {
    const choice = validThemes.has(theme) ? theme : "system";
    if (choice === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", choice);
    if (themePicker) themePicker.value = choice;
    return choice;
  }

  let savedTheme = "system";
  try {
    savedTheme = localStorage.getItem(themeKey) || "system";
  } catch {
    // Storage may be unavailable in private or restricted browsing contexts.
  }
  applyTheme(savedTheme);
  themePicker?.addEventListener("change", () => {
    const choice = applyTheme(themePicker.value);
    try {
      localStorage.setItem(themeKey, choice);
    } catch {
      // The selected theme still applies for this visit.
    }
  });

  function announce(message) {
    if (!status) return;
    clearTimeout(statusTimer);
    status.textContent = "";
    statusTimer = setTimeout(() => { status.textContent = message; }, 30);
  }

  function showManualCopy(text, trigger) {
    announce("自动复制未成功。请在手动复制窗口中复制已选中的完整内容。");
    if (!dialog || !fallbackText) {
      announce("自动复制未成功。请手动选择页面中的完整内容并复制。");
      return;
    }
    fallbackTrigger = trigger;
    fallbackText.value = text;
    if (!dialog.open) {
      if (typeof dialog.showModal === "function") dialog.showModal();
      else dialog.setAttribute("open", "");
    }
    fallbackText.focus();
    fallbackText.select();
  }

  closeFallback?.addEventListener("click", () => {
    if (typeof dialog.close === "function") dialog.close();
    else {
      dialog.removeAttribute("open");
      fallbackTrigger?.focus();
    }
  });
  dialog?.addEventListener("close", () => { fallbackTrigger?.focus(); });

  async function copy(text, button) {
    if (button.disabled || typeof text !== "string" || text.length === 0) return;
    const label = button.dataset.copyLabel || button.getAttribute("aria-label") || "复制";
    button.dataset.copyLabel = label;
    clearTimeout(resetTimers.get(button));
    delete button.dataset.state;
    button.setAttribute("aria-label", label);
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    try {
      if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function") {
        throw new Error("Clipboard unavailable");
      }
      await navigator.clipboard.writeText(text);
      button.dataset.state = "success";
      button.setAttribute("aria-label", `${label}，已复制`);
      button.setAttribute("title", "已复制");
      announce("已复制完整内容。");
      resetTimers.set(button, setTimeout(() => {
        delete button.dataset.state;
        button.setAttribute("aria-label", label);
        button.setAttribute("title", label);
      }, 2000));
    } catch {
      button.setAttribute("title", "自动复制未成功，点击重试");
      showManualCopy(text, button);
    } finally {
      button.disabled = false;
      button.removeAttribute("aria-busy");
    }
  }

  document.querySelectorAll(".code-block pre").forEach((pre) => {
    pre.setAttribute("tabindex", "0");
  });
  document.querySelectorAll("[data-copy-target]").forEach((button) => {
    const target = document.getElementById(button.dataset.copyTarget);
    if (!target) {
      button.disabled = true;
      button.setAttribute("title", "复制内容不可用");
      return;
    }
    button.addEventListener("click", () => copy(target.textContent, button));
  });

  root.classList.add("enhanced");
})();
