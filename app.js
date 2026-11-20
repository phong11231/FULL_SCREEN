/* =====================================================================
   DEFENSE_v1.0 — app.js
   Client-side integrity / focus monitor (red/blue lab).

   Design:
   - STANDALONE. Does not know about any extension. Works on its own.
   - Platform-agnostic. No hard-coded host/URL; reads location at runtime.
   - Relies on standard browser signals (visibilitychange, blur/focus,
     fullscreenchange, keydown, input timing) — the same generic surface
     an attacker would try to neutralize.
   - Keeps a local API (window.__DEFENSE__) only for ITS OWN use
     (live table + JSON export). The attack side does NOT depend on it.

   REMINDER: client-side signals are advisory only. A real system must
   re-validate every decision on the server. This page proves nothing by
   itself — it only observes.
   ===================================================================== */
(function () {
  "use strict";

  // ---- Keep pristine references early (defense-in-depth) ----------------
  const NATIVE = {
    addEventListener: EventTarget.prototype.addEventListener,
    now: (performance && performance.now) ? performance.now.bind(performance) : Date.now,
    AEL_src: Function.prototype.toString.call(EventTarget.prototype.addEventListener),
  };

  const DEFENSE = {
    version: "DEFENSE_v1.0",
    startedAt: new Date().toISOString(),
    origin: location.origin,          // runtime, not hard-coded
    logs: [],
    counters: { visibility: 0, blur: 0, fullscreen: 0, keydown: 0, rapid: 0, integrity: 0 },
    integrity: { ok: true, violations: [] },
  };

  // ---- Logging ----------------------------------------------------------
  const SEV = { INFO: "info", WARN: "warn", ALERT: "alert" };

  function log(type, severity, detail) {
    const entry = {
      i: DEFENSE.logs.length + 1,
      t: new Date().toISOString(),
      ms: Math.round(NATIVE.now()),
      type: type,
      severity: severity,
      detail: detail || "",
      url: location.href,
    };
    DEFENSE.logs.push(entry);
    renderRow(entry);
    updateCount();
    if (severity === SEV.ALERT) raiseAlert();
    return entry;
  }

  // ---- DOM refs ---------------------------------------------------------
  const $ = (id) => document.getElementById(id);
  const el = {};
  function cacheEls() {
    el.banner = $("status-banner");
    el.body = $("log-body");
    el.count = $("log-count");
    el.mVis = $("m-visibility");
    el.mFocus = $("m-focus");
    el.mFull = $("m-fullscreen");
    el.mInteg = $("m-integrity");
    el.input = $("answer-input");
    el.submit = $("submit-btn");
    el.fs = $("toggle-fullscreen");
    el.export = $("export-json");
    el.clear = $("clear-log");
  }

  function renderRow(e) {
    if (!el.body) return;
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td>${e.i}</td>` +
      `<td>${e.t.split("T")[1].replace("Z", "")}</td>` +
      `<td>${escapeHtml(e.type)}</td>` +
      `<td class="sev sev--${e.severity}">${e.severity.toUpperCase()}</td>` +
      `<td>${escapeHtml(e.detail)}</td>`;
    el.body.prepend(tr);
  }
  function updateCount() { if (el.count) el.count.textContent = String(DEFENSE.logs.length); }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  function setBanner(text, cls) {
    if (!el.banner) return;
    el.banner.textContent = text;
    el.banner.className = "status " + cls;
  }
  function raiseAlert() { setBanner("⚠ integrity alert", "status--alert"); }

  // ---- 1) Visibility (tab switch / minimize) ----------------------------
  function onVisibility() {
    const state = document.visibilityState;
    if (el.mVis) el.mVis.textContent = state;
    if (document.hidden || state !== "visible") {
      DEFENSE.counters.visibility++;
      log("visibilitychange", SEV.ALERT, "page hidden / tab switched (state=" + state + ")");
    } else {
      log("visibilitychange", SEV.INFO, "page visible again");
    }
  }

  // ---- 2) Window focus/blur --------------------------------------------
  function onBlur() {
    if (el.mFocus) el.mFocus.textContent = "blurred";
    DEFENSE.counters.blur++;
    log("blur", SEV.WARN, "window lost focus");
  }
  function onFocus() {
    if (el.mFocus) el.mFocus.textContent = "focused";
    log("focus", SEV.INFO, "window regained focus");
  }

  // ---- 3) Fullscreen ----------------------------------------------------
  function fsElement() {
    return document.fullscreenElement || document.webkitFullscreenElement || null;
  }
  function onFullscreen() {
    const active = !!fsElement();
    if (el.mFull) el.mFull.textContent = active ? "yes" : "no";
    if (active) log("fullscreenchange", SEV.INFO, "entered fullscreen");
    else { DEFENSE.counters.fullscreen++; log("fullscreenchange", SEV.WARN, "exited fullscreen"); }
  }
  function toggleFullscreen() {
    if (fsElement()) {
      (document.exitFullscreen || document.webkitExitFullscreen || function(){}).call(document);
    } else {
      const d = document.documentElement;
      (d.requestFullscreen || d.webkitRequestFullscreen || function(){}).call(d);
    }
  }

  // ---- 4) Suspicious keydown -------------------------------------------
  // Devtools / copy / paste / print / screenshot / save shortcuts.
  function onKeydown(ev) {
    const k = (ev.key || "").toLowerCase();
    const combo = (ev.ctrlKey ? "Ctrl+" : "") + (ev.metaKey ? "Meta+" : "") +
                  (ev.altKey ? "Alt+" : "") + (ev.shiftKey ? "Shift+" : "") + (ev.key || "");
    let suspicious = null;
    if (k === "f12") suspicious = "DevTools (F12)";
    else if ((ev.ctrlKey || ev.metaKey) && ev.shiftKey && (k === "i" || k === "j" || k === "c"))
      suspicious = "DevTools (" + combo + ")";
    else if ((ev.ctrlKey || ev.metaKey) && k === "u") suspicious = "View source";
    else if ((ev.ctrlKey || ev.metaKey) && (k === "c" || k === "v" || k === "x"))
      suspicious = "Clipboard (" + combo + ")";
    else if ((ev.ctrlKey || ev.metaKey) && (k === "p" || k === "s")) suspicious = combo;
    else if (k === "printscreen") suspicious = "PrintScreen";
    if (suspicious) {
      DEFENSE.counters.keydown++;
      log("keydown", SEV.WARN, "suspicious: " + suspicious);
    }
  }

  // ---- 5) Rapid / bot-like input & submit ------------------------------
  let lastKeyTs = 0, fastRun = 0;
  function onInputTiming() {
    const now = NATIVE.now();
    const gap = now - lastKeyTs;
    lastKeyTs = now;
    if (gap < 30) {                        // <30ms between chars → non-human
      fastRun++;
      if (fastRun === 5) {
        DEFENSE.counters.rapid++;
        log("rapid-input", SEV.WARN, "burst of ultra-fast input (paste/automation?)");
      }
    } else { fastRun = 0; }
  }
  let lastSubmit = 0;
  function onSubmit() {
    const now = NATIVE.now();
    const gap = now - lastSubmit;
    if (lastSubmit && gap < 800) {
      DEFENSE.counters.rapid++;
      log("rapid-submit", SEV.ALERT, "submit spamming (" + Math.round(gap) + "ms apart)");
    } else {
      log("submit", SEV.INFO, "answer submitted");
    }
    lastSubmit = now;
  }

  // ---- 6) Integrity watchdog -------------------------------------------
  // Heuristics that TRIP when something tampers with core APIs. This is how
  // naive bypasses get caught -> gives the lab a real pass/blocked outcome.
  function integrityCheck() {
    const v = [];

    // (a) addEventListener monkey-patched?
    const curSrc = Function.prototype.toString.call(EventTarget.prototype.addEventListener);
    if (curSrc !== NATIVE.AEL_src || !/\[native code\]/.test(curSrc))
      v.push("addEventListener patched");

    // (b) visibilityState overridden as own-property on the instance?
    if (Object.prototype.hasOwnProperty.call(document, "visibilityState") ||
        Object.prototype.hasOwnProperty.call(document, "hidden"))
      v.push("visibilityState/hidden spoofed on instance");

    // (c) getter no longer native?
    const d = Object.getOwnPropertyDescriptor(Document.prototype, "visibilityState");
    if (d && d.get && !/\[native code\]/.test(Function.prototype.toString.call(d.get)))
      v.push("visibilityState getter replaced");

    // (d) hasFocus lying while we were blurred?
    // (observational only)

    if (v.length) {
      DEFENSE.integrity.ok = false;
      // record only new violations
      v.forEach((msg) => {
        if (!DEFENSE.integrity.violations.includes(msg)) {
          DEFENSE.integrity.violations.push(msg);
          DEFENSE.counters.integrity++;
          log("integrity", SEV.ALERT, "TAMPER: " + msg);
        }
      });
      if (el.mInteg) el.mInteg.textContent = "TAMPERED";
    }
  }

  // ---- Export JSON ------------------------------------------------------
  function exportJSON() {
    const payload = {
      meta: {
        version: DEFENSE.version,
        origin: DEFENSE.origin,
        href: location.href,
        userAgent: navigator.userAgent,
        startedAt: DEFENSE.startedAt,
        exportedAt: new Date().toISOString(),
      },
      counters: DEFENSE.counters,
      integrity: DEFENSE.integrity,
      logs: DEFENSE.logs,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "defense_v1_log_" + Date.now() + ".json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    log("export", SEV.INFO, "JSON log exported (" + DEFENSE.logs.length + " entries)");
  }

  function clearLog() {
    DEFENSE.logs.length = 0;
    if (el.body) el.body.innerHTML = "";
    updateCount();
  }

  // ---- Wire up ----------------------------------------------------------
  function bind() {
    cacheEls();

    // Use native addEventListener reference so a later override of the
    // prototype method does not silently drop our own handlers.
    const on = (t, ev, fn, opts) => NATIVE.addEventListener.call(t, ev, fn, opts);

    on(document, "visibilitychange", onVisibility);
    on(window, "blur", onBlur);
    on(window, "focus", onFocus);
    on(document, "fullscreenchange", onFullscreen);
    on(document, "webkitfullscreenchange", onFullscreen);
    on(document, "keydown", onKeydown, true);

    if (el.input) on(el.input, "input", onInputTiming);
    if (el.submit) on(el.submit, "click", onSubmit);
    if (el.fs) on(el.fs, "click", toggleFullscreen);
    if (el.export) on(el.export, "click", exportJSON);
    if (el.clear) on(el.clear, "click", clearLog);

    // periodic integrity scan
    setInterval(integrityCheck, 1000);
    integrityCheck();

    setBanner("[DEFENSE_v1.0 READY]", "status--ready");
    log("boot", SEV.INFO, "monitor armed on " + location.host);

    // Required console banner
    console.log(
      "%c[DEFENSE_v1.0 READY]%c monitor armed — origin=" + DEFENSE.origin,
      "background:#39d98a;color:#04170e;font-weight:700;padding:2px 6px;border-radius:4px",
      "color:#39d98a"
    );
  }

  // Expose for THIS page's own tooling only (export/debug).
  Object.defineProperty(window, "__DEFENSE__", { value: DEFENSE, writable: false, configurable: false });

  if (document.readyState === "loading")
    NATIVE.addEventListener.call(document, "DOMContentLoaded", bind);
  else bind();
})();
