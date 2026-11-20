/* =====================================================================
   DEFENSE_v1.0 — app.js  (Exam + anti-cheat auto-submit)
   Red/blue lab defensive surface.

   - STANDALONE, platform-agnostic (no hard-coded host).
   - Monitors standard signals: visibilitychange, blur/focus,
     fullscreenchange, suspicious keydown, rapid input/submit.
   - AUTO-SUBMIT POLICY:
       * CRITICAL  -> nộp ngay lập tức
       * WARNING   -> +1 strike; đủ maxStrikes -> nộp
       * timeout   -> nộp
   - Integrity watchdog phát hiện can thiệp (bị extension vá API).

   NHẮC LẠI: chấm điểm/kết luận ở client KHÔNG đáng tin. Hệ thống thật
   phải nộp đáp án lên server và xác thực ở đó. Trang này chỉ minh hoạ.
   ===================================================================== */
(function () {
  "use strict";

  // ----------------------- CONFIG ---------------------------------------
  const DEF_BUILD = "d3";          // arms-race build tag (defense)
  const CONFIG = {
    durationSec: 600,              // 10 phút
    maxStrikes: 3,                 // d4+: đủ 3 lần phát hiện mới CHỐT CỜ (không auto-nộp)
    // d3 server-authoritative: đặt URL (vd "http://localhost:8799") để bật.
    // null -> degrade về d2 (client-only) — dùng cho GitHub Pages tĩnh.
    server: "http://localhost:8799",
    policy: {
      // kind -> "critical" | "warning"
      "visibility-hidden": "critical",
      "integrity-tamper": "critical",
      "rapid-submit":      "critical",
      "blur":              "warning",
      "fullscreen-exit":   "warning",
      "suspicious-key":    "warning",
      "rapid-input":       "warning",
    },
    requireFullscreen: true,
    labMonitorVisible: true,       // hiện panel log (để demo). Đặt false khi "thi thật".
  };

  // Ngân hàng câu hỏi (sửa tuỳ ý). correct = index đáp án đúng.
  const QUESTIONS = [
    { q: "HTTP mặc định chạy ở cổng nào?", opts: ["21", "80", "443", "8080"], correct: 1 },
    { q: "Lệnh Linux xem quyền file?", opts: ["ls -l", "cat", "cd", "pwd"], correct: 0 },
    { q: "Tầng nào của OSI lo định tuyến (routing)?", opts: ["Data Link", "Network", "Transport", "Session"], correct: 1 },
    { q: "Hàm băm nào ĐÃ được coi là yếu/không nên dùng?", opts: ["SHA-256", "MD5", "SHA-3", "BLAKE2"], correct: 1 },
    { q: "XSS tấn công vào đâu?", opts: ["CSDL máy chủ", "Trình duyệt người dùng", "Router", "Kernel"], correct: 1 },
  ];

  // ----------------------- STATE ----------------------------------------
  const NATIVE = {
    addEventListener: EventTarget.prototype.addEventListener,
    now: (window.performance && performance.now) ? performance.now.bind(performance) : Date.now,
    AEL_src: Function.prototype.toString.call(EventTarget.prototype.addEventListener),
  };
  const DEFENSE = {
    version: "DEFENSE_v1.0",
    startedAt: null,
    origin: location.origin,
    logs: [],
    answers: {},
    strikes: 0,
    submitted: false,
    submitReason: null,
    integrity: { ok: true, violations: [] },
    flagged: false, flagReason: null, serverFlagged: false,   // d4+: chốt cờ, KHÔNG auto-nộp
    counters: { visibility: 0, blur: 0, fullscreen: 0, keydown: 0, rapid: 0, integrity: 0 },
  };
  Object.defineProperty(window, "__DEFENSE__", { value: DEFENSE, writable: false, configurable: false });

  const SEV = { INFO: "info", WARN: "warn", ALERT: "alert" };
  const $ = (id) => document.getElementById(id);
  const el = {};
  let timerId = null, remaining = CONFIG.durationSec, started = false;

  // ----------------------- LOGGING --------------------------------------
  function log(type, severity, detail) {
    const e = {
      i: DEFENSE.logs.length + 1,
      t: new Date().toISOString(),
      ms: Math.round(NATIVE.now()),
      type, severity, detail: detail || "", url: location.href,
    };
    DEFENSE.logs.push(e);
    renderRow(e);
    return e;
  }
  function renderRow(e) {
    if (!el.logBody) return;
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td>${e.i}</td>` +
      `<td>${e.t.split("T")[1].replace("Z", "")}</td>` +
      `<td>${esc(e.type)}</td>` +
      `<td class="sev sev--${e.severity}">${e.severity.toUpperCase()}</td>` +
      `<td>${esc(e.detail)}</td>`;
    el.logBody.prepend(tr);
  }
  function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  // ----------------------- VIOLATION ENGINE -----------------------------
  // Mọi tín hiệu bất thường đi qua đây -> ghi log + thực thi chính sách.
  function violation(kind, detail) {
    if (DEFENSE.submitted) return;                 // đã nộp (thủ công/hết giờ) thì thôi
    const level = CONFIG.policy[kind] || "warning";
    const sev = level === "critical" ? SEV.ALERT : SEV.WARN;
    log(kind, sev, detail || "");                  // MỌI phát hiện đều vào bảng log
    if (window.D3Guard && window.D3Guard.available) window.D3Guard.reportViolation(kind);

    // CHÍNH SÁCH MỚI (giám sát liên tục): KHÔNG auto-nộp, KHÔNG khoá.
    // Mỗi phát hiện = +1 strike; đủ maxStrikes thì CHỐT CỜ nhưng vẫn cho thi tiếp.
    DEFENSE.strikes++;
    updateStrikeUI();
    if (DEFENSE.strikes >= CONFIG.maxStrikes) {
      markFlagged("Đủ " + DEFENSE.strikes + " lần phát hiện — phiên bị gắn cờ (" +
        prettyKind(kind) + ").");
    } else {
      flashBanner("⚠ Phát hiện " + DEFENSE.strikes + "/" + CONFIG.maxStrikes +
        " · " + prettyKind(kind));
    }
  }

  // Chốt cờ vi phạm: ghi log + banner đỏ cố định, nhưng KHÔNG nộp, KHÔNG khoá —
  // watchdog tiếp tục chạy & tiếp tục đẩy log các phát hiện sau.
  function markFlagged(reason) {
    DEFENSE.flagged = true;
    if (!DEFENSE.flagReason) DEFENSE.flagReason = reason;
    log("flagged", SEV.ALERT, reason);
    if (el.banner) {
      el.banner.textContent = "⛔ GẮN CỜ · " + DEFENSE.strikes + " vi phạm (vẫn đang giám sát)";
      el.banner.className = "status status--alert";
    }
    clearTimeout(flashTid);   // giữ banner cờ, không để flash ghi đè
  }
  function prettyKind(k) {
    return ({
      "visibility-hidden": "rời tab / ẩn trang",
      "integrity-tamper": "can thiệp mã giám sát",
      "rapid-submit": "spam nộp bài",
      "blur": "mất focus",
      "fullscreen-exit": "thoát toàn màn hình",
      "suspicious-key": "phím đáng ngờ",
      "rapid-input": "nhập liệu bất thường",
    })[k] || k;
  }

  // ----------------------- MONITORS -------------------------------------
  function onVisibility() {
    if (!started) return;
    if (document.hidden || document.visibilityState !== "visible") {
      DEFENSE.counters.visibility++;
      violation("visibility-hidden", "state=" + document.visibilityState);
    }
  }
  function onBlur() {
    if (!started) return;
    DEFENSE.counters.blur++;
    violation("blur", "cửa sổ mất focus");
  }
  function onFullscreen() {
    if (!started) return;
    const active = !!(document.fullscreenElement || document.webkitFullscreenElement);
    if (!active) {
      DEFENSE.counters.fullscreen++;
      violation("fullscreen-exit", "đã thoát toàn màn hình");
    }
  }
  function onKeydown(ev) {
    if (!started) return;
    const k = (ev.key || "").toLowerCase();
    let sus = null;
    if (k === "f12") sus = "F12 (DevTools)";
    else if ((ev.ctrlKey || ev.metaKey) && ev.shiftKey && (k === "i" || k === "j" || k === "c")) sus = "DevTools";
    else if ((ev.ctrlKey || ev.metaKey) && k === "u") sus = "View source";
    else if ((ev.ctrlKey || ev.metaKey) && (k === "c" || k === "v" || k === "x")) sus = "Clipboard";
    else if ((ev.ctrlKey || ev.metaKey) && (k === "p" || k === "s")) sus = "Print/Save";
    else if (k === "printscreen") sus = "PrintScreen";
    if (sus) {
      DEFENSE.counters.keydown++;
      violation("suspicious-key", sus);
    }
  }
  let lastKeyTs = 0, fastRun = 0;
  function onInputTiming() {
    const now = NATIVE.now(), gap = now - lastKeyTs; lastKeyTs = now;
    if (gap < 25) { if (++fastRun === 6) { DEFENSE.counters.rapid++; violation("rapid-input", "gõ/dán quá nhanh"); } }
    else fastRun = 0;
  }

  // ----------------------- INTEGRITY WATCHDOG ---------------------------
  // PRISTINE realm: một iframe same-origin tạo mới -> có realm built-in RIÊNG,
  // chưa bị ai vá. Dùng Function.prototype.toString của realm đó để soi lại
  // các hàm của window chính. Đây là cách phát hiện CHUNG (không nhận diện
  // riêng extension nào) — kể cả khi toString() của window chính bị giả mạo.
  const PRISTINE = { fts: null, frame: null };
  function initPristineRealm() {
    try {
      const ifr = document.createElement("iframe");
      ifr.setAttribute("aria-hidden", "true");
      ifr.style.cssText = "position:absolute;width:0;height:0;border:0;visibility:hidden";
      (document.body || document.documentElement).appendChild(ifr);   // giữ gắn vào DOM để realm không bị huỷ
      const w = ifr.contentWindow;
      if (w && w.Function) PRISTINE.fts = w.Function.prototype.toString;
      PRISTINE.frame = ifr;
    } catch (e) { PRISTINE.fts = null; }
  }

  function integrityCheck() {
    const v = [];
    const curSrc = Function.prototype.toString.call(EventTarget.prototype.addEventListener);
    if (curSrc !== NATIVE.AEL_src || !/\[native code\]/.test(curSrc)) v.push("addEventListener patched");
    if (Object.prototype.hasOwnProperty.call(document, "visibilityState") ||
        Object.prototype.hasOwnProperty.call(document, "hidden")) v.push("visibilityState spoofed (instance)");
    const d = Object.getOwnPropertyDescriptor(Document.prototype, "visibilityState");
    if (d && d.get && !/\[native code\]/.test(Function.prototype.toString.call(d.get))) v.push("visibilityState getter replaced");

    // --- DEFENSE build d2: cross-realm probe ---
    if (PRISTINE.fts) {
      try {
        const aelSrc = PRISTINE.fts.call(EventTarget.prototype.addEventListener);
        if (!/\[native code\]/.test(aelSrc)) v.push("addEventListener patched (cross-realm)");
        const d2 = Object.getOwnPropertyDescriptor(Document.prototype, "visibilityState");
        if (d2 && d2.get && !/\[native code\]/.test(PRISTINE.fts.call(d2.get))) v.push("visibilityState getter replaced (cross-realm)");
        if (!/\[native code\]/.test(PRISTINE.fts.call(Function.prototype.toString))) v.push("Function.prototype.toString spoofed (cross-realm)");
      } catch (e) { v.push("cross-realm probe blocked: " + e.message); }
    }

    if (v.length) {
      DEFENSE.integrity.ok = false;
      v.forEach((m) => {
        if (!DEFENSE.integrity.violations.includes(m)) {
          DEFENSE.integrity.violations.push(m);
          DEFENSE.counters.integrity++;
          if (started) violation("integrity-tamper", m);
          else log("integrity", SEV.ALERT, "TAMPER (pre-start): " + m);
        }
      });
    }
  }

  // ----------------------- EXAM FLOW ------------------------------------
  function buildQuestions() {
    el.questions.innerHTML = "";
    QUESTIONS.forEach((item, qi) => {
      const box = document.createElement("div");
      box.className = "qcard";
      let html = `<div class="qtext"><span class="qnum">${qi + 1}.</span> ${esc(item.q)}</div><div class="opts">`;
      item.opts.forEach((opt, oi) => {
        const id = `q${qi}_o${oi}`;
        html += `<label class="opt"><input type="radio" name="q${qi}" value="${oi}" id="${id}"> <span>${esc(opt)}</span></label>`;
      });
      html += `</div>`;
      box.innerHTML = html;
      el.questions.appendChild(box);
    });
    el.totalCount.textContent = String(QUESTIONS.length);
    el.questions.addEventListener("change", (e) => {
      if (e.target && e.target.name && e.target.name.startsWith("q")) {
        DEFENSE.answers[e.target.name] = Number(e.target.value);
        el.answeredCount.textContent = String(Object.keys(DEFENSE.answers).length);
      }
    });
  }

  function startExam() {
    if (started) return;
    if (CONFIG.requireFullscreen) {
      const root = document.documentElement;
      (root.requestFullscreen || root.webkitRequestFullscreen || function(){}).call(root);
    }
    started = true;
    DEFENSE.startedAt = new Date().toISOString();
    el.startOverlay.hidden = true;
    el.exam.hidden = false;
    if (CONFIG.labMonitorVisible) el.monitor.hidden = false;
    setBanner("[DEFENSE_v1.0 READY]", "status--ready");
    log("boot", SEV.INFO, "bài thi bắt đầu trên " + location.host);
    startTimer();

    // Nếu watchdog ĐÃ phát hiện can thiệp trước giờ bắt đầu -> tính thành strike
    // (KHÔNG auto-nộp). Mỗi dấu hiệu tamper khác nhau = 1 lần phát hiện, vào log.
    if (!DEFENSE.integrity.ok) {
      DEFENSE.integrity.violations.forEach((m) => violation("integrity-tamper", m));
    }

    // d3: nếu cấu hình server, mở phiên server-authoritative.
    if (CONFIG.server && window.D3Guard) {
      log("d3", SEV.INFO, "đang kết nối server xác thực…");
      window.D3Guard.start(CONFIG.server, {
        onFlagged: function (reasons) {
          if (DEFENSE.serverFlagged) return;           // server sticky -> chỉ báo 1 lần
          DEFENSE.serverFlagged = true;
          const r = reasons && reasons.length ? reasons[reasons.length - 1] : "bất thường";
          log("server-flag", SEV.ALERT, "SERVER phát hiện: " + r);
          markFlagged("SERVER phát hiện: " + r);        // gắn cờ, KHÔNG nộp
        }
      }).then(function (r) {
        if (r) log("d3", SEV.INFO, "server OK · session " + String(r.sessionId).slice(0, 8) + "…");
        else log("d3", SEV.WARN, "server không với tới — chạy chế độ d2 (client-only)");
      });
    }

    console.log(
      "%c[DEFENSE_v1.0 READY]%c exam armed — origin=" + DEFENSE.origin,
      "background:#39d98a;color:#04170e;font-weight:700;padding:2px 6px;border-radius:4px",
      "color:#39d98a"
    );
  }

  function startTimer() {
    remaining = CONFIG.durationSec;
    renderTimer();
    timerId = setInterval(() => {
      remaining--;
      renderTimer();
      if (remaining <= 0) { clearInterval(timerId); autoSubmit("Hết giờ — nộp bài tự động."); }
    }, 1000);
  }
  function renderTimer() {
    const m = Math.floor(remaining / 60), s = remaining % 60;
    const txt = String(m).padStart(2, "0") + ":" + String(s).padStart(2, "0");
    if (el.timer) el.timer.textContent = txt;
  }

  // Nộp thủ công
  let lastSubmit = 0;
  function manualSubmit() {
    const now = NATIVE.now();
    if (lastSubmit && now - lastSubmit < 800) {
      violation("rapid-submit", Math.round(now - lastSubmit) + "ms apart");
      return;
    }
    lastSubmit = now;
    finalize("Bạn đã nộp bài.");
  }

  function autoSubmit(reason) { finalize(reason, true); }

  function finalize(reason, auto) {
    if (DEFENSE.submitted) return;
    DEFENSE.submitted = true;
    DEFENSE.submitReason = reason;
    if (timerId) clearInterval(timerId);

    // Chấm điểm (client-side, chỉ để demo)
    let score = 0;
    QUESTIONS.forEach((item, qi) => { if (DEFENSE.answers["q" + qi] === item.correct) score++; });

    const elapsed = CONFIG.durationSec - remaining;
    log("submit", auto ? SEV.ALERT : SEV.INFO, (auto ? "AUTO: " : "") + reason + " | score=" + score + "/" + QUESTIONS.length);

    // Hiển thị kết quả
    el.resultTitle.textContent = auto ? "Bài thi bị nộp tự động" : "Đã nộp bài";
    el.resultReason.textContent = reason;
    el.resultReason.className = "result-reason" + (auto ? " result-reason--auto" : "");
    el.scoreVal.textContent = String(score);
    el.scoreMax.textContent = String(QUESTIONS.length);
    el.rElapsed.textContent = Math.floor(elapsed / 60) + "m" + (elapsed % 60) + "s";
    el.rStrikes.textContent = String(DEFENSE.strikes);
    el.rEvents.textContent = String(DEFENSE.logs.length);
    el.rIntegrity.textContent = DEFENSE.integrity.ok ? "ok" : "TAMPERED";
    el.exam.hidden = true;
    el.resultOverlay.hidden = false;

    // d3: server chấm điểm & ra phán quyết (ưu tiên hơn client).
    if (window.D3Guard && window.D3Guard.available) {
      el.resultReason.textContent = reason + " · đang chờ server xác thực…";
      window.D3Guard.submit(DEFENSE.answers).then(function (sv) {
        window.D3Guard.stop();
        if (!sv) { el.resultReason.textContent = reason + " · (server mất kết nối — dùng kết quả client)"; return; }
        el.scoreVal.textContent = String(sv.score);
        el.scoreMax.textContent = String(sv.max);
        el.rIntegrity.textContent = sv.flagged ? "FLAGGED (server)" : "ok (server)";
        el.resultTitle.textContent = sv.flagged ? "Phiên thi BỊ GẮN CỜ (server)" : "Đã nộp — server xác nhận";
        el.resultReason.className = "result-reason" + (sv.flagged ? " result-reason--auto" : "");
        el.resultReason.textContent = reason + " · SERVER: " +
          (sv.flagged ? "GIAN LẬN — " + (sv.reasons[sv.reasons.length - 1] || "") : "hợp lệ") +
          " · điểm server: " + sv.score + "/" + sv.max;
      });
    }

    // thoát fullscreen cho gọn
    if (document.fullscreenElement) (document.exitFullscreen || function(){}).call(document);
  }

  // ----------------------- EXPORT ---------------------------------------
  function exportJSON() {
    const payload = {
      meta: { version: DEFENSE.version, origin: DEFENSE.origin, href: location.href,
        userAgent: navigator.userAgent, startedAt: DEFENSE.startedAt, exportedAt: new Date().toISOString(),
        submitted: DEFENSE.submitted, submitReason: DEFENSE.submitReason,
        flagged: DEFENSE.flagged, flagReason: DEFENSE.flagReason, strikes: DEFENSE.strikes },
      counters: DEFENSE.counters, strikes: DEFENSE.strikes, integrity: DEFENSE.integrity,
      answers: DEFENSE.answers, logs: DEFENSE.logs,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "exam_defense_v1_" + Date.now() + ".json";
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // ----------------------- UI HELPERS -----------------------------------
  function setBanner(text, cls) { if (el.banner) { el.banner.textContent = text; el.banner.className = "status " + cls; } }
  let flashTid = null;
  function flashBanner(text) {
    if (!el.banner) return;
    el.banner.textContent = text;
    el.banner.className = "status status--alert";
    clearTimeout(flashTid);
    flashTid = setTimeout(() => setBanner(started && !DEFENSE.submitted ? "armed" : "done",
      started && !DEFENSE.submitted ? "status--ready" : "status--init"), 1500);
  }
  function updateStrikeUI() { if (el.strikeCount) el.strikeCount.textContent = String(DEFENSE.strikes); }

  // ----------------------- BIND -----------------------------------------
  function bind() {
    el.startOverlay = $("start-overlay"); el.startBtn = $("start-btn");
    el.exam = $("exam"); el.questions = $("questions");
    el.timer = $("timer"); el.strikeCount = $("strike-count"); el.strikeMax = $("strike-max");
    el.banner = $("status-banner"); el.submit = $("submit-btn");
    el.answeredCount = $("answered-count"); el.totalCount = $("total-count");
    el.monitor = $("monitor"); el.logBody = $("log-body");
    el.export = $("export-json"); el.toggleMonitor = $("toggle-monitor");
    el.resultOverlay = $("result-overlay"); el.resultTitle = $("result-title");
    el.resultReason = $("result-reason"); el.scoreVal = $("score-val"); el.scoreMax = $("score-max");
    el.rElapsed = $("r-elapsed"); el.rStrikes = $("r-strikes"); el.rEvents = $("r-events"); el.rIntegrity = $("r-integrity");
    el.resultExport = $("result-export"); el.resultMonitor = $("result-monitor");

    // labels
    if ($("max-strikes")) $("max-strikes").textContent = String(CONFIG.maxStrikes);
    if (el.strikeMax) el.strikeMax.textContent = String(CONFIG.maxStrikes);
    if ($("dur-label")) $("dur-label").textContent = fmt(CONFIG.durationSec);
    renderTimerLabel();

    buildQuestions();

    const on = (t, ev, fn, opts) => NATIVE.addEventListener.call(t, ev, fn, opts);
    on(document, "visibilitychange", onVisibility);
    on(window, "blur", onBlur);
    on(document, "fullscreenchange", onFullscreen);
    on(document, "webkitfullscreenchange", onFullscreen);
    on(document, "keydown", onKeydown, true);
    on(el.questions, "input", onInputTiming);

    on(el.startBtn, "click", startExam);
    on(el.submit, "click", manualSubmit);
    on(el.export, "click", exportJSON);
    on(el.resultExport, "click", exportJSON);
    on(el.toggleMonitor, "click", () => { el.monitor.hidden = true; });
    on(el.resultMonitor, "click", () => { el.monitor.hidden = false; });

    initPristineRealm();
    setInterval(integrityCheck, 1000);
    integrityCheck();
    console.log("%c[DEFENSE_v1.0 READY]%c build=" + DEF_BUILD + " · 1-strike · cross-realm watchdog",
      "background:#39d98a;color:#04170e;font-weight:700;padding:2px 6px;border-radius:4px", "color:#39d98a");
  }
  function fmt(sec) { return String(Math.floor(sec / 60)).padStart(2, "0") + ":" + String(sec % 60).padStart(2, "0"); }
  function renderTimerLabel() { if (el.timer) el.timer.textContent = fmt(CONFIG.durationSec); }

  if (document.readyState === "loading") NATIVE.addEventListener.call(document, "DOMContentLoaded", bind);
  else bind();
})();
