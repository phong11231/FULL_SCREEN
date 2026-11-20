/* =====================================================================
   DEFENSE d3 — guard-server.js  (client beacon layer)
   Lớp client cho chế độ server-authoritative. TÁCH BIỆT khỏi app.js:
   app.js chỉ gọi vài hàm công khai dưới đây.

   Cơ chế: gửi heartbeat đều đặn lên server. Khi tab bị ẩn, trình duyệt
   THẬT SỰ throttle setInterval/rAF -> beacon tới trễ -> server phát hiện
   mâu thuẫn "nhịp khựng nhưng client khai visible". Client KHÔNG cần tự
   tin tưởng gì — server mới là bên ra phán quyết & chấm điểm.

   API:
     D3Guard.available                      -> boolean (có cấu hình server?)
     await D3Guard.start(url, {onFlagged})  -> {sessionId, questions, hbIntervalMs} | null
     await D3Guard.submit(answers)          -> {score, max, flagged, reasons} | null
     D3Guard.stop()
   ===================================================================== */
(function () {
  "use strict";

  const G = {
    available: false,
    url: null,
    sessionId: null,
    nonce: null,
    seq: 0,
    prevPerf: null,   // d4: mốc performance.now() của nhịp trước (đo throttle)
    hb: null,
    onFlagged: null,
    pendingViolations: [],
    stopped: false,
  };

  async function api(path, body) {
    const res = await fetch(G.url + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
      cache: "no-store",
      keepalive: true,
    });
    if (!res.ok) throw new Error("HTTP " + res.status);
    return res.json();
  }

  async function start(url, opts) {
    G.url = String(url).replace(/\/+$/, "");
    G.onFlagged = (opts && opts.onFlagged) || function () {};
    try {
      // kiểm tra sống + mở phiên
      const s = await api("/session/start", {});
      G.sessionId = s.sessionId;
      G.nonce = s.nonce;
      G.available = true;
      G.stopped = false;
      startHeartbeat(s.hbIntervalMs || 1000);
      return { sessionId: s.sessionId, questions: s.questions || null, hbIntervalMs: s.hbIntervalMs || 1000 };
    } catch (e) {
      G.available = false;
      return null;   // server không với tới -> app.js tự degrade về d2
    }
  }

  function startHeartbeat(interval) {
    const tick = async () => {
      if (G.stopped) return;
      try {
        // d4: Δ performance.now() giữa 2 nhịp TẠO beacon. Tab ẩn -> setInterval
        // bị throttle -> delta này GIÃN RA ngay cả khi visibilityState bị spoof.
        // Server dùng để RAISE cờ (xem server.py mục 2c).
        const tNow = (window.performance && performance.now) ? performance.now() : Date.now();
        const clientDtMs = G.prevPerf == null ? null : Math.round(tNow - G.prevPerf);
        G.prevPerf = tNow;
        const r = await api("/beacon", {
          sessionId: G.sessionId,
          seq: G.seq++,
          // client khai trạng thái — extension có thể đã spoof mấy giá trị này,
          // nhưng NHỊP tới của beacon thì không spoof được.
          claimedVisible: document.visibilityState === "visible",
          claimedFocused: typeof document.hasFocus === "function" ? document.hasFocus() : true,
          clientDtMs: clientDtMs,
          nonce: G.nonce,
          violations: G.pendingViolations.splice(0),
        });
        G.nonce = r.nonce;
        if (r.verdict === "flagged" && !G.stopped) {
          G.onFlagged(r.reasons || []);
        }
      } catch (e) { /* mạng chớp tắt: bỏ qua, nhịp sau thử lại */ }
    };
    // setInterval sẽ bị throttle khi tab ẩn -> đó chính là tín hiệu cho server.
    G.hb = setInterval(tick, interval);
    tick();
  }

  function reportViolation(kind) { G.pendingViolations.push(kind); }

  async function submit(answers) {
    if (!G.available) return null;
    try {
      const r = await api("/submit", { sessionId: G.sessionId, answers: answers || {} });
      return r;
    } catch (e) { return null; }
  }

  function stop() { G.stopped = true; if (G.hb) clearInterval(G.hb); G.hb = null; }

  window.D3Guard = {
    get available() { return G.available; },
    start, submit, stop, reportViolation,
  };
})();
