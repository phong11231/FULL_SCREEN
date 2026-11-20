#!/usr/bin/env python3
# =====================================================================
# DEFENSE d4 — server.py  (Python stdlib, no deps)
# Server-authoritative proctoring backend for the red/blue lab.
#
# NÂNG CẤP d4 so với d3 (chống báo nhầm + bịt lỗ):
#   • Phân biệt lag-mạng vs throttle bằng ĐỘ DÀI bất thường, không phải 1 cú
#     khựng lẻ: cần khựng-khi-'visible' LẶP LẠI (GAP_STRIKES_NEEDED) mới kết
#     luận. Một cú lag thoáng qua KHÔNG còn bị cờ oan (sửa false positive của d3).
#   • Kích hoạt nhánh im lặng dài (SILENCE_MS) -> nghi rời/đóng tab (d3 bỏ quên).
#   • Dùng clientDtMs (đồng hồ nội bộ client tự đo) để RAISE cờ khi client khai
#     đồng hồ bị ghì mà vẫn 'visible' — nhưng KHÔNG dùng nó để gỡ nghi, vì số
#     này client giả được; tín hiệu gốc vẫn là NHỊP server tự đo.
#
# Why this wins the arms race:
#   A client-only watchdog can always be blinded by an extension that runs
#   first and controls every realm in the page. So d3 moves the TRUST to the
#   server and relies on a signal the page CANNOT spoof: the browser really
#   throttles requestAnimationFrame / timers when a tab is hidden. If the
#   client keeps claiming visibilityState='visible' but its heartbeat cadence
#   stalls, that contradiction = tamper/cheat -> the SERVER flags the session.
#   Grading also happens server-side, so a spoofed client score is worthless.
#
# Endpoints (all JSON, permissive CORS for LAB use only):
#   POST /session/start -> { sessionId, nonce, hbIntervalMs, questions[] }
#   POST /beacon        -> { verdict, nonce, reasons[] }
#   POST /submit        -> { score, max, flagged, reasons[] }
#   GET  /health        -> { ok: true }
#
# Run:  python3 server.py [port]      (default 8799)
# LAB ONLY. Not hardened for production.
# =====================================================================
import json, os, secrets, time, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HB_INTERVAL_MS     = 1000      # client gửi heartbeat mỗi ~1s
GAP_FLAG_MS        = 3500      # 1 nhịp khựng > 3.5s => NGHI (chưa kết luận)
GAP_STRIKES_NEEDED = 3         # d4: cần khựng-khi-'visible' LẶP LẠI 3 lần mới kết luận
                               #     (1-2 cú lẻ = lag thoáng qua, KHÔNG cờ)
SILENCE_MS         = 8000      # im lặng > 8s => nghi rời/đóng tab (cờ ngay)

# Ngân hàng đề (ĐÁP ÁN chỉ nằm ở server — client không bao giờ thấy)
QUESTIONS = [
    {"q": "HTTP mặc định chạy ở cổng nào?", "opts": ["21", "80", "443", "8080"], "correct": 1},
    {"q": "Lệnh Linux xem quyền file?", "opts": ["ls -l", "cat", "cd", "pwd"], "correct": 0},
    {"q": "Tầng nào của OSI lo định tuyến (routing)?", "opts": ["Data Link", "Network", "Transport", "Session"], "correct": 1},
    {"q": "Hàm băm nào ĐÃ bị coi là yếu?", "opts": ["SHA-256", "MD5", "SHA-3", "BLAKE2"], "correct": 1},
    {"q": "XSS tấn công vào đâu?", "opts": ["CSDL máy chủ", "Trình duyệt người dùng", "Router", "Kernel"], "correct": 1},
]

SESSIONS = {}   # sessionId -> state

def now_ms():
    return int(time.time() * 1000)

def public_questions():
    # gửi cho client KHÔNG kèm 'correct'
    return [{"q": x["q"], "opts": x["opts"]} for x in QUESTIONS]

def new_session():
    sid = secrets.token_hex(16)
    nonce = secrets.token_hex(8)
    SESSIONS[sid] = {
        "created": now_ms(),
        "nonce": nonce,          # nonce client phải echo ở beacon kế tiếp
        "last_arrival": now_ms(),
        "last_seq": -1,
        "gap_strikes": 0,        # d4: số nhịp khựng-khi-'visible' LIÊN TIẾP
        "flags": [],             # danh sách lý do bị cờ (không trùng)
        "beacons": 0,
        "closed": False,
    }
    return sid, nonce

def add_flag(st, reason):
    if reason not in st["flags"]:
        st["flags"].append(reason)

def handle_beacon(body):
    sid = body.get("sessionId")
    st = SESSIONS.get(sid)
    if not st:
        return 404, {"error": "unknown session"}

    arrival = now_ms()
    gap = arrival - st["last_arrival"]
    seq = body.get("seq", -1)
    claimed_visible = bool(body.get("claimedVisible", True))
    claimed_focused = bool(body.get("claimedFocused", True))
    echoed = body.get("nonce")
    client_violations = body.get("violations") or []
    client_dt = body.get("clientDtMs", None)   # d4: đồng hồ nội bộ client tự khai

    # (1) Nonce-chain: beacon phải echo đúng nonce server cấp lần trước. (HARD)
    if echoed != st["nonce"]:
        add_flag(st, "nonce-mismatch (kênh báo cáo bị can thiệp/replay)")

    # (2) Nhịp tới (server TỰ đo — không spoof được). Phân biệt lag vs throttle
    #     bằng ĐỘ DÀI bất thường, không phải một cú khựng lẻ.
    if st["last_seq"] >= 0:
        if gap > SILENCE_MS:
            # (2a) im lặng rất lâu -> nghi rời/đóng tab (cờ ngay, độc lập 'visible')
            add_flag(st, f"im lặng {gap}ms (> {SILENCE_MS}ms) => nghi rời/đóng tab")
            st["gap_strikes"] = 0
        elif gap > GAP_FLAG_MS and claimed_visible:
            # (2b) khựng khi khai 'visible' -> cần LẶP LẠI mới kết luận. Lag mạng
            #      thoáng qua chỉ 1 cú rồi hồi; tab ẩn thì khựng LIÊN TỤC.
            st["gap_strikes"] += 1
            if st["gap_strikes"] >= GAP_STRIKES_NEEDED:
                add_flag(st, f"throttle KÉO DÀI {st['gap_strikes']} nhịp "
                             f"(gap≈{gap}ms) nhưng khai 'visible' => tamper "
                             f"(không phải lag thoáng qua)")
        else:
            st["gap_strikes"] = 0   # nhịp hồi phục -> coi như lag thoáng qua

    # (2c) Client TỰ KHAI đồng hồ nội bộ bị ghì mà vẫn 'visible' -> bằng chứng
    #      mạnh (bắt được cheat KHÔNG giả clientDtMs, vd ATTACK v2). LƯU Ý: số này
    #      client giả được -> CHỈ dùng để RAISE, không dùng để gỡ nghi; cheat khai
    #      clientDtMs nhỏ thì để (2b) nhịp-server lo.
    if client_dt is not None and client_dt > GAP_FLAG_MS and claimed_visible:
        add_flag(st, f"đồng hồ client {client_dt}ms bị ghì nhưng khai 'visible' "
                     f"=> tab ẩn/throttle (tamper)")

    # (3) Client tự thú vi phạm (nếu không bị vá) -> cũng cờ. (HARD)
    for v in client_violations:
        add_flag(st, f"client-reported: {v}")

    # (4) Mất focus theo khai báo -> cờ (chính sách 1-strike). (HARD)
    if not claimed_focused:
        add_flag(st, "client khai mất focus")

    st["last_arrival"] = arrival
    st["last_seq"] = seq
    st["beacons"] += 1
    st["nonce"] = secrets.token_hex(8)   # cấp nonce mới cho beacon kế

    flagged = len(st["flags"]) > 0
    return 200, {
        "verdict": "flagged" if flagged else "ok",
        "nonce": st["nonce"],
        "reasons": st["flags"],
        "gapMs": gap,
        "gapStrikes": st["gap_strikes"],
        "clientDtMs": client_dt,
    }

def grade(answers):
    score = 0
    for i, item in enumerate(QUESTIONS):
        if str(i) in answers and answers[str(i)] == item["correct"]:
            score += 1
        elif i in answers and answers[i] == item["correct"]:
            score += 1
    return score

def handle_submit(body):
    sid = body.get("sessionId")
    st = SESSIONS.get(sid)
    if not st:
        return 404, {"error": "unknown session"}
    st["closed"] = True
    answers = body.get("answers") or {}
    score = grade(answers)           # CHẤM Ở SERVER
    flagged = len(st["flags"]) > 0
    return 200, {
        "score": score,
        "max": len(QUESTIONS),
        "flagged": flagged,
        "reasons": st["flags"],
    }

class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        payload = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        # CORS mở — CHỈ dùng trong lab
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self):
        self._send(204, {})

    def do_GET(self):
        if self.path.startswith("/health"):
            return self._send(200, {"ok": True, "sessions": len(SESSIONS)})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self._send(400, {"error": "bad json"})

        if self.path.startswith("/session/start"):
            sid, nonce = new_session()
            return self._send(200, {
                "sessionId": sid, "nonce": nonce,
                "hbIntervalMs": HB_INTERVAL_MS, "questions": public_questions(),
            })
        if self.path.startswith("/beacon"):
            code, obj = handle_beacon(body)
            return self._send(code, obj)
        if self.path.startswith("/submit"):
            code, obj = handle_submit(body)
            return self._send(code, obj)
        self._send(404, {"error": "not found"})

    def log_message(self, *a):
        pass   # im lặng

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8799
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"[DEFENSE d4] server-authoritative proctoring on http://localhost:{port}")
    print(f"  endpoints: POST /session/start · POST /beacon · POST /submit · GET /health")
    print(f"  hbInterval={HB_INTERVAL_MS}ms gapFlag={GAP_FLAG_MS}ms "
          f"strikesNeeded={GAP_STRIKES_NEEDED} silence={SILENCE_MS}ms  (LAB ONLY)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[DEFENSE d4] stopped.")

if __name__ == "__main__":
    main()
