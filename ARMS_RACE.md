# ARMS RACE LADDER — DEFENSE ⚔ ATTACK

Nhật ký leo thang red/blue. **Nguyên tắc bất biến:** hai bên **mù nhau** —
attack chỉ vá **API chuẩn trình duyệt**, defense chỉ dò **dấu hiệu can thiệp
chung chung**, không bên nào biết nội bộ của bên kia.

Luật thắng/thua mỗi vòng:
- **Attack thắng** nếu mở trang (có extension) mà **không bị auto-nộp vì can thiệp** → thí sinh gian lận trót lọt.
- **Defense thắng** nếu **phát hiện can thiệp → auto-nộp ngay** (chính sách hiện tại: **1 vi phạm = out**).

---

## Vòng 0 — xuất phát
| Bên | Bản | Cơ chế |
|---|---|---|
| 🛡️ DEFENSE | d1 | Theo dõi visibility/blur/fullscreen/keydown + watchdog dùng `Function.prototype.toString` để dò API bị vá. |
| 🗡️ ATTACK | v1 | Vá getter trên prototype + giả `toString` của từng hàm (own-property). |

**Kết quả:** ATTACK v1 **THUA**. Defender dùng `Function.prototype.toString.call(fn)`
(bỏ qua own-property `toString` của hàm) → vẫn thấy mã không phải `[native code]`
→ **BẮT** được việc vá `addEventListener`. → auto-nộp.

---

## Vòng 1 — ATTACK nâng cấp → v2 (tàng hình toString)
**Ý tưởng:** thay thẳng `Function.prototype.toString` bằng bản giả: hàm nào thuộc
tập hook của mình thì trả `"[native code]"`, còn lại gọi bản thật.

→ Mọi detector dựa trên `toString()` ở **realm chính** đều bị lừa.

**Kết quả đo được (mô phỏng lõi, đã test):**
```
ATTACK v2  vs  DEFENSE v1  →  QUA MẶT ✅ (attack thắng)
```
`naive_sees_native = {AEL:true, vis:true}` → defender tưởng mọi thứ còn nguyên bản.

---

## Vòng 2 — DEFENSE nâng cấp → d2 (dò chéo qua iframe realm)
**Ý tưởng:** tạo một `<iframe>` same-origin mới → nó có **realm built-in riêng,
chưa bị ai vá**. Dùng `iframe.contentWindow.Function.prototype.toString` (bản sạch)
để soi lại các hàm của window chính. Vì attack chỉ vá realm chính (chưa đụng iframe
mới), bản `toString` sạch này **soi xuyên được** lớp nguỵ trang.

Đồng thời đổi chính sách: **1 vi phạm = out ngay** (bỏ cơ chế 3 cảnh cáo).

**Kết quả đo được (đã test):**
```
ATTACK v2  vs  DEFENSE v2  →  BỊ BẮT ✅ (defense thắng)
realm_sees_native = {AEL:false, vis:false, FnToString:false}   // lộ hết
1-strike auto-submit: 1 blur → nộp ngay (đã verify)
```

---

## Vòng 3 — DEFENSE nhảy thẳng sang d3 (server-authoritative)

**Quyết định có chủ đích:** KHÔNG build tiếp ATTACK v3.

Về mặt kỹ thuật, để qua mặt d2 thì attack chỉ cần vá mọi realm iframe mới
(hook `createElement`/`appendChild` hoặc chặn getter `contentWindow`). Nhưng đó
là bước biến đòn kiểm thử thành **công cụ vượt proctoring tổng quát, tàng hình,
chạy trên mọi nền tảng thi thật** — vượt khỏi phạm vi lab. Nên ta dừng leo thang
phía tấn công, **giữ ATTACK v2 làm đối thủ cố định**, và nâng phòng thủ tới điểm
mà *không cần* chạy đua tàng hình vẫn thắng: **dời điểm tin cậy sang server.**

### 🛡️ DEFENSE d3 — tín hiệu KHÔNG spoof được
- Client gửi **heartbeat đều đặn** lên server (`defense-server/server.py`).
- Khi tab bị ẩn, trình duyệt **thật sự throttle** `setInterval`/`rAF` → beacon tới
  **trễ**. Extension có spoof `visibilityState='visible'` thì server vẫn thấy
  **mâu thuẫn: nhịp khựng nhưng khai 'visible'** → **gắn cờ**.
- **Chấm điểm ở server** (đáp án không bao giờ gửi cho client) → client có bị vá
  cỡ nào thì điểm/kết luận vẫn do server quyết.
- Nonce-chain mỗi beacon → vá/replay kênh báo cáo cũng bị phát hiện.

**Kết quả đo được (đã test bằng server thật):**
```
A) Thí sinh sạch (nhịp đều, tab hiện)          -> flagged: False   (hợp lệ)
B) Thí sinh bị vá (ATTACK v2, khai 'visible'
   nhưng beacon khựng 5005ms khi rời tab)      -> flagged: True ✅
   lý do: "heartbeat khựng 5005ms nhưng client khai 'visible' => tamper"
E2E trong trình duyệt: session mở, heartbeat chạy, submit -> server chấm & xác nhận. OK.
```

→ **DEFENSE d3 THẮNG** kể cả trước hướng tấn công tàng hình hơn, vì nó không dựa
vào việc "soi mã client" nữa.

## Vòng 4 — DEFENSE siết d3 → d4 (bỏ báo nhầm) · ATTACK thành test-harness

**Bối cảnh:** d3 đã thắng về cấu trúc, nhưng soi kỹ logic chấm lộ ra **2 lỗ chính
xác** (không phải lỗ bảo mật, mà là chất lượng phán quyết):

1. **Báo nhầm lag ↔ throttle.** d3 cờ ngay khi `gap > 3500ms && khai 'visible'`.
   Nhưng tab **đang hiện** gặp **nghẽn mạng thật > 3.5s** tạo **wire-signature GIỐNG
   HỆT** "tab ẩn + khai visible" → server không phân biệt được → **1 cú lag thoáng
   qua bị kết án**, mà cờ lại **sticky** → oan cả phiên.
2. **Nhánh im lặng chết.** `SILENCE_MS = 8000` khai báo nhưng `handle_beacon` không
   dùng → rời/đóng tab > 8s không có lý do cờ riêng.

> **Quyết định (tiếp nối Vòng 3):** KHÔNG leo thang tàng hình phía tấn công (v3).
> Thay vào đó biến `attack/content.js` thành **test-harness** đo độ chính xác của d3,
> rồi dồn sức **làm cứng phán quyết server**. ATTACK v2 giữ nguyên ở
> `attack/versions/content.v2.js` làm đối thủ tham chiếu.

### 🛡️ DEFENSE d4 — chấm theo ĐỘ DÀI bất thường, không theo 1 cú khựng
- **Lag vs throttle:** khựng-khi-'visible' phải **lặp lại ≥ `GAP_STRIKES_NEEDED` (=3)
  nhịp liên tiếp** mới kết luận tamper. 1-2 cú lag lẻ → chưa đủ → **ok** (sửa
  false-positive). Tab ẩn thì khựng **liên tục** → đủ strike → cờ.
- **Im lặng:** `gap > SILENCE_MS` → cờ "nghi rời/đóng tab" (độc lập 'visible').
- **`clientDtMs` (tín hiệu mới):** `guard-server.js` gửi Δ `performance.now()` giữa 2
  nhịp. Tab ẩn → `setInterval` bị throttle → delta **giãn ra dù visibility bị spoof**.
  Server dùng để **RAISE** cờ khi "đồng hồ client bị ghì mà vẫn khai visible" → bắt
  được cheat **không** giả `clientDtMs` (vd ATTACK v2, vốn không đụng beacon).
  **Giới hạn thừa nhận:** `clientDtMs` do client khai nên **giả được** → chỉ dùng để
  RAISE, KHÔNG để gỡ nghi; cheat khai nhỏ thì **nhịp server (2b) lo**.

### 🔁 Chính sách GIÁM SÁT LIÊN TỤC (bỏ auto-nộp)
- **Không còn auto-nộp khi phát hiện vi phạm.** Mỗi phát hiện (client watchdog hoặc
  server) = **+1 strike** và **vào bảng log** `#monitor` hiển thị tại chỗ.
- Đủ **`maxStrikes = 3`** → **CHỐT CỜ** phiên (banner đỏ + báo server) nhưng **vẫn cho
  làm bài** và watchdog **tiếp tục** ghi log các phát hiện sau. Không khoá, không nộp.
- Chỉ nộp khi **hết giờ** hoặc **thí sinh tự bấm nộp**. (Chấm/kết luận vẫn ở server.)

### 🧪 Test-harness (thay HUD attack cũ)
Bọc `fetch` ở tầng wire (không vá DOM, **không tàng hình**, chỉ top-frame). Công tắc
từng kịch bản + in verdict server mỗi beacon ra console (`__HARNESS__.help()`):

| Kịch bản | Mô phỏng | Kỳ vọng d4 |
|---|---|---|
| `lag` / `jitter` | 1 cú khựng (tab hiện) | **ok** — không báo nhầm |
| `sustainedThrottle` | khựng ~4.2s **liên tục** + khai 'visible' | **flagged** (TP thật) |
| `spoofClientClock` | nói dối `clientDtMs=1000` | ghép sustained → **vẫn flagged** nhờ (2b) |
| `longSilence` | im > 8s | **flagged** (SILENCE_MS) |
| `nonceReplay` / `dupBurst` / `contradictFocus` | phá nonce-chain / nhân bản / mất focus | **flagged** |

### Kết quả
```
server.py: py_compile OK.
Kỳ vọng thiết kế — CHƯA chạy E2E sống trong môi trường soạn thảo (không có node,
bị chặn serve). CẦN verify trên máy khi reload extension + chạy harness:
  lag (1 cú)            -> ok        (d3 từng flag; d4 phải hết oan)
  sustainedThrottle     -> flagged   sau ~GAP_STRIKES_NEEDED nhịp
  sustained + spoofClock-> flagged   (2c bị né, 2b vẫn bắt)
  longSilence           -> flagged   "nghi rời/đóng tab"
```

**Bài học Vòng 4:** mọi **scalar do client khai** (visible, focus, cả `clientDtMs`)
đều **giả được** → tín hiệu tin cậy duy nhất là **nhịp tới server tự đo**; phân biệt
lag ↔ throttle phải dựa vào **độ dài/độ lặp** của bất thường, không phải một mẫu đơn lẻ.

---

## Kết luận arms-race
> Client-side chỉ **nâng chi phí** cho kẻ gian; ai kiểm soát realm trước (extension
> `document_start`) có lợi thế cấu trúc, nên cuộc đua tàng hình thuần client **không
> có điểm dừng chắc thắng**. Lối ra đúng là **xác thực ở server** bằng tín hiệu
> không giả được + chấm điểm phía server. Đó là lý do d3 là nước đi cuối hợp lý.

---

### Cách chạy d4 (local / Kali)
```bash
# 1) server xác thực (in "[DEFENSE d4] …")
python3 defense-server/server.py 8799

# 2) phục vụ web (thư mục defense).
#    app.js ĐÃ trỏ CONFIG.server = "http://localhost:8799"
#    (đặt null nếu muốn deploy tĩnh GitHub Pages — khi đó về chế độ d2 client-only)
python3 -m http.server 8000 --directory defense

# 3) nạp test-harness: chrome://extensions → Load unpacked → attack/ → Reload
#    rồi mở http://localhost:8000, F12, gõ __HARNESS__.help()
```

### Lịch sử phiên bản (lưu trên USB)
```
attack/content.js              = D3/D4 TEST HARNESS (đo chính xác, KHÔNG tàng hình)
attack/versions/content.v1.js  = ATTACK v1
attack/versions/content.v2.js  = ATTACK v2 (đối thủ tham chiếu, bản lưu)
defense/app.js                 = DEFENSE (1-strike + cross-realm + hỗ trợ server)
defense/guard-server.js        = client beacon layer (d4: gửi thêm clientDtMs)
defense-server/server.py       = DEFENSE d4 server-authoritative (Python stdlib)
defense/versions/app.d2.js     = DEFENSE d2 (bản lưu)
```
