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

## Kết luận arms-race
> Client-side chỉ **nâng chi phí** cho kẻ gian; ai kiểm soát realm trước (extension
> `document_start`) có lợi thế cấu trúc, nên cuộc đua tàng hình thuần client **không
> có điểm dừng chắc thắng**. Lối ra đúng là **xác thực ở server** bằng tín hiệu
> không giả được + chấm điểm phía server. Đó là lý do d3 là nước đi cuối hợp lý.

---

### Cách chạy d3 (local / Kali)
```bash
# 1) server xác thực
python3 defense-server/server.py 8799

# 2) phục vụ web (thư mục defense), rồi sửa trong app.js:
#    CONFIG.server = "http://localhost:8799"   (đang để null cho GitHub Pages tĩnh)
python3 -m http.server 8000 --directory defense
```

### Lịch sử phiên bản (lưu trên USB)
```
attack/content.js              = ATTACK v2 (đối thủ cố định)
attack/versions/content.v1.js  = ATTACK v1
attack/versions/content.v2.js  = ATTACK v2 (bản lưu)
defense/app.js                 = DEFENSE d3 (1-strike + cross-realm + hỗ trợ server)
defense/guard-server.js        = client beacon layer cho d3
defense-server/server.py       = server-authoritative backend (Python stdlib)
defense/versions/app.d2.js     = DEFENSE d2 (bản lưu)
```
