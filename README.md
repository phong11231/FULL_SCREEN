# Red/Blue Lab — DEFENSE_v1.0 + ATTACK_v1.0

Bộ lab kiểm thử phòng thủ phía client. **Chỉ dùng cho mục đích kiểm thử/giáo dục
trên hệ thống của chính bạn.** Hai thành phần **tách rời hoàn toàn**:

```
redblue-lab/
├─ defense/            # WEB PHÒNG THỦ — push GitHub / deploy đâu cũng chạy
│  ├─ index.html
│  ├─ style.css
│  ├─ app.js           # DEFENSE d3: 1-strike + cross-realm + hỗ trợ server
│  └─ guard-server.js  # lớp beacon cho chế độ server (d3)
├─ defense-server/
│  └─ server.py        # DEFENSE d3 — server-authoritative (Python stdlib)
├─ attack/             # EXTENSION TẤN CÔNG — tự chạy khi mở web (ATTACK v2)
│  ├─ manifest.json
│  ├─ content.js
│  └─ popup.html
└─ ARMS_RACE.md        # nhật ký leo thang red/blue từng vòng
```

> Chi tiết các vòng tấn công/phòng thủ và kết quả đo: xem **ARMS_RACE.md**.
> Mặc định web chạy chế độ **d2** (client-only) cho GitHub Pages tĩnh; bật **d3**
> bằng cách chạy `defense-server/server.py` và đặt `CONFIG.server` trong `app.js`.

## 1) Chạy web phòng thủ (DEFENSE_v1.0)
- Mở thẳng `defense/index.html`, hoặc chạy server tĩnh:
  ```
  cd defense
  python3 -m http.server 8000      # http://localhost:8000
  ```
- Hoặc push thư mục `defense/` lên GitHub → bật **GitHub Pages**. Không có URL
  cứng trong code nên deploy nền tảng nào cũng chạy.
- Mở Console (F12) sẽ thấy banner `[DEFENSE_v1.0 READY]`. Thử: chuyển tab,
  click ra ngoài, thoát fullscreen, bấm F12/Ctrl+C, dán nhanh → bảng log cập
  nhật trực tiếp. Nút **Export JSON** để xuất log.

## 2) Nạp extension tấn công (ATTACK_v1.0)
- Chrome/Chromium → `chrome://extensions` → bật **Developer mode** →
  **Load unpacked** → chọn thư mục `attack/`.
- Mở lại trang web phòng thủ. Extension **tự inject** ở `document_start`
  (không cần bấm gì). Xem Console: `[ATTACK_v1.0 READY]`, từng kỹ thuật in
  `[PASS_BYPASS]` hoặc `[BLOCKED/DETECTED]`, cuối cùng có `console.table` tổng kết.

## Đổi domain/nền tảng triển khai sau này
Chỉ sửa mảng `matches` trong `attack/manifest.json` (thêm domain mới).
**Không cần sửa logic** `content.js`. Mặc định đã phủ: localhost, `*.github.io`,
`*.pages.dev`, `*.vercel.app`, `*.netlify.app`.

## Bài học cốt lõi
Mọi tín hiệu phòng thủ ở client (visibility, focus, fullscreen, phím tắt) đều
**có thể bị vô hiệu hóa** bằng một extension chạy trong trang. Watchdog toàn vẹn
(integrity) chỉ **nâng chi phí** cho kẻ tấn công, không ngăn tuyệt đối.
➡ **Mọi quyết định quan trọng phải được xác thực lại ở server.**
