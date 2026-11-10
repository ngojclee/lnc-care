# LNC Care — giải thích plan dễ hiểu + các phương án (cho owner)

Ngày: 2026-10-26. Trạng thái: **chưa viết code**, đang ở Phase 0 (bằng chứng +
quyết định). File này dùng để owner đọc trước khi duyệt hướng triển khai.
Plan kỹ thuật đầy đủ: `plan.md`. Checklist: `task.md`.

## 1. Bài toán thực tế

- Comment rải rác trên **14 Facebook Page + 3 Instagram professional** —
  không có chỗ nào nhìn gộp; comment cũ bị chìm, không ai biết cái nào chưa trả lời.
- **Không có lịch sử hiệu quả bài post**: reach/tương tác hôm nay vs tuần trước?
  Meta không giữ cho mình kiểu "bảng theo ngày".
- **Không có bằng chứng đã đăng gì**: bài bị sửa/xóa là mất media + caption gốc.
- **Không có audit**: ai reply cái gì, lúc nào, bằng tài khoản nào.
- **Agent AI không đọc được inbox** vì không có MCP tool nào trong Hub.

## 2. Plan làm gì — 6 việc, nói đơn giản

| # | Việc | Bản chất |
|---|---|---|
| 1 | **Ingest** | Kéo post + comment về SQLite của mình qua Graph API chính thức — webhook (realtime) + polling (bù, backfill 90 ngày). Không dò trình duyệt. |
| 2 | **Snapshot hàng ngày** | Mỗi post: reach, reactions, comments, shares, saves, plays. Mỗi kênh: followers. → biểu đồ xu hướng, so tuần/tháng. |
| 3 | **Archive** | Mỗi post lưu: caption + file media (tải từ `media_url` của API) + permalink + **screenshot** trang public. Bài bị xóa/sửa vẫn còn bằng chứng. |
| 4 | **Inbox** | Comment có trạng thái: new → needs_reply → replied / hidden / ignored. Giao việc, ghi chú, rule gắn cờ từ khóa (khiếu nại, giá, đơn hàng). |
| 5 | **Reply có duyệt** | Mọi reply/ẩn tạo **draft** trước; operator duyệt rồi mới gửi. Idempotency key chống gửi trùng. Audit log ai duyệt ai gửi. Mặc định `draft_only` (owner đã chọn). |
| 6 | **Connector `care__*`** | Agent qua Business MCP Hub: đọc inbox, tạo draft, đọc stats. Không có scope `care:write:meta` thì không gửi được gì. |

**Không làm** (non-goals): đăng bài/lịch (Postiz lo), tin nhắn riêng DM
(khác scope — loại Chatwoot nếu cần sau), track kênh đối thủ (SocialTrak lo),
comment trên ads (Phase 5), auto-reply AI (chỉ draft, Phase 5).

## 3. Kiến trúc — nói đơn giản

```
Meta webhook ──► /webhooks/meta (kiểm chữ ký HMAC) ──► hàng đợi jobs ──► fetcher ──► SQLite
Polling (backfill + snapshot hằng ngày) ──────────────────────────────► fetcher ──► SQLite
                                                                                 │
  lnc-care  (API + UI /admin + /mcp) ◄──────────── đọc ────────────────────────────┘
  lnc-care-worker ◄── jobs: tải media, chụp screenshot (Playwright headless)
```

- **2 service cùng 1 image** trong một Portainer stack: app (nhẹ, filesystem
  read-only như lnc-ads) + worker (Chromium, chỉ chạy job nền, không có port public).
  Webhook/UI không bao giờ phải chờ browser.
- **Vault AES-GCM** với `LNC_MASTER_KEY` — giống hệt lnc-ads; token OAuth của
  care cấp riêng, không share với app khác.
- **Credentials không bao giờ** lộ trong MCP args, Git, logs, chat.

## 4. Các phase

| Phase | Nội dung | Cửa |
|---|---|---|
| 0 | Bằng chứng + quyết định (đang ở đây) | Probe xong 2026-10-26 |
| 1 | Ingest + inbox chạy local, test offline | Scaffold từ lnc-ads patterns |
| 2 | Webhook realtime + worker archive/screenshot | Public path verify chữ ký |
| 3 | Reply/hide/private reply có duyệt + audit | Mỗi write cần approval + idempotency |
| 4 | Release: gitea, Portainer, NPM `care-mcp.lengoc.me`, Hub connector | Owner duyệt từng bước |
| 5 | Later: comment trên ads, AI draft reply, Threads, báo cáo tuần | — |

## 5. Các phương án khả dĩ (đã khảo sát + probe thực tế)

| Phương án | Là gì | Ưu | Nhược | Đáp ứng mục tiêu? |
|---|---|---|---|---|
| **A. Build đủ theo plan** | App riêng Shape 0 + Hub connector | Đúng 6 mục tiêu; tái dùng pattern lnc-ads đã chạy live; data ở server mình; audit + MCP cho agent | Nhiều việc nhất (Phase 1–3); mình tự maintain | Đầy đủ |
| **A-lite. Build rút gọn** | Chỉ polling + ingest + inbox + snapshot + archive media (không webhook Phase 1, không screenshot, chưa writes) | Nhanh ra bản dùng được; vẫn đọc comment + stats + archive qua API; ít rủi ro | Không realtime; reply vẫn tay trên Meta | ~80% mục tiêu, mở đường nâng dần lên A |
| **B. Meta Business Suite** | Inbox miễn phí của Meta | Không cần build; official; có app mobile | Không có API/MCP cho agent; không snapshot lịch sử; không archive media; không audit; comment cũ vẫn chìm | ~30% — chỉ inbox thủ công |
| **C. Community MCP** (mcp-meta-inbox, meta-mcp-server…) | MCP mã nguồn mở wrap sẵn Graph API | Dùng thử nhanh; cùng API | **Vẫn cần đúng permission y hệt** — không có đường tắt phía Meta; không vault/Hub/audit/snapshot/archive; bảo trì rủi ro; hosted thì data qua bên thứ ba | ~40%, tham khảo code được |
| **D. Postiz unified inbox** | Postiz vừa thêm inbox (2025–26, còn non) | Không service mới; kênh đã kết nối | Coverage chưa rõ/mới; không snapshot/screenshot/audit/Hub; trộn token care vào Postiz dễ vỡ | ~30–40%, chưa chứng minh |
| **E. Hosted SaaS** (Modiva, dmswift…) | MCP host bên ngoài | Nhanh nhất | Data/comment đi qua bên thứ ba; phí; vẫn không snapshot/archive/audit của mình | Loại — mất kiểm soát data |
| **F. Chatwoot** | Inbox DM | Mature, MIT | Chỉ Messenger/IG **DM**, không phải comment bài post | Không đúng bài toán |

**Bằng chứng probe 2026-10-26** (token lnc-ads, live):
- Đọc được ngay: 14 Page + page token, `published_posts`, followers FB+IG.
- Thiếu scope (owner sẽ thêm): `pages_read_user_content` (đọc comment),
  `pages_manage_metadata` (đăng ký webhook), `read_insights` (post stats),
  `instagram_basic` (IG media), + 3 quyền cho Phase 3 writes.
- Postiz dùng **app Meta khác** (`39303237442608473` vs `1821062268930458`)
  → share app lnc-ads không đụng webhook Postiz.

## 6. Điểm cần owner cân nhắc

1. **A đủ hay A-lite?** A-lite = Phase 1 + phần đọc của Phase 2, bỏ webhook +
   screenshot + writes sang sau. Vẫn giữ kiến trúc để nâng lên A đủ.
2. **Screenshot archive**: giữ (worker riêng, chỉ permalink public, không login)
   hay bỏ hẳn? API media archive đã đủ "bằng chứng nội dung"; screenshot là
   "bằng chứng hiển thị".
3. **TikTok/YouTube**: V1 chỉ FB+IG (đã chốt). TikTok business cần scope
   riêng trên app `LNC Ads` — đang chờ duyệt, làm sau.
4. **Tài khoản cá nhân**: không có API chính thức cho personal profile —
   nằm ngoài mọi phương án (Meta không cho, kể cả tool trả phí).
5. **Ai approve draft** trong inbox: mặc định owner; có thể thêm operator
   khi app có user model — hiện UI là management-key đơn như lnc-ads.

## 7. Tài khoản cá nhân + các platform khác + nguồn học

### 7.1 Tài khoản cá nhân — sự thật theo platform (kiểm chứng 2026-10-26)

| Platform | Cá nhân đọc comment được không? | Đường hợp lệ |
|---|---|---|
| Facebook profile (kể cả professional mode) | **KHÔNG** — Graph API không có surface nào cho profile cá nhân (Meta gỡ `publish_actions`/`user_posts` từ v3.0/2018 và chưa trả lại; mọi scheduler thứ ba đều xác nhận điều này) | Chuyển hoạt động sang **Page** — "Lê Ngọc" trong list đã là Page nên track được |
| Instagram cá nhân | **KHÔNG** | Convert sang **professional account** (miễn phí, giữ nguyên followers) rồi link vào Page |
| TikTok cá nhân (creator) | **KHÔNG** — Display API chỉ cho `comment_count`, không có text comment; Research API chỉ cho học thuật | Convert sang **business account** → dùng TikTok API for Business (`/business/comment/*`) — đang trong plan Phase 3 |
| YouTube channel cá nhân | **CÓ** — Data API `commentThreads.list`, `comments.insert`, `setModerationStatus`; quota 10k units/ngày | OAuth `youtube.force-ssl` — Phase 3+ |
| Threads | Có cho tài khoản mình | `threads_read_replies`, `threads_manage_replies` — cần App Review |
| Pinterest | Có cho tài khoản mình | API v5 standard — chưa trong plan, thêm được sau |
| X/Twitter | Có nhưng **trả phí** — tier đọc ý nghĩa ~$200/tháng | Ngoài plan; quyết sau |
| LinkedIn cá nhân | Thực tế không | API bị khóa chặt — bỏ qua |
| Google Business Profile | Có (reviews) | GBP API — chỉ nếu anh có listing cần trả lời review |

**Kết luận:** "care tài khoản cá nhân" chỉ khả thi trên **YouTube channel** và
**Pinterest**. FB/IG/TikTok cá nhân là giới hạn cứng của platform — mọi tool
trả phí cũng không vượt được; cách hợp lệ duy nhất là convert sang Page /
professional / business account (miễn phí và nhanh).

### 7.2 Platform khác ngoài FB+IG — thứ tự khả thi

1. **TikTok business** — sẵn trong plan Phase 3; API đầy đủ (video list +
   comment list/reply/hide + webhook `comment.update`); chờ scope
   *TikTok Accounts* trên app `LNC Ads` được duyệt.
2. **YouTube** — dễ nhất sau Meta: một OAuth Google riêng, quota ngày.
3. **Threads** — API có nhưng cần App Review; ít comment hiện nay.
4. **GBP reviews** — chỉ khi có listing.
5. X/Twitter, LinkedIn — chi phí/giới hạn → không đề xuất V1.

### 7.3 "Nền sẵn" — mình có gì rồi

Build **tự làm trên nền đã có**, không phải từ con số 0:

- `lnc-ads` **đang chạy live**: vault AES-GCM, OAuth flow, delegation Hub,
  UI admin, schema org/shop — care copy *pattern*, không import.
- Meta app `1821062268930458` **Live** + token verified + `business_management`
  đã granted — care chỉ thêm scope vào cùng app.
- `business-mcp-hub` container đang chạy; contract connector đã chứng minh
  qua lnc-ads (v3/v4 HMAC delegation).
- `SocialTrak`: snapshot-table design + bài học Playwright-trong-Docker.
- `lnc-postiz`: cách đọc inventory channel Postiz (tham khảo, không phụ thuộc).
- Hạ tầng: host `10.21.4.101`, NPM FR, internal-dns, Portainer — sẵn hết.

### 7.4 MCP có sẵn để học (đọc, không cài)

| Nguồn | Học gì |
|---|---|
| `pauloFroes/mcp-meta-inbox` | Tool-shape cho đúng domain: list_posts, list_comments, reply_to_comment, hide_comment, private_reply — gần nhất với care |
| `oliverames/meta-mcp-server` | 52 tools Page — tham khảo field/endpoint/insights metric names |
| Postiz native MCP | Đã consume qua `lnc-postiz` — mẫu upstream MCP thật trong fleet |
| `fbsamples/graph-api-webhooks-samples` (official) | Webhook receiver chuẩn Meta (challenge + signature) |
| `facebook-python-business-sdk`, `tiktok-business-api-sdk` | Field names chính thức |
| PostStack, Mixpost (quarantine copy) | Semantics inbox: approval-first, permission matrix — đọc theo README-QUARANTINE |

Không có official Meta MCP cho organic (MCP chính thức của Meta chỉ phía ads)
→ không có đường tắt "cắm MCP có sẵn là xong": permission Meta vẫn phải tự
xin, còn vault/Hub/audit/snapshot/archive thì tool ngoài không có.

### 7.5 Nếu vẫn muốn care cả tài khoản cá nhân — các lane khả dĩ

Không có API chính thức, nhưng có lane khác. **Nguyên tắc: personal chỉ
READ, không WRITE** — reply/comment qua browser automation có nguy cơ
checkpoint/khóa tài khoản cá nhân (Meta detect automation rất nhanh), và
tài khoản cá nhân là tài sản quan trọng. Reply bằng tay trên app chính chủ.

| Lane | Cách làm | Được gì | Mất/rủi |
|---|---|---|---|
| **P1 — Convert (khuyến nghị)** | FB profile → dùng Page; IG → professional; TikTok → business. Miễn phí, nhanh | Đủ API: comments + reply + webhook + insights + screenshot public + BAUPA | Phải chuyển thói quen đăng bài sang Page/account business |
| **P2 — Browser read-only** | `lnc-scrapling` (shared cookies `F:\_agentsync\.secrets\social\`) + `lnc-browser` fallback — pattern đã có ở `lnm-facebook-nail-scraper`/`lnm-instagram-nail-scraper`. Đọc notifications page + comment trên bài của mình → ingest `channel.kind=personal_profile`, cờ `read_only` | Không cần convert; thấy comment profile cá nhân | Fragile: selector đổi, cookie hết hạn, checkpoint; comment friends-only → screenshot public không xem được; KHÔNG reply |
| **P3 — Email notification** | FB/IG gửi email khi có comment → parse qua Gmail MCP (đã có trong fleet) → ingest read-only | Không ban risk, không browser | Chỉ có những gì email báo; không backfill, không full thread |
| **P4 — Để ngoài V1** | Không làm gì | 0 effort | Profile cá nhân vẫn mù |

**Quyết định của owner (2026-10-26):** chọn **P2 cho personal profiles** —
không convert sang Page, không làm email lane. Tất cả kênh khác giữ
official API. Lane browser chạy trên `lnc-scrapling` (đã là connector Hub,
Playwright sẵn trong container) + `lnc-browser` fallback, dùng shared
cookies `F:\_agentsync\.secrets\social\` — fleet đã có hết, không dựng mới.

**Cách kiến trúc hỗ trợ** (không làm bẩn core API): `channels` có field
`adapter` ∈ {`meta_api`, `browser_ingest`} — inbox UI và comment_states
giống hệt nhau, chỉ khác nguồn dữ liệu và tập action được phép (browser
lane: chỉ read + flag, reply button bị disable với hint "trả lời trên app
chính chủ"). Lane này vào **Phase 2b** — sau khi ingest API chạy ổn, trước
writes — vì nó fragile và cần nghiên cứu ổn định trước.

**Nghiên cứu ổn định cần làm trước khi build lane** (đã ghi vào plan §2b):
session lifetime trên cookies thật, cadence keepalive, nhận diện checkpoint
(login redirect/security page), anomaly detector → auto-pause + alert
Telegram, một session ấm per profile, poll jitter ≥ 30 phút, không burst.

## 8. Khuyến nghị của em

**A-lite → A**: build theo plan nhưng Phase 1 ship bản "đọc" trước
(polling + ingest + inbox UI + snapshot + archive media). Webhook, worker
screenshot và writes đánh giá lại sau khi inbox chạy thật. Lý do: phần giá
trị lớn nhất (nhìn gộp + lịch sử + archive + agent đọc được) nằm ở reads —
đó cũng là phần permission dễ nhất (đã probe: chỉ thiếu 4 scope đọc).
Writes là phần rủi ro public nhất, để sau khi hệ thống đáng tin.
