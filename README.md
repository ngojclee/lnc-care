# LNC Care (`lnc-care`)

Care console for owned social channels (Facebook Pages, Instagram Business accounts, TikTok Business, YouTube) with:

- **Split-Pane Triage & Consultation Inbox (`/admin/#inbox`)**: Inspired by `Friend Triage` — top bucket pills, priority comment queue, `0–100` score bar with `Auto-suggest threshold 80`, 12-label probability rubric (`Muốn mua`, `Hỏi giá`, `Mẫu & size`, `Vận chuyển`, `Khen ngợi`, `Xây dựng`, `Tích cực`, `Lịch sự`, `Khiếu nại`, `Tiêu cực`, `Nghi clone/spam`, `Miệt thị / Bôi nhọ`), `[✓]` / `[✕]` human calibration, and **Evaluate → Reason → Consult** Public Reply + Private DM Consultation studio.
- **Forensic Evidence Vault (`/admin/#evidence`, "Lập vi bằng số")**: 5-layer preservation (immutable numerical `actor_uid`/`post_id`/`comment_id`, `ALL_COMMENTS` thread expansion, full-page PNG + `.mhtml` DOM + `.har` trace, original media, SHA-256 `manifest.json` + `.zip` bundle + `+6h/+24h/+72h` deletion watchdog).
- **Multi-Account Fleet (`/admin/#fleet`)**: 1:1 profile & residential proxy registry across `meta_api`, `veilbrowser` (Camoufox 152 + Xray TUN), and `orbine_mobile` (Physical ARM64 + Xray TPROXY) with structural write-guards (`channel_adapter_unsupported`) on `personal_main` accounts.
- **Business MCP Hub Connector (`/mcp`, `care__*`)**: Audience `lnc-care`, HMAC-SHA256 v3/v4 delegation verification, single-use nonce replay guard, and guarded provider write tools.

## Local Development & Tests

```bash
python -m pytest -v
```
