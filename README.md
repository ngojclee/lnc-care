# LNC Care (`lnc-care`)

Native **Rust (`Axum 0.7` + `Rusqlite 0.32` WAL)** care console for owned social channels (Facebook Pages, Instagram Business accounts, TikTok Business, YouTube) with:

- **Split-Pane Triage & Consultation Inbox (`/admin/#inbox`)**: Top bucket pills, full-width priority comment queue, `0–100` score bar with `Auto-suggest threshold 80`, 12-label probability rubric, `[✓]` / `[✕]` human calibration, and **Evaluate → Reason → Consult** Public Reply + Private DM Consultation studio.
- **Forensic Evidence Vault (`/admin/#evidence`)**: 5-layer preservation (immutable numerical `actor_uid`/`post_id`/`comment_id`, `ALL_COMMENTS` thread expansion, full-page PNG + `.mhtml` DOM + `.har` trace, original media, SHA-256 `manifest.json` + `.zip` bundle + `+6h/+24h/+72h` deletion watchdog).
- **Multi-Account Fleet (`/admin/#fleet`)**: 1:1 profile & residential proxy registry across `meta_api`, `veilbrowser` (Camoufox 152 + Xray TUN), and `orbine_mobile` (Physical ARM64 + Xray TPROXY) with structural write-guards (`channel_adapter_unsupported`) on `personal_main` accounts.
- **Ecosystem Alignment (`LNC-Agent-Hub` + `Business MCP Hub` + `LNC Ads`)**: Shared Platform Vault (`/v1/platform/*`) with 900s encrypted local SQLite lease cache (`AES-256-GCM`), automatic LAN bridge fallback (`:8480`), 3-way Universal SSO (`lnc_sso_*` + HMAC peer tickets), outbound stateful `McpGatewayClient` (`Mcp-Session-Id`), and inbound `/mcp` (`26` `care__*` tools, Business MCP Hub v3/v4 HMAC + SQLite nonce replay guard).

## CLI & Local Tests

```bash
# Run full contract & unit test suite (20 tests)
cargo test

# Run HTTP server (default port 8000), background worker, healthcheck, or Vault rotation
cargo run -- serve
cargo run -- worker
cargo run -- healthcheck
cargo run -- rotate-vault --new-key <64-hex-key>
```
