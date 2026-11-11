//! Prompt-injection-isolated comment collector, 12-label rubric evaluator, and consultation reasoner.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use regex::{Regex, RegexBuilder};
use rusqlite::{params, Connection};
use serde_json::{json, Value};

use crate::store::{query_maps, query_one_map};

pub const RUBRIC_VERSION: &str = "v1.2-triage";

pub const RUBRIC_LABELS: &[(&str, &str, &str, &str)] = &[
    ("purchase_intent", "Muốn mua", "Purchase intent", "positive"),
    ("price_inquiry", "Hỏi giá", "Price inquiry", "positive"),
    ("product_spec", "Mẫu & size", "Product & sizing", "positive"),
    ("shipping_policy", "Vận chuyển", "Shipping & return", "positive"),
    ("praise_feedback", "Khen ngợi", "Praise & loyalty", "positive"),
    ("constructive", "Xây dựng", "Constructive", "positive"),
    ("positive", "Tích cực", "Positive", "positive"),
    ("polite", "Lịch sự", "Polite", "positive"),
    ("complaint_urgent", "Khiếu nại", "Urgent complaint", "negative"),
    ("negative", "Tiêu cực", "Negative", "negative"),
    ("spam_seeding", "Nghi clone/spam", "Spam / clone", "negative"),
    ("defamation_abuse", "Miệt thị / Bôi nhọ", "Defamation / libel", "negative"),
];

const INJECTION_PATTERNS: &[&str] = &[
    r"(?i)ignore\s+(?:all\s+)?previous\s+instructions",
    r"(?i)system\s+prompt",
    r"(?i)you\s+are\s+now\s+a",
    r"(?i)disregard\s+above",
    r"(?i)override\s+rubric",
];

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

pub fn sanitize_untrusted_text(raw_text: &str) -> (String, bool) {
    let mut cleaned = truncate_chars(raw_text, 2000);
    let mut detected = false;
    for pat in INJECTION_PATTERNS {
        if let Ok(re) = Regex::new(pat) {
            if re.is_match(&cleaned) {
                detected = true;
                cleaned = re.replace_all(&cleaned, "[REDACTED_INJECTION]").into_owned();
            }
        }
    }
    (cleaned.trim().to_string(), detected)
}

#[derive(Debug, Clone)]
pub struct CommentContext {
    pub comment_id: i64,
    pub untrusted_comment_text: String,
    pub sanitized_comment_text: String,
    pub injection_attempt_detected: bool,
    pub author_name: String,
    pub author_meta: String,
    pub source: String,
    pub verified: bool,
    pub post_id: i64,
    pub post_caption: String,
    pub post_permalink: String,
    pub channel_id: i64,
    pub channel_name: String,
    pub channel_kind: String,
    pub provider: String,
    pub adapter: String,
    pub threshold: i64,
    pub playbook_knowledge: String,
    pub calibration: HashMap<String, f64>,
}

pub fn collect_inline_context(
    comment_id: i64,
    comment_text: &str,
    author_name: &str,
    author_meta: &str,
    post_caption: &str,
    channel_name: &str,
    channel_kind: &str,
) -> CommentContext {
    let (sanitized, injected) = sanitize_untrusted_text(comment_text);
    CommentContext {
        comment_id,
        untrusted_comment_text: comment_text.to_string(),
        sanitized_comment_text: sanitized,
        injection_attempt_detected: injected,
        author_name: if author_name.is_empty() {
            "Customer".to_string()
        } else {
            author_name.to_string()
        },
        author_meta: if author_meta.is_empty() {
            "Public commenter".to_string()
        } else {
            author_meta.to_string()
        },
        source: "api".to_string(),
        verified: true,
        post_id: 0,
        post_caption: truncate_chars(post_caption, 1500),
        post_permalink: String::new(),
        channel_id: 0,
        channel_name: if channel_name.is_empty() {
            "Channel".to_string()
        } else {
            channel_name.to_string()
        },
        channel_kind: channel_kind.to_string(),
        provider: "meta".to_string(),
        adapter: "meta_api".to_string(),
        threshold: 80,
        playbook_knowledge: String::new(),
        calibration: HashMap::new(),
    }
}

pub fn collect_comment_context_db(
    db: &Connection,
    organization_id: &str,
    comment_id: i64,
) -> Result<CommentContext, String> {
    let row = query_one_map(
        db,
        "SELECT cm.id, cm.text, cm.author_name, cm.author_external_id, cm.author_meta,
                cm.source, cm.verified, cm.created_at, cm.like_count, cm.reply_count,
                p.id AS post_id, p.caption AS post_caption, p.permalink AS post_permalink, p.kind AS post_kind,
                c.id AS channel_id, c.name AS channel_name, c.provider, c.kind AS channel_kind,
                c.adapter, c.reply_policy, c.auto_suggest_threshold
         FROM comments cm
         JOIN posts p ON p.id=cm.post_id AND p.organization_id=cm.organization_id
         JOIN channels c ON c.id=cm.channel_id AND c.organization_id=cm.organization_id
         WHERE cm.organization_id=? AND cm.id=?",
        &[organization_id.to_string().into(), comment_id.into()],
    )
    .ok_or_else(|| "Comment not found".to_string())?;

    let author_ext = row
        .get("author_external_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let prior_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM comments
             WHERE organization_id=?1 AND author_external_id=?2 AND author_external_id!=''",
            params![organization_id, author_ext],
            |r| r.get(0),
        )
        .unwrap_or(0);

    let channel_id = row.get("channel_id").and_then(|v| v.as_i64()).unwrap_or(0);
    let playbook = query_one_map(
        db,
        "SELECT consultation_knowledge_md, auto_suggest_threshold
         FROM consultation_playbooks
         WHERE organization_id=? AND (channel_id=? OR channel_id IS NULL)
         ORDER BY channel_id DESC LIMIT 1",
        &[organization_id.to_string().into(), channel_id.into()],
    );

    let mut calibration = HashMap::new();
    for fb in query_maps(
        db,
        "SELECT label, AVG(CASE WHEN agreed=1 THEN 1.0 ELSE -1.0 END) AS bias, COUNT(*) AS cnt
         FROM evaluation_feedback WHERE organization_id=? AND label!='_decision' GROUP BY label",
        &[organization_id.to_string().into()],
    ) {
        if let Some(lbl) = fb.get("label").and_then(|v| v.as_str()) {
            let bias = fb.get("bias").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let cnt = fb.get("cnt").and_then(|v| v.as_i64()).unwrap_or(0) as f64;
            calibration.insert(lbl.to_string(), bias * (cnt * 2.0).min(8.0));
        }
    }

    let raw_text = row
        .get("text")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let (sanitized, injected) = sanitize_untrusted_text(raw_text);
    let raw_meta = row
        .get("author_meta")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let author_meta = if !raw_meta.is_empty() {
        raw_meta.to_string()
    } else if prior_count > 1 {
        format!("Repeat commenter ({prior_count} comments)")
    } else {
        "Public commenter".to_string()
    };

    let default_thresh = row
        .get("auto_suggest_threshold")
        .and_then(|v| v.as_i64())
        .unwrap_or(80);
    let threshold = playbook
        .as_ref()
        .and_then(|p| p.get("auto_suggest_threshold").and_then(|v| v.as_i64()))
        .unwrap_or(default_thresh);
    let playbook_md = playbook
        .as_ref()
        .and_then(|p| p.get("consultation_knowledge_md").and_then(|v| v.as_str()))
        .unwrap_or_default();

    Ok(CommentContext {
        comment_id,
        untrusted_comment_text: truncate_chars(raw_text, 2000),
        sanitized_comment_text: sanitized,
        injection_attempt_detected: injected,
        author_name: row
            .get("author_name")
            .and_then(|v| v.as_str())
            .unwrap_or("Customer")
            .to_string(),
        author_meta,
        source: row
            .get("source")
            .and_then(|v| v.as_str())
            .unwrap_or("api")
            .to_string(),
        verified: row.get("verified").and_then(|v| v.as_i64()).unwrap_or(1) != 0,
        post_id: row.get("post_id").and_then(|v| v.as_i64()).unwrap_or(0),
        post_caption: truncate_chars(
            row.get("post_caption")
                .and_then(|v| v.as_str())
                .unwrap_or_default(),
            1500,
        ),
        post_permalink: row
            .get("post_permalink")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        channel_id,
        channel_name: row
            .get("channel_name")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        channel_kind: row
            .get("channel_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("fb_page")
            .to_string(),
        provider: row
            .get("provider")
            .and_then(|v| v.as_str())
            .unwrap_or("meta")
            .to_string(),
        adapter: row
            .get("adapter")
            .and_then(|v| v.as_str())
            .unwrap_or("meta_api")
            .to_string(),
        threshold,
        playbook_knowledge: truncate_chars(playbook_md, 1500),
        calibration,
    })
}

fn clamp_prob(val: f64) -> i64 {
    val.clamp(1.0, 99.0).round() as i64
}

fn has_repeated_word_4x(text: &str) -> bool {
    let mut prev = "";
    let mut run = 0usize;
    for raw in text.split_whitespace() {
        let w = raw.trim_matches(|c: char| !c.is_alphanumeric() && c != '_');
        if w.is_empty() {
            prev = "";
            run = 0;
            continue;
        }
        if w == prev {
            run += 1;
            if run >= 4 {
                return true;
            }
        } else {
            prev = w;
            run = 1;
        }
    }
    false
}

pub fn evaluate_context(ctx: &CommentContext, threshold_override: Option<i64>) -> Value {
    let raw_text = if !ctx.sanitized_comment_text.is_empty() {
        &ctx.sanitized_comment_text
    } else {
        &ctx.untrusted_comment_text
    };
    let text = raw_text.to_lowercase();
    let eff_threshold = threshold_override.unwrap_or(ctx.threshold);

    let has_any = |patterns: &[&str]| patterns.iter().any(|p| text.contains(p));

    let ask_price = has_any(&[
        "giá",
        "bao nhiêu",
        "bn tiền",
        "inbox giá",
        "ib giá",
        "price",
        "how much",
        "cost",
        "báo giá",
        "rổ giá",
        "mấy tiền",
    ]);
    let ask_any_buy = has_any(&[
        "mua",
        "đặt hàng",
        "chốt",
        "order",
        "lấy bộ này",
        "còn hàng",
        "in stock",
        "want to buy",
        "tư vấn giúp",
        "tư vấn",
        "link mua",
        "shop ơi",
        "em lấy",
        "muốn đặt",
    ]) || ask_price;

    let ask_spec = has_any(&[
        "size",
        "mẫu",
        "màu",
        "keo",
        "dán",
        "bền",
        "tháo",
        "custom",
        "form",
        "nhọn",
        "tròn",
        "almond",
        "coffin",
        "measurement",
        "reuse",
        "tái sử dụng",
    ]);
    let ask_ship = has_any(&[
        "ship",
        "giao hàng",
        "vận chuyển",
        "bao lâu",
        "pháp",
        "france",
        "paris",
        "eu",
        "cod",
        "đổi trả",
        "delivery",
        "shipping",
        "mất mấy ngày",
    ]);
    let is_praise = has_any(&[
        "đẹp quá",
        "xuất sắc",
        "ưng lắm",
        "xinh xỉu",
        "tuyệt vời",
        "cảm ơn shop",
        "love this",
        "gorgeous",
        "stunning",
        "amazing",
        "best nails",
        "10 điểm",
        "đỉnh",
    ]);
    let is_defamation = has_any(&[
        "lừa đảo",
        "scam",
        "bôi nhọ",
        "vu khống",
        "phốt",
        "cướp",
        "vô đạo đức",
        "treo đầu dê",
        "đồ giả",
        "fraud",
        "fake shop",
        "kiện",
        "tố cáo",
        "rác rưởi",
    ]);
    let is_complaint = has_any(&[
        "chưa nhận được",
        "giao sai",
        "bị gãy",
        "bong keo",
        "không giống hình",
        "chậm trễ",
        "khiếu nại",
        "hoàn tiền",
        "refund",
        "damaged",
        "wrong size",
        "tệ",
        "đổi size",
        "mã vận đơn",
    ]);
    let is_spam = has_any(&[
        "http://",
        "https://",
        "t.me/",
        "zalo.me",
        "kiếm tiền tại nhà",
        "tuyển cộng tác viên",
        "nhận quà miễn phí",
        "cờ bạc",
        "bet88",
        "crypto",
        "inbox mình chỉ cách",
    ]) || has_repeated_word_4x(&text);

    let is_negative = is_defamation
        || is_complaint
        || has_any(&[
            "xấu",
            "đắt quá",
            "chán",
            "ghét",
            "dởm",
            "kém",
            "awful",
            "terrible",
            "waste",
        ]);
    let is_polite = has_any(&[
        "ạ",
        "nhé",
        "giúp mình",
        "cho em hỏi",
        "cảm ơn",
        "please",
        "thank",
        "chị ơi",
        "shop ơi",
    ]) && !is_defamation;

    let cal = |k: &str| ctx.calibration.get(k).copied().unwrap_or(0.0);
    let mut probs = HashMap::new();
    probs.insert(
        "purchase_intent",
        clamp_prob(
            (if ask_any_buy {
                88.0
            } else if ask_spec || ask_ship {
                62.0
            } else if is_praise {
                22.0
            } else {
                8.0
            }) + cal("purchase_intent"),
        ),
    );
    probs.insert(
        "price_inquiry",
        clamp_prob(
            (if ask_price {
                92.0
            } else if ask_any_buy {
                35.0
            } else {
                6.0
            }) + cal("price_inquiry"),
        ),
    );
    probs.insert(
        "product_spec",
        clamp_prob(
            (if ask_spec {
                90.0
            } else if ask_any_buy {
                44.0
            } else {
                12.0
            }) + cal("product_spec"),
        ),
    );
    probs.insert(
        "shipping_policy",
        clamp_prob(
            (if ask_ship {
                89.0
            } else if ask_any_buy {
                28.0
            } else {
                5.0
            }) + cal("shipping_policy"),
        ),
    );
    probs.insert(
        "praise_feedback",
        clamp_prob(
            (if is_praise {
                94.0
            } else if is_polite && !is_negative {
                38.0
            } else {
                7.0
            }) + cal("praise_feedback"),
        ),
    );
    probs.insert(
        "constructive",
        clamp_prob(
            (if (ask_spec || ask_ship || is_praise) && !is_defamation {
                84.0
            } else if !is_negative {
                48.0
            } else {
                11.0
            }) + cal("constructive"),
        ),
    );
    probs.insert(
        "positive",
        clamp_prob(
            (if is_praise {
                91.0
            } else if is_polite && !is_negative {
                78.0
            } else if is_negative {
                14.0
            } else {
                56.0
            }) + cal("positive"),
        ),
    );
    probs.insert(
        "polite",
        clamp_prob(
            (if is_polite {
                93.0
            } else if is_defamation {
                12.0
            } else {
                64.0
            }) + cal("polite"),
        ),
    );
    probs.insert(
        "complaint_urgent",
        clamp_prob(
            (if is_complaint {
                89.0
            } else if is_defamation {
                42.0
            } else {
                4.0
            }) + cal("complaint_urgent"),
        ),
    );
    probs.insert(
        "negative",
        clamp_prob(
            (if is_defamation {
                92.0
            } else if is_complaint {
                82.0
            } else if is_negative {
                74.0
            } else {
                8.0
            }) + cal("negative"),
        ),
    );
    probs.insert(
        "spam_seeding",
        clamp_prob((if is_spam { 95.0 } else { 6.0 }) + cal("spam_seeding")),
    );
    probs.insert(
        "defamation_abuse",
        clamp_prob(
            (if is_defamation {
                94.0
            } else if is_complaint {
                18.0
            } else {
                2.0
            }) + cal("defamation_abuse"),
        ),
    );

    let mut reasoning: Vec<String> = Vec::new();
    if ctx.injection_attempt_detected {
        reasoning.push(
            "Prompt-injection attempt neutralized by code-first collector shield".to_string(),
        );
    }

    let (bucket, recommended_action, score, tier_label) = if is_defamation {
        reasoning.extend([
            "Contains severe defamatory or hostile accusations targeting brand reputation".to_string(),
            "High legal/platform report value — freeze 5-layer forensic evidence before deletion".to_string(),
            "Do not auto-reply publicly; escalate to owner and capture immutable UID + HAR".to_string(),
        ]);
        (
            "evidence",
            "preserve_evidence",
            14.0,
            "Tier 1/5: Defamation / Hostile — Freeze Evidence",
        )
    } else if is_spam {
        reasoning.extend([
            "Detected promotional link, repetitive seeding pattern, or off-topic solicitation".to_string(),
            "Zero genuine product consultation or community value".to_string(),
            "Recommend hiding comment to keep post thread clean".to_string(),
        ]);
        (
            "spam_clone",
            "hide_spam",
            18.0,
            "Tier 1/5: Suspected Spam / Clone",
        )
    } else if is_complaint {
        reasoning.extend([
            "Customer reports an issue with order delivery, sizing, or product condition".to_string(),
            "Requires human verification of order ID before committing to a resolution".to_string(),
            "Acknowledge empathetically in public and move order details to Private DM".to_string(),
        ]);
        (
            "complaint",
            "prioritize_care",
            76.5,
            "Tier 3/5: Urgent Order / Quality Complaint",
        )
    } else if ask_any_buy || ask_spec || ask_ship {
        let raw_score: f64 = 78.0
            + if ask_price { 8.0 } else { 0.0 }
            + if ask_spec { 6.0 } else { 0.0 }
            + if ask_ship { 5.0 } else { 0.0 }
            + if is_polite { 4.0 } else { 0.0 };
        let sc = (raw_score * 10.0).round().min(980.0) / 10.0;
        let bk = if sc >= eff_threshold as f64 {
            "should_consult"
        } else {
            "needs_review"
        };
        let tl = if sc >= 88.0 {
            "Tier 5/5: High-Intent Consultation"
        } else {
            "Tier 4/5: Strong Consultation Fit"
        };
        reasoning.extend([
            "Matches commercial consultation criteria with zero toxicity or spam signals".to_string(),
            "Clear customer intent regarding pricing, custom nail sizing, or shipping timeline".to_string(),
            "Polite, constructive tone suitable for immediate guided consultation".to_string(),
            "Eligible for Public Reply + Private DM conversion flow".to_string(),
        ]);
        (bk, bk, sc, tl)
    } else if is_praise {
        reasoning.extend([
            "Strong positive sentiment and appreciation for the design/craftsmanship".to_string(),
            "Reinforces social proof on the post thread".to_string(),
            "Warm thank-you reply + soft invitation to view matching collection".to_string(),
        ]);
        let act = if 86.0 >= eff_threshold as f64 {
            "should_consult"
        } else {
            "needs_review"
        };
        (
            "praise",
            act,
            86.0,
            "Tier 4/5: VIP Praise & Brand Advocate",
        )
    } else if is_negative {
        reasoning.extend([
            "Displays negative or dismissive attitude without a specific actionable inquiry".to_string(),
            "Low probability of productive consultation".to_string(),
        ]);
        (
            "negative",
            "needs_review",
            32.0,
            "Tier 2/5: Negative / Unconstructive",
        )
    } else {
        reasoning.extend([
            "General engagement comment without explicit price/order keywords".to_string(),
            "Safe community tone; below automatic consultation threshold".to_string(),
        ]);
        (
            "needs_review",
            "needs_review",
            72.5,
            "Tier 3/5: General Comment — Manual Review",
        )
    };

    let base_caption = if ctx.post_caption.is_empty() {
        "this design"
    } else {
        ctx.post_caption.lines().next().unwrap_or("this design")
    };
    let post_snip = truncate_chars(base_caption, 90);
    let author = if ctx.author_name.is_empty() {
        "there"
    } else {
        ctx.author_name.as_str()
    };

    let (strategy, public_draft, private_draft) = match bucket {
        "evidence" => (
            json!({
                "objective": "Preserve 5-layer forensic evidence (Lập vi bằng số) before moderation",
                "goal": "Preserve 5-layer forensic evidence (Lập vi bằng số) before moderation",
                "tone": "Forensic & Non-Engaging",
                "recommended_channel": "freeze_evidence",
                "key_points": [
                    "Capture immutable UID + full thread + HAR",
                    "Hold public reply to avoid tipping off actor",
                ],
                "next_step_cta": "Seal Forensic Bundle in Evidence Vault",
                "steps": [
                    "1. Trigger 5-layer Evidence Vault capture (numerical UID, expanded thread, full-page screenshot, MHTML, HAR/UTC headers).",
                    "2. Hold public reply to avoid tipping off the actor to delete the thread prematurely.",
                ],
            }),
            String::new(),
            String::new(),
        ),
        "spam_clone" => (
            json!({
                "objective": "Suppress spam/clone noise without engaging",
                "goal": "Suppress spam/clone noise without engaging",
                "tone": "Moderation Only",
                "recommended_channel": "hide_only",
                "key_points": ["Hide spam comment", "Flag repeat spammer UID"],
                "next_step_cta": "Hide Comment",
                "steps": ["1. Hide comment from public post thread."],
            }),
            String::new(),
            String::new(),
        ),
        "complaint" => (
            json!({
                "objective": "De-escalate publicly with empathy and verify order ID in Private DM",
                "goal": "De-escalate publicly with empathy and verify order ID in Private DM",
                "tone": "Empathetic, Accountable & Responsive",
                "recommended_channel": "public_and_dm",
                "key_points": ["Acknowledge concern warmly", "Request order code in DM"],
                "next_step_cta": "Check Private DM for Order Verification",
                "steps": [
                    format!("1. Thank {author} for flagging the issue and apologize for the inconvenience."),
                    "2. Ask them to check their Private Message (DM) so the care team can verify their order ID immediately.".to_string(),
                ],
            }),
            format!(
                "Hi {author}, thank you for letting us know — we are truly sorry to hear this! We just sent you a private message so our care team can check your order code and resolve this for you right away."
            ),
            format!(
                "Hi {author}, we saw your comment on \"{post_snip}\" and want to make this right immediately. Could you share your order number so we can arrange a priority replacement or sizing adjustment?"
            ),
        ),
        "should_consult" => {
            let mut points: Vec<String> = Vec::new();
            if ask_price {
                points.push("Confirm collection tier & pricing details clearly".to_string());
            }
            if ask_spec {
                points.push(
                    "Explain custom nail shape/sizing kit & reusable press-on application"
                        .to_string(),
                );
            }
            if ask_ship {
                points.push(
                    "Confirm tracked express shipping timeline (48-72h EU/FR dispatch)".to_string(),
                );
            }
            if points.is_empty() {
                points.push("Provide direct product consultation and sizing guidance".to_string());
            }
            let spec_clause = if ask_spec {
                " Each set is handcrafted to your exact nail measurements (Almond, Coffin, Oval, or Short Square) and includes a full prep & reusable glue/tab kit."
            } else {
                ""
            };
            let ship_clause = if ask_ship {
                " We dispatch with tracked 48-72h delivery across France & EU."
            } else {
                ""
            };
            let playbook_note = if !ctx.playbook_knowledge.trim().is_empty() {
                format!(
                    "\n• Brand Playbook Note: {}",
                    truncate_chars(ctx.playbook_knowledge.trim(), 260)
                )
            } else {
                String::new()
            };
            if !playbook_note.is_empty() {
                points.push("Apply active consultation playbook knowledge".to_string());
            }
            (
                json!({
                    "objective": "Convert high-intent inquiry into an order via structured consultation",
                    "goal": "Convert high-intent inquiry into an order via structured consultation",
                    "tone": "Warm, Consultative & Luxury-Editorial",
                    "recommended_channel": "public_and_dm",
                    "playbook_applied": !playbook_note.is_empty(),
                    "key_points": points,
                    "next_step_cta": "Check Private Message (DM) for Custom Size Chart & Direct Order Link",
                    "steps": [
                        format!("1. Greet {author} warmly and confirm availability for \"{post_snip}\"."),
                        format!("2. Address key questions: {}.", points.join("; ")),
                        "3. Send detailed sizing chart & direct checkout link via Private Reply (DM).".to_string(),
                    ],
                }),
                format!(
                    "Hi {author}! Thank you for your interest in this set.{spec_clause}{ship_clause} We have just sent the full price details and sizing guide to your inbox — please check your messages!"
                ),
                format!(
                    "Hi {author}! Following up on your comment on \"{post_snip}\":\n• Handcrafted Press-On Set: available in standard sizes (XS/S/M/L) or custom measurements.\n• Includes: 10 handmade nails + prep kit (buffer, cuticle stick, alcohol pad, jelly tabs & nail glue).{playbook_note}\n• Reply here with your preferred shape or nail widths and we will help you pick the exact fit!"
                ),
            )
        }
        "praise" => (
            json!({
                "objective": "Strengthen VIP brand relationship and invite future discovery",
                "goal": "Strengthen VIP brand relationship and invite future discovery",
                "tone": "Grateful & Appreciative",
                "recommended_channel": "public_only",
                "key_points": ["Thank customer warmly", "Invite to tag us in nail photos"],
                "next_step_cta": "Share your nail look with us",
                "steps": [format!("1. Thank {author} warmly for the kind words on \"{post_snip}\".")],
            }),
            format!(
                "Thank you so much, {author}! We are thrilled you love this design — every set is hand-painted with care."
            ),
            format!(
                "Hi {author}! Thank you again for your lovely feedback on \"{post_snip}\" — let us know anytime you would like early access to our next collection!"
            ),
        ),
        _ => (
            json!({
                "objective": "Maintain friendly community presence",
                "goal": "Maintain friendly community presence",
                "tone": "Friendly & Helpful",
                "recommended_channel": "public_only",
                "key_points": ["Acknowledge comment"],
                "next_step_cta": "Ask if sizing advice is needed",
                "steps": ["1. Review comment context on the post."],
            }),
            format!(
                "Thank you for your comment, {author}! Let us know if you ever need sizing or style advice."
            ),
            format!(
                "Hi {author}, thank you for engaging with \"{post_snip}\"! Feel free to message us here if you have any questions."
            ),
        ),
    };

    let label_scores: Vec<Value> = RUBRIC_LABELS
        .iter()
        .map(|&(key, vi, en, pol)| {
            json!({
                "key": key,
                "label": format!("{vi} · {en}"),
                "label_vi": vi,
                "label_en": en,
                "polarity": pol,
                "group": if pol == "negative" { "risk" } else { "commercial" },
                "probability": probs.get(key).copied().unwrap_or(50),
            })
        })
        .collect();

    let confidence: i64 = if ctx.verified && raw_text.chars().count() >= 12 {
        91
    } else {
        74
    };
    let data_quality = if ctx.source == "api" {
        "Full post & comment context"
    } else {
        "Browser ingest · Public permalink readable"
    };

    json!({
        "rubric_version": RUBRIC_VERSION,
        "overall_score": score,
        "threshold": eff_threshold,
        "bucket": bucket,
        "recommended_action": recommended_action,
        "tier_label": tier_label,
        "confidence": confidence,
        "data_quality": data_quality,
        "reasoning_bullets": reasoning,
        "label_scores": label_scores,
        "reply_strategy": strategy,
        "public_draft": public_draft,
        "private_draft": private_draft,
    })
}

pub fn evaluate_and_persist(
    db: &Connection,
    organization_id: &str,
    comment_id: i64,
    threshold: Option<i64>,
    actor: &str,
) -> Result<Value, String> {
    let ctx = collect_comment_context_db(db, organization_id, comment_id)?;
    let result = evaluate_context(&ctx, threshold);
    let now = now_unix();

    let reasoning_json =
        serde_json::to_string(&result["reasoning_bullets"]).unwrap_or_else(|_| "[]".to_string());
    let labels_json =
        serde_json::to_string(&result["label_scores"]).unwrap_or_else(|_| "[]".to_string());
    let strategy_json =
        serde_json::to_string(&result["reply_strategy"]).unwrap_or_else(|_| "{}".to_string());

    db.execute(
        "INSERT INTO comment_evaluations
           (organization_id, comment_id, rubric_version, overall_score, threshold,
            recommended_action, tier_label, confidence, data_quality,
            reasoning_bullets_json, label_scores_json, reply_strategy_json, evaluated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
         ON CONFLICT(organization_id, comment_id) DO UPDATE SET
            rubric_version=excluded.rubric_version,
            overall_score=excluded.overall_score,
            threshold=excluded.threshold,
            recommended_action=excluded.recommended_action,
            tier_label=excluded.tier_label,
            confidence=excluded.confidence,
            data_quality=excluded.data_quality,
            reasoning_bullets_json=excluded.reasoning_bullets_json,
            label_scores_json=excluded.label_scores_json,
            reply_strategy_json=excluded.reply_strategy_json,
            evaluated_at=excluded.evaluated_at",
        params![
            organization_id,
            comment_id,
            result["rubric_version"].as_str().unwrap_or(RUBRIC_VERSION),
            result["overall_score"].as_f64().unwrap_or(50.0),
            result["threshold"].as_i64().unwrap_or(80),
            result["recommended_action"]
                .as_str()
                .unwrap_or("needs_review"),
            result["tier_label"].as_str().unwrap_or(""),
            result["confidence"].as_i64().unwrap_or(75),
            result["data_quality"].as_str().unwrap_or(""),
            reasoning_json,
            labels_json,
            strategy_json,
            now,
        ],
    )
    .map_err(|e| e.to_string())?;

    let mut flags: Vec<String> = Vec::new();
    let mut bucket = result["bucket"]
        .as_str()
        .unwrap_or("needs_review")
        .to_string();
    let mut status = if matches!(bucket.as_str(), "should_consult" | "complaint" | "praise") {
        "needs_reply".to_string()
    } else {
        "new".to_string()
    };
    match bucket.as_str() {
        "spam_clone" => flags.push("spam_risk".to_string()),
        "evidence" => flags.push("defamation_evidence".to_string()),
        "complaint" => flags.push("complaint".to_string()),
        "should_consult" => flags.push("high_intent".to_string()),
        _ => {}
    }

    for rule in query_maps(
        db,
        "SELECT * FROM rules WHERE organization_id=? AND enabled=1",
        &[organization_id.to_string().into()],
    ) {
        let pat = rule
            .get("pattern")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let match_kind = rule
            .get("match_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("keyword");
        let matched = match match_kind {
            "keyword" => ctx
                .untrusted_comment_text
                .to_lowercase()
                .contains(&pat.to_lowercase()),
            "author" => ctx
                .author_name
                .to_lowercase()
                .contains(&pat.to_lowercase()),
            "regex" => RegexBuilder::new(pat)
                .case_insensitive(true)
                .build()
                .map(|re| re.is_match(&ctx.untrusted_comment_text))
                .unwrap_or(false),
            _ => false,
        };
        if matched {
            let flag = rule
                .get("flag")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if !flag.is_empty() && !flags.iter().any(|f| f == flag) {
                flags.push(flag.to_string());
            }
            if let Some(st) = rule.get("auto_status").and_then(|v| v.as_str()) {
                status = st.to_string();
            }
            if let Some(bk) = rule.get("auto_bucket").and_then(|v| v.as_str()) {
                bucket = bk.to_string();
            }
        }
    }

    let existing_state = query_one_map(
        db,
        "SELECT status, assigned_to, note FROM comment_states WHERE organization_id=? AND comment_id=?",
        &[organization_id.to_string().into(), comment_id.into()],
    );
    let mut assigned_to = String::new();
    let mut note = String::new();
    if let Some(st_row) = existing_state {
        if let Some(prev_st) = st_row.get("status").and_then(|v| v.as_str()) {
            if matches!(prev_st, "replied" | "hidden" | "ignored") {
                status = prev_st.to_string();
            }
        }
        assigned_to = st_row
            .get("assigned_to")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        note = st_row
            .get("note")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
    }

    let flags_json = serde_json::to_string(&flags).unwrap_or_else(|_| "[]".to_string());
    db.execute(
        "INSERT INTO comment_states
           (organization_id, comment_id, status, bucket, assigned_to, note, flags_json, updated_by, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(organization_id, comment_id) DO UPDATE SET
            status=excluded.status,
            bucket=excluded.bucket,
            flags_json=excluded.flags_json,
            updated_by=excluded.updated_by,
            updated_at=excluded.updated_at",
        params![
            organization_id,
            comment_id,
            status,
            bucket,
            assigned_to,
            note,
            flags_json,
            actor,
            now
        ],
    )
    .map_err(|e| e.to_string())?;

    let strategy_summary = result["reply_strategy"]["objective"]
        .as_str()
        .unwrap_or_default();
    for (kind, draft_key) in [("public", "public_draft"), ("private_dm", "private_draft")] {
        let draft_text = result[draft_key].as_str().unwrap_or_default();
        if draft_text.is_empty() {
            continue;
        }
        let existing_draft = query_one_map(
            db,
            "SELECT id, status FROM reply_drafts
             WHERE organization_id=? AND comment_id=? AND kind=?
             ORDER BY id DESC LIMIT 1",
            &[
                organization_id.to_string().into(),
                comment_id.into(),
                kind.to_string().into(),
            ],
        );
        if let Some(dr) = existing_draft {
            if dr.get("status").and_then(|v| v.as_str()) == Some("draft") {
                let did = dr.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
                db.execute(
                    "UPDATE reply_drafts SET strategy_summary=?1, text=?2, updated_at=?3
                     WHERE organization_id=?4 AND id=?5",
                    params![strategy_summary, draft_text, now, organization_id, did],
                )
                .map_err(|e| e.to_string())?;
            }
        } else {
            db.execute(
                "INSERT INTO reply_drafts
                   (organization_id, comment_id, kind, strategy_summary, text, created_by, status, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'draft', ?7, ?8)",
                params![
                    organization_id,
                    comment_id,
                    kind,
                    strategy_summary,
                    draft_text,
                    actor,
                    now,
                    now
                ],
            )
            .map_err(|e| e.to_string())?;
        }
    }

    Ok(result)
}

pub fn record_feedback(
    db: &Connection,
    organization_id: &str,
    comment_id: i64,
    label: Option<&str>,
    agreed: Option<bool>,
    human_decision: Option<i64>,
    actor: &str,
) -> Result<Value, String> {
    let now = now_unix();
    if let Some(lbl) = label {
        let valid = lbl == "_decision" || RUBRIC_LABELS.iter().any(|(k, _, _, _)| *k == lbl);
        let Some(ag) = agreed else {
            return Err("Invalid rubric label or verdict".to_string());
        };
        if !valid {
            return Err("Invalid rubric label or verdict".to_string());
        }
        db.execute(
            "INSERT INTO evaluation_feedback
               (organization_id, comment_id, label, agreed, human_decision, actor, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(organization_id, comment_id, label) DO UPDATE SET
                agreed=excluded.agreed,
                human_decision=COALESCE(excluded.human_decision, evaluation_feedback.human_decision),
                actor=excluded.actor,
                created_at=excluded.created_at",
            params![
                organization_id,
                comment_id,
                lbl,
                if ag { 1 } else { 0 },
                human_decision,
                actor,
                now
            ],
        )
        .map_err(|e| e.to_string())?;
    }

    if let Some(hd) = human_decision {
        if matches!(hd, 1..=3) {
            let new_status = match hd {
                1 | 2 => "needs_reply",
                _ => "ignored",
            };
            let new_bucket = match hd {
                1 => "should_consult",
                2 => "needs_review",
                _ => "negative",
            };
            db.execute(
                "INSERT INTO comment_states
                   (organization_id, comment_id, status, bucket, human_decision, updated_by, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(organization_id, comment_id) DO UPDATE SET
                    status=excluded.status,
                    bucket=excluded.bucket,
                    human_decision=excluded.human_decision,
                    updated_by=excluded.updated_by,
                    updated_at=excluded.updated_at",
                params![
                    organization_id,
                    comment_id,
                    new_status,
                    new_bucket,
                    hd,
                    actor,
                    now
                ],
            )
            .map_err(|e| e.to_string())?;

            if hd == 1 {
                db.execute(
                    "UPDATE reply_drafts SET status='approved', approved_by=?1, updated_at=?2
                     WHERE organization_id=?3 AND comment_id=?4 AND status='draft'",
                    params![actor, now, organization_id, comment_id],
                )
                .map_err(|e| e.to_string())?;
            } else if hd == 3 {
                db.execute(
                    "UPDATE reply_drafts SET status='rejected', updated_at=?1
                     WHERE organization_id=?2 AND comment_id=?3 AND status='draft'",
                    params![now, organization_id, comment_id],
                )
                .map_err(|e| e.to_string())?;
            }
        }
    }

    Ok(json!({
        "ok": true,
        "comment_id": comment_id,
        "label": label,
        "agreed": agreed,
        "human_decision": human_decision,
    }))
}
