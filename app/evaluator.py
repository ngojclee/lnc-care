"""Prompt-injection-isolated comment collector, multi-label rubric evaluator, and consultation reasoner.

Follows the 3-step pipeline:
1. Code collects untrusted comment/post/channel context as pure data variables and strips prompt-injection strings.
2. Multi-label rubric evaluates 12 commercial consultation & community/safety labels (0-100%)
   incorporating historical human [✓]/[✕] feedback.
3. Consultation reasoner formulates a structured reply strategy and generates tailored
   Public Reply + Private DM Consultation drafts.
"""
import json
import re
import sqlite3
import time

from . import audit

RUBRIC_VERSION = "v1.2-triage"

RUBRIC_LABELS = (
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
)

LABEL_DEFS = tuple(
    {
        "key": k,
        "label": f"{vi} · {en}",
        "label_vi": vi,
        "label_en": en,
        "polarity": pol,
        "group": "risk" if pol == "negative" else "commercial",
    }
    for k, vi, en, pol in RUBRIC_LABELS
)

INJECTION_PATTERNS = (
    r"ignore\s+(?:all\s+)?previous\s+instructions",
    r"system\s+prompt",
    r"you\s+are\s+now\s+a",
    r"disregard\s+above",
    r"override\s+rubric",
)


def _sanitize_untrusted_text(raw_text: str) -> tuple[str, bool]:
    text = str(raw_text or "")[:2000]
    detected = False
    cleaned = text
    for pat in INJECTION_PATTERNS:
        if re.search(pat, cleaned, flags=re.IGNORECASE):
            detected = True
            cleaned = re.sub(pat, "[REDACTED_INJECTION]", cleaned, flags=re.IGNORECASE)
    return cleaned.strip(), detected


def collect_comment_context(
    db: sqlite3.Connection | None = None,
    organization_id: str = "lnc-default",
    comment_id: int = 0,
    *,
    comment_text: str | None = None,
    author_name: str = "",
    author_meta: str = "",
    post_caption: str = "",
    channel_name: str = "",
    channel_kind: str = "fb_page",
) -> dict:
    """Step 1: Pure deterministic code collector. Untrusted user text stays isolated in data fields."""
    if db is None or comment_text is not None:
        sanitized, injected = _sanitize_untrusted_text(comment_text or "")
        return {
            "comment_id": comment_id,
            "untrusted_comment_text": comment_text or "",
            "sanitized_comment_text": sanitized,
            "injection_attempt_detected": injected,
            "author_name": author_name or "Customer",
            "author_meta": author_meta or "Public commenter",
            "source": "api",
            "verified": True,
            "post_id": 0,
            "post_caption": (post_caption or "")[:1500],
            "post_permalink": "",
            "channel_id": 0,
            "channel_name": channel_name or "Channel",
            "channel_kind": channel_kind,
            "provider": "meta",
            "adapter": "meta_api",
            "threshold": 80,
            "playbook_knowledge": "",
            "calibration": {},
        }

    row = db.execute(
        """SELECT cm.id, cm.text, cm.author_name, cm.author_external_id, cm.author_meta,
                  cm.source, cm.verified, cm.created_at, cm.like_count, cm.reply_count,
                  p.id AS post_id, p.caption AS post_caption, p.permalink AS post_permalink, p.kind AS post_kind,
                  c.id AS channel_id, c.name AS channel_name, c.provider, c.kind AS channel_kind,
                  c.adapter, c.reply_policy, c.auto_suggest_threshold
           FROM comments cm
           JOIN posts p ON p.id=cm.post_id AND p.organization_id=cm.organization_id
           JOIN channels c ON c.id=cm.channel_id AND c.organization_id=cm.organization_id
           WHERE cm.organization_id=? AND cm.id=?""",
        (organization_id, comment_id),
    ).fetchone()
    if not row:
        raise ValueError("Comment not found")

    prior_count = db.execute(
        """SELECT COUNT(*) FROM comments
           WHERE organization_id=? AND author_external_id=? AND author_external_id!=''""",
        (organization_id, row["author_external_id"]),
    ).fetchone()[0]

    playbook = db.execute(
        """SELECT consultation_knowledge_md, auto_suggest_threshold
           FROM consultation_playbooks
           WHERE organization_id=? AND (channel_id=? OR channel_id IS NULL)
           ORDER BY channel_id DESC LIMIT 1""",
        (organization_id, row["channel_id"]),
    ).fetchone()

    calibration: dict[str, float] = {}
    for fb in db.execute(
        """SELECT label, AVG(CASE WHEN agreed=1 THEN 1.0 ELSE -1.0 END) AS bias, COUNT(*) AS cnt
           FROM evaluation_feedback WHERE organization_id=? AND label!='_decision' GROUP BY label""",
        (organization_id,),
    ).fetchall():
        calibration[fb["label"]] = float(fb["bias"]) * min(8.0, float(fb["cnt"]) * 2.0)

    sanitized, injected = _sanitize_untrusted_text(row["text"])
    return {
        "comment_id": row["id"],
        "untrusted_comment_text": row["text"][:2000],
        "sanitized_comment_text": sanitized,
        "injection_attempt_detected": injected,
        "author_name": row["author_name"],
        "author_meta": row["author_meta"]
        or (f"Repeat commenter ({prior_count} comments)" if prior_count > 1 else "Public commenter"),
        "source": row["source"],
        "verified": bool(row["verified"]),
        "post_id": row["post_id"],
        "post_caption": (row["post_caption"] or "")[:1500],
        "post_permalink": row["post_permalink"] or "",
        "channel_id": row["channel_id"],
        "channel_name": row["channel_name"],
        "channel_kind": row["channel_kind"],
        "provider": row["provider"],
        "adapter": row["adapter"],
        "threshold": int(
            playbook["auto_suggest_threshold"] if playbook else row["auto_suggest_threshold"] or 80
        ),
        "playbook_knowledge": (playbook["consultation_knowledge_md"] if playbook else "")[:1500],
        "calibration": calibration,
    }


def _clamp(val: float, low: float = 1.0, high: float = 99.0) -> int:
    return int(round(max(low, min(high, val))))


def evaluate_context(ctx: dict, *, threshold: int | None = None) -> dict:
    """Step 2 & 3: Multi-label rubric scoring + consultation strategy reasoning."""
    raw_text = ctx.get("sanitized_comment_text") or ctx.get("untrusted_comment_text", "")
    text = raw_text.lower()
    cal = ctx.get("calibration", {})
    eff_threshold = int(threshold if threshold is not None else ctx.get("threshold", 80))

    def has_any(patterns: tuple[str, ...]) -> bool:
        return any(p in text for p in patterns)

    ask_price = has_any(
        (
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
        )
    )
    ask_any_buy = (
        has_any(
            (
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
            )
        )
        or ask_price
    )
    ask_spec = has_any(
        (
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
        )
    )
    ask_ship = has_any(
        (
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
        )
    )
    is_praise = has_any(
        (
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
        )
    )

    is_defamation = has_any(
        (
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
        )
    )
    is_complaint = has_any(
        (
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
        )
    )
    is_spam = has_any(
        (
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
        )
    ) or bool(re.search(r"(\b\w+\b)(?:\s+\1){3,}", text))
    is_negative = (
        is_defamation
        or is_complaint
        or has_any(("xấu", "đắt quá", "chán", "ghét", "dởm", "kém", "awful", "terrible", "waste"))
    )
    is_polite = (
        has_any(
            (
                "ạ",
                "nhé",
                "giúp mình",
                "cho em hỏi",
                "cảm ơn",
                "please",
                "thank",
                "chị ơi",
                "shop ơi",
            )
        )
        and not is_defamation
    )

    probs: dict[str, int] = {
        "purchase_intent": _clamp(
            (88 if ask_any_buy else 62 if (ask_spec or ask_ship) else 22 if is_praise else 8)
            + cal.get("purchase_intent", 0)
        ),
        "price_inquiry": _clamp(
            (92 if ask_price else 35 if ask_any_buy else 6) + cal.get("price_inquiry", 0)
        ),
        "product_spec": _clamp(
            (90 if ask_spec else 44 if ask_any_buy else 12) + cal.get("product_spec", 0)
        ),
        "shipping_policy": _clamp(
            (89 if ask_ship else 28 if ask_any_buy else 5) + cal.get("shipping_policy", 0)
        ),
        "praise_feedback": _clamp(
            (94 if is_praise else 38 if is_polite and not is_negative else 7)
            + cal.get("praise_feedback", 0)
        ),
        "constructive": _clamp(
            (84 if (ask_spec or ask_ship or is_praise) and not is_defamation else 48 if not is_negative else 11)
            + cal.get("constructive", 0)
        ),
        "positive": _clamp(
            (91 if is_praise else 78 if (is_polite and not is_negative) else 14 if is_negative else 56)
            + cal.get("positive", 0)
        ),
        "polite": _clamp(
            (93 if is_polite else 12 if is_defamation else 64) + cal.get("polite", 0)
        ),
        "complaint_urgent": _clamp(
            (89 if is_complaint else 42 if is_defamation else 4) + cal.get("complaint_urgent", 0)
        ),
        "negative": _clamp(
            (92 if is_defamation else 82 if is_complaint else 74 if is_negative else 8)
            + cal.get("negative", 0)
        ),
        "spam_seeding": _clamp((95 if is_spam else 6) + cal.get("spam_seeding", 0)),
        "defamation_abuse": _clamp(
            (94 if is_defamation else 18 if is_complaint else 2) + cal.get("defamation_abuse", 0)
        ),
    }

    reasoning: list[str] = []
    if ctx.get("injection_attempt_detected"):
        reasoning.append("Prompt-injection attempt neutralized by code-first collector shield")

    if is_defamation:
        bucket = "evidence"
        recommended_action = "preserve_evidence"
        score = 14.0
        tier_label = "Tier 1/5: Defamation / Hostile — Freeze Evidence"
        reasoning.extend(
            [
                "Contains severe defamatory or hostile accusations targeting brand reputation",
                "High legal/platform report value — freeze 5-layer forensic evidence before deletion",
                "Do not auto-reply publicly; escalate to owner and capture immutable UID + HAR",
            ]
        )
    elif is_spam:
        bucket = "spam_clone"
        recommended_action = "hide_spam"
        score = 18.0
        tier_label = "Tier 1/5: Suspected Spam / Clone"
        reasoning.extend(
            [
                "Detected promotional link, repetitive seeding pattern, or off-topic solicitation",
                "Zero genuine product consultation or community value",
                "Recommend hiding comment to keep post thread clean",
            ]
        )
    elif is_complaint:
        bucket = "complaint"
        recommended_action = "prioritize_care"
        score = 76.5
        tier_label = "Tier 3/5: Urgent Order / Quality Complaint"
        reasoning.extend(
            [
                "Customer reports an issue with order delivery, sizing, or product condition",
                "Requires human verification of order ID before committing to a resolution",
                "Acknowledge empathetically in public and move order details to Private DM",
            ]
        )
    elif ask_any_buy or ask_spec or ask_ship:
        raw_score = (
            78.0
            + (8.0 if ask_price else 0.0)
            + (6.0 if ask_spec else 0.0)
            + (5.0 if ask_ship else 0.0)
            + (4.0 if is_polite else 0.0)
        )
        score = min(98.0, round(raw_score, 1))
        bucket = "should_consult" if score >= eff_threshold else "needs_review"
        recommended_action = bucket
        tier_label = (
            "Tier 5/5: High-Intent Consultation"
            if score >= 88
            else "Tier 4/5: Strong Consultation Fit"
        )
        reasoning.extend(
            [
                "Matches commercial consultation criteria with zero toxicity or spam signals",
                "Clear customer intent regarding pricing, custom nail sizing, or shipping timeline",
                "Polite, constructive tone suitable for immediate guided consultation",
                "Eligible for Public Reply + Private DM conversion flow",
            ]
        )
    elif is_praise:
        bucket = "praise"
        recommended_action = "should_consult" if 86.0 >= eff_threshold else "needs_review"
        score = 86.0
        tier_label = "Tier 4/5: VIP Praise & Brand Advocate"
        reasoning.extend(
            [
                "Strong positive sentiment and appreciation for the design/craftsmanship",
                "Reinforces social proof on the post thread",
                "Warm thank-you reply + soft invitation to view matching collection",
            ]
        )
    elif is_negative:
        bucket = "negative"
        recommended_action = "needs_review"
        score = 32.0
        tier_label = "Tier 2/5: Negative / Unconstructive"
        reasoning.extend(
            [
                "Displays negative or dismissive attitude without a specific actionable inquiry",
                "Low probability of productive consultation",
            ]
        )
    else:
        bucket = "needs_review"
        recommended_action = "needs_review"
        score = 72.5
        tier_label = "Tier 3/5: General Comment — Manual Review"
        reasoning.extend(
            [
                "General engagement comment without explicit price/order keywords",
                "Safe community tone; below automatic consultation threshold",
            ]
        )

    post_snip = (ctx.get("post_caption") or "this design").split("\n")[0][:90]
    author = ctx.get("author_name") or "there"
    first_name = author.split()[0] if author else "there"

    if bucket == "evidence":
        strategy = {
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
        }
        public_draft = ""
        private_draft = ""
    elif bucket == "spam_clone":
        strategy = {
            "objective": "Suppress spam/clone noise without engaging",
            "goal": "Suppress spam/clone noise without engaging",
            "tone": "Moderation Only",
            "recommended_channel": "hide_only",
            "key_points": ["Hide spam comment", "Flag repeat spammer UID"],
            "next_step_cta": "Hide Comment",
            "steps": ["1. Hide comment from public post thread."],
        }
        public_draft = ""
        private_draft = ""
    elif bucket == "complaint":
        strategy = {
            "objective": "De-escalate publicly with empathy and verify order ID in Private DM",
            "goal": "De-escalate publicly with empathy and verify order ID in Private DM",
            "tone": "Empathetic, Accountable & Responsive",
            "recommended_channel": "public_and_dm",
            "key_points": ["Acknowledge concern warmly", "Request order code in DM"],
            "next_step_cta": "Check Private DM for Order Verification",
            "steps": [
                f"1. Thank {author} for flagging the issue and apologize for the inconvenience.",
                "2. Ask them to check their Private Message (DM) so the care team can verify their order ID immediately.",
            ],
        }
        public_draft = (
            f"Hi {author}, thank you for letting us know — we are truly sorry to hear this! "
            f"We just sent you a private message so our care team can check your order code and resolve this for you right away."
        )
        private_draft = (
            f"Hi {author}, we saw your comment on \"{post_snip}\" and want to make this right immediately. "
            f"Could you share your order number so we can arrange a priority replacement or sizing adjustment?"
        )
    elif bucket == "should_consult":
        points = []
        if ask_price:
            points.append("Confirm collection tier & pricing details clearly")
        if ask_spec:
            points.append("Explain custom nail shape/sizing kit & reusable press-on application")
        if ask_ship:
            points.append("Confirm tracked express shipping timeline (48-72h EU/FR dispatch)")
        if not points:
            points.append("Provide direct product consultation and sizing guidance")
        strategy = {
            "objective": "Convert high-intent inquiry into an order via structured consultation",
            "goal": "Convert high-intent inquiry into an order via structured consultation",
            "tone": "Warm, Consultative & Luxury-Editorial",
            "recommended_channel": "public_and_dm",
            "key_points": points,
            "next_step_cta": "Check Private Message (DM) for Custom Size Chart & Direct Order Link",
            "steps": [
                f"1. Greet {author} warmly and confirm availability for \"{post_snip}\".",
                f"2. Address key questions: {'; '.join(points)}.",
                "3. Send detailed sizing chart & direct checkout link via Private Reply (DM).",
            ],
        }
        spec_clause = (
            " Each set is handcrafted to your exact nail measurements (Almond, Coffin, Oval, or Short Square) and includes a full prep & reusable glue/tab kit."
            if ask_spec
            else ""
        )
        ship_clause = " We dispatch with tracked 48-72h delivery across France & EU." if ask_ship else ""
        public_draft = (
            f"Hi {author}! Thank you for your interest in this set.{spec_clause}{ship_clause} "
            f"We have just sent the full price details and sizing guide to your inbox — please check your messages!"
        )
        private_draft = (
            f"Hi {author}! Following up on your comment on \"{post_snip}\":\n"
            f"• Handcrafted Press-On Set: available in standard sizes (XS/S/M/L) or custom measurements.\n"
            f"• Includes: 10 handmade nails + prep kit (buffer, cuticle stick, alcohol pad, jelly tabs & nail glue).\n"
            f"• Reply here with your preferred shape or nail widths and we will help you pick the exact fit!"
        )
    elif bucket == "praise":
        strategy = {
            "objective": "Strengthen VIP brand relationship and invite future discovery",
            "goal": "Strengthen VIP brand relationship and invite future discovery",
            "tone": "Grateful & Appreciative",
            "recommended_channel": "public_only",
            "key_points": ["Thank customer warmly", "Invite to tag us in nail photos"],
            "next_step_cta": "Share your nail look with us",
            "steps": [f"1. Thank {author} warmly for the kind words on \"{post_snip}\"."],
        }
        public_draft = (
            f"Thank you so much, {author}! We are thrilled you love this design — every set is hand-painted with care."
        )
        private_draft = (
            f"Hi {author}! Thank you again for your lovely feedback on \"{post_snip}\" — let us know anytime you would like early access to our next collection!"
        )
    else:
        strategy = {
            "objective": "Maintain friendly community presence",
            "goal": "Maintain friendly community presence",
            "tone": "Friendly & Helpful",
            "recommended_channel": "public_only",
            "key_points": ["Acknowledge comment"],
            "next_step_cta": "Ask if sizing advice is needed",
            "steps": ["1. Review comment context on the post."],
        }
        public_draft = (
            f"Thank you for your comment, {author}! Let us know if you ever need sizing or style advice."
        )
        private_draft = (
            f"Hi {author}, thank you for engaging with \"{post_snip}\"! Feel free to message us here if you have any questions."
        )

    label_scores = [
        {
            "key": d["key"],
            "label": d["label"],
            "label_vi": d["label_vi"],
            "label_en": d["label_en"],
            "polarity": d["polarity"],
            "group": d["group"],
            "probability": probs[d["key"]],
        }
        for d in LABEL_DEFS
    ]
    confidence = 91 if ctx.get("verified") and len(raw_text) >= 12 else 74
    data_quality = (
        "Full post & comment context"
        if ctx.get("source") == "api"
        else "Browser ingest · Public permalink readable"
    )

    return {
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
    }


def evaluate_and_persist(
    db: sqlite3.Connection,
    organization_id: str,
    comment_id: int,
    *,
    threshold: int | None = None,
    actor: str = "ai:evaluator",
) -> dict:
    """Run the 3-step pipeline on a comment and persist evaluation, triage state, rules, and drafts."""
    ctx = collect_comment_context(db, organization_id, comment_id)
    result = evaluate_context(ctx, threshold=threshold)
    now = int(time.time())

    db.execute(
        """INSERT INTO comment_evaluations
           (organization_id, comment_id, rubric_version, overall_score, threshold,
            recommended_action, tier_label, confidence, data_quality,
            reasoning_bullets_json, label_scores_json, reply_strategy_json, evaluated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            evaluated_at=excluded.evaluated_at""",
        (
            organization_id,
            comment_id,
            result["rubric_version"],
            result["overall_score"],
            result["threshold"],
            result["recommended_action"],
            result["tier_label"],
            result["confidence"],
            result["data_quality"],
            json.dumps(result["reasoning_bullets"], ensure_ascii=False),
            json.dumps(result["label_scores"], ensure_ascii=False),
            json.dumps(result["reply_strategy"], ensure_ascii=False),
            now,
        ),
    )

    flags: list[str] = []
    bucket = result["bucket"]
    status = "needs_reply" if bucket in ("should_consult", "complaint", "praise") else "new"
    if bucket == "spam_clone":
        flags.append("spam_risk")
    elif bucket == "evidence":
        flags.append("defamation_evidence")
    elif bucket == "complaint":
        flags.append("complaint")
    elif bucket == "should_consult":
        flags.append("high_intent")

    for rule in db.execute(
        "SELECT * FROM rules WHERE organization_id=? AND enabled=1", (organization_id,)
    ).fetchall():
        pat = rule["pattern"]
        matched = False
        if rule["match_kind"] == "keyword":
            matched = pat.lower() in ctx["untrusted_comment_text"].lower()
        elif rule["match_kind"] == "author":
            matched = pat.lower() in ctx["author_name"].lower()
        elif rule["match_kind"] == "regex":
            try:
                matched = bool(re.search(pat, ctx["untrusted_comment_text"], re.IGNORECASE))
            except re.error:
                matched = False
        if matched:
            if rule["flag"] and rule["flag"] not in flags:
                flags.append(rule["flag"])
            status = rule["auto_status"]
            bucket = rule["auto_bucket"]

    existing_state = db.execute(
        "SELECT status, assigned_to, note, human_decision FROM comment_states WHERE organization_id=? AND comment_id=?",
        (organization_id, comment_id),
    ).fetchone()
    if existing_state and existing_state["status"] in ("replied", "hidden", "ignored"):
        status = existing_state["status"]

    db.execute(
        """INSERT INTO comment_states
           (organization_id, comment_id, status, bucket, assigned_to, note, flags_json, updated_by, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(organization_id, comment_id) DO UPDATE SET
            status=excluded.status,
            bucket=excluded.bucket,
            flags_json=excluded.flags_json,
            updated_by=excluded.updated_by,
            updated_at=excluded.updated_at""",
        (
            organization_id,
            comment_id,
            status,
            bucket,
            existing_state["assigned_to"] if existing_state else "",
            existing_state["note"] if existing_state else "",
            json.dumps(flags),
            actor,
            now,
        ),
    )

    strategy_summary = result["reply_strategy"].get("objective", "")
    for kind, draft_text in (("public", result["public_draft"]), ("private_dm", result["private_draft"])):
        if not draft_text:
            continue
        existing_draft = db.execute(
            """SELECT id, status FROM reply_drafts
               WHERE organization_id=? AND comment_id=? AND kind=?
               ORDER BY id DESC LIMIT 1""",
            (organization_id, comment_id, kind),
        ).fetchone()
        if existing_draft and existing_draft["status"] == "draft":
            db.execute(
                """UPDATE reply_drafts SET strategy_summary=?, text=?, updated_at=?
                   WHERE organization_id=? AND id=?""",
                (strategy_summary, draft_text, now, organization_id, existing_draft["id"]),
            )
        elif not existing_draft:
            db.execute(
                """INSERT INTO reply_drafts
                   (organization_id, comment_id, kind, strategy_summary, text, created_by, status, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, 'draft', ?, ?)""",
                (organization_id, comment_id, kind, strategy_summary, draft_text, actor, now, now),
            )

    return result


def record_feedback(
    db: sqlite3.Connection,
    organization_id: str,
    comment_id: int,
    *,
    label: str | None = None,
    agreed: bool | None = None,
    human_decision: int | None = None,
    actor: str = "owner",
) -> dict:
    """Record operator [✓]/[✕] label calibration or 1/2/3 quick decision."""
    now = int(time.time())
    valid_keys = {d["key"] for d in LABEL_DEFS} | {"_decision"}
    if label is not None:
        if label not in valid_keys or agreed is None:
            raise ValueError("Invalid rubric label or verdict")
        db.execute(
            """INSERT INTO evaluation_feedback
               (organization_id, comment_id, label, agreed, human_decision, actor, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(organization_id, comment_id, label) DO UPDATE SET
                agreed=excluded.agreed,
                human_decision=COALESCE(excluded.human_decision, evaluation_feedback.human_decision),
                actor=excluded.actor,
                created_at=excluded.created_at""",
            (organization_id, comment_id, label, 1 if agreed else 0, human_decision, actor, now),
        )

    if human_decision in (1, 2, 3):
        new_status = {1: "needs_reply", 2: "needs_reply", 3: "ignored"}[human_decision]
        new_bucket = {1: "should_consult", 2: "needs_review", 3: "negative"}[human_decision]
        db.execute(
            """INSERT INTO comment_states
               (organization_id, comment_id, status, bucket, human_decision, updated_by, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(organization_id, comment_id) DO UPDATE SET
                status=excluded.status,
                bucket=excluded.bucket,
                human_decision=excluded.human_decision,
                updated_by=excluded.updated_by,
                updated_at=excluded.updated_at""",
            (organization_id, comment_id, new_status, new_bucket, human_decision, actor, now),
        )
        if human_decision == 1:
            db.execute(
                """UPDATE reply_drafts SET status='approved', approved_by=?, updated_at=?
                   WHERE organization_id=? AND comment_id=? AND status='draft'""",
                (actor, now, organization_id, comment_id),
            )
        elif human_decision == 3:
            db.execute(
                """UPDATE reply_drafts SET status='rejected', updated_at=?
                   WHERE organization_id=? AND comment_id=? AND status='draft'""",
                (now, organization_id, comment_id),
            )

    return {
        "ok": True,
        "comment_id": comment_id,
        "label": label,
        "agreed": agreed,
        "human_decision": human_decision,
    }
