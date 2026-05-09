"""
engine.py — Inspection and Decision Engine
Public-Facing AI Agent Security Gateway

Sits between external website visitors and the company's AI agent backend.
All incoming messages from the public are inspected before reaching the AI.

ARCHITECTURE (May 2026 refactor):
  Layer 1:   Hugging Face Inference Providers — ProtectAI DeBERTa prompt-injection
             classifier. A transformer model trained specifically to detect adversarial
             prompt manipulation, jailbreaks, and injection attacks via semantic
             understanding rather than static keyword matching.
             Requires a FREE Hugging Face token (sign up at huggingface.co → Settings →
             Access Tokens → create a "fine-grained" token with Inference permissions).
             Set it as the HF_TOKEN environment variable.

  Layer 2:   OpenAI Moderation API — content-policy violation detector. Flags harmful,
             hateful, violent, or self-harm content before it reaches the AI agent.
             Free endpoint; requires OPENAI_API_KEY environment variable
             (platform.openai.com → API Keys).
             Both layers run together when keys are present; the worse result wins.

  Fallback:  Weighted regex rule engine — 32 hand-authored patterns across HIGH / MEDIUM
             tiers. Engages automatically when both API layers are unreachable (offline,
             rate limited, or missing tokens). Preserves full auditability and zero latency.
"""

import re
import os
from dataclasses import dataclass
from typing import List, Tuple, Optional


# ═══════════════════════════════════════════════════════════════════════════════
# HUGGING FACE API CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Model: ProtectAI DeBERTa v2 — fine-tuned for prompt injection detection
# Alternative: "meta-llama/Prompt-Guard-86M" (Meta's official prompt attack classifier)
HF_MODEL_ID = "protectai/deberta-v3-base-prompt-injection-v2"
HF_TIMEOUT = 8  # seconds before falling back to regex
HF_INJECTION_LABELS = {"INJECTION", "PROMPT_INJECTION", "ATTACK", "INJECTED", "JAILBREAK"}


# ═══════════════════════════════════════════════════════════════════════════════
# OPENAI MODERATION API CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Free content-policy moderation endpoint — complements HF prompt-injection detection
# Requires OPENAI_API_KEY environment variable (platform.openai.com → API Keys)
OPENAI_TIMEOUT = 8  # seconds before treating as unavailable


# ═══════════════════════════════════════════════════════════════════════════════
# RISK TIER DEFINITIONS (shared by both engines)
# ═══════════════════════════════════════════════════════════════════════════════

# Custom patterns added at runtime via the Pattern Editor page (session-level)
# Each entry: (pattern, reason, tier)  where tier is "HIGH" or "MEDIUM"
CUSTOM_PATTERNS: List[Tuple[str, str, str]] = []

# Confidence level per rule reason (shown in the Confidence Explanation panel)
RULE_CONFIDENCE: dict = {
    # ── Regex rules (fallback engine) ─────────────────────────────────────
    "Instruction override attempt detected": ("Critical", "#ef4444"),
    "Bypass directive detected":             ("Critical", "#ef4444"),
    "Override command detected":             ("Critical", "#ef4444"),
    "Sensitive data extraction attempt":     ("Critical", "#ef4444"),
    "Credential-related keyword":            ("High",     "#f97316"),
    "Privilege escalation attempt":          ("Critical", "#ef4444"),
    "System prompt probe":                   ("Critical", "#ef4444"),
    "Jailbreak keyword detected":            ("Critical", "#ef4444"),
    "DAN-style attack pattern":              ("Critical", "#ef4444"),
    "DAN attack signature":                  ("Critical", "#ef4444"),
    "Memory wipe attempt":                   ("High",     "#f97316"),
    "Persona hijack attempt":                ("High",     "#f97316"),
    "Disregard directive detected":          ("High",     "#f97316"),
    "Confidential data probe":               ("High",     "#f97316"),
    "Internal data extraction attempt":      ("Critical", "#ef4444"),
    "Customer data extraction attempt":      ("Critical", "#ef4444"),
    "Data leak attempt":                     ("High",     "#f97316"),
    "System instruction probing":            ("High",     "#f97316"),
    "Role-play directive":                   ("Medium",   "#f59e0b"),
    "Persona simulation keyword":            ("Medium",   "#f59e0b"),
    "Simulation request":                    ("Low",      "#22c55e"),
    "Role-play request":                     ("Medium",   "#f59e0b"),
    "Hypothetical persona framing":          ("Medium",   "#f59e0b"),
    "Disclaimer bypass pattern":             ("Medium",   "#f59e0b"),
    "Hypothetical framing":                  ("Medium",   "#f59e0b"),
    "Theory framing attempt":                ("Low",      "#22c55e"),
    "Conditional persona shift":             ("Medium",   "#f59e0b"),
    "Restriction removal request":           ("High",     "#f97316"),
    "Unfiltered response request":           ("High",     "#f97316"),
    "Off-record conversation attempt":       ("Medium",   "#f59e0b"),
    "Informal trust manipulation":           ("Low",      "#22c55e"),
    "Social engineering probe":              ("Medium",   "#f59e0b"),
    # ── ML classifier rules (primary engine) ──────────────────────────────
    "ML semantic classifier: prompt injection detected": ("Critical", "#ef4444"),
    "ML semantic classifier: suspicious content flagged": ("High",     "#f97316"),
    # ── OpenAI moderation rules (secondary engine) ────────────────────────
    "OpenAI moderation: content policy violation detected": ("Critical", "#ef4444"),
    "OpenAI moderation: suspicious content detected":       ("High",     "#f97316"),
}

HIGH_PATTERNS: List[Tuple[str, str]] = [
    (r"\bignore\s+(previous|all|prior)\s+(instructions?|rules?|context)\b",
     "Instruction override attempt detected"),
    (r"\bbypass\b",                    "Bypass directive detected"),
    (r"\boverride\b",                  "Override command detected"),
    (r"\breveal\b",                    "Sensitive data extraction attempt"),
    (r"\bpassword\b",                  "Credential-related keyword"),
    (r"\badmin\s*access\b",            "Privilege escalation attempt"),
    (r"\bsystem\s*prompt\b",           "System prompt probe"),
    (r"\bjailbreak\b",                 "Jailbreak keyword detected"),
    (r"\bdo\s*anything\s*now\b",       "DAN-style attack pattern"),
    (r"\bdan\b",                       "DAN attack signature"),
    (r"\bforget\s+(your|all|previous)\b", "Memory wipe attempt"),
    (r"\byou\s+are\s+now\b",           "Persona hijack attempt"),
    (r"\bdisregard\b",                 "Disregard directive detected"),
    (r"\bconfidential\b",              "Confidential data probe"),
    (r"\binternal\s*(data|documents?|records?)\b", "Internal data extraction attempt"),
    (r"\bcustomer\s*(data|records?|database)\b",   "Customer data extraction attempt"),
    (r"\bleake?d?\b",                  "Data leak attempt"),
    (r"\bwhat\s+(are\s+)?your\s+(instructions?|rules?|guidelines?)\b",
     "System instruction probing"),
]

MEDIUM_PATTERNS: List[Tuple[str, str]] = [
    (r"\bact\s+as\b",                  "Role-play directive"),
    (r"\bpretend\b",                   "Persona simulation keyword"),
    (r"\bsimulate\b",                  "Simulation request"),
    (r"\brole\s*play\b",               "Role-play request"),
    (r"\bimagine\s+you\s+are\b",       "Hypothetical persona framing"),
    (r"\bfor\s+educational\s+purposes\b", "Disclaimer bypass pattern"),
    (r"\bhypothetically\b",            "Hypothetical framing"),
    (r"\bin\s+theory\b",               "Theory framing attempt"),
    (r"\bwhat\s+if\s+you\s+(were|had|could)\b", "Conditional persona shift"),
    (r"\bno\s+restrictions?\b",        "Restriction removal request"),
    (r"\bunfiltered\b",                "Unfiltered response request"),
    (r"\boff\s+the\s+record\b",        "Off-record conversation attempt"),
    (r"\bbetween\s+us\b",              "Informal trust manipulation"),
    (r"\btell\s+me\s+a\s+secret\b",    "Social engineering probe"),
]

# Weighted scoring — per matched rule (regex fallback only)
SCORE_PER_HIGH   = 25
SCORE_PER_MEDIUM = 10
SCORE_PER_CUSTOM_HIGH   = 25
SCORE_PER_CUSTOM_MEDIUM = 10
SCORE_LENGTH_WARN  = 15
SCORE_LENGTH_ALERT = 30
SCORE_MIN_LOW    = 10

# Decision map (shared by both engines)
DECISION_MAP = {
    "LOW":    ("ALLOW",  "#22c55e"),
    "MEDIUM": ("FLAG",   "#f59e0b"),
    "HIGH":   ("BLOCK",  "#ef4444"),
}

RISK_COLORS = {
    "LOW":    "#22c55e",
    "MEDIUM": "#f59e0b",
    "HIGH":   "#ef4444",
}

RISK_ICONS = {
    "LOW":    "✅",
    "MEDIUM": "⚠️",
    "HIGH":   "🚨",
}

# Numeric rank for comparing risk tiers
RISK_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


@dataclass
class InspectionResult:
    risk_level: str
    score: int
    action: str
    action_color: str
    risk_color: str
    icon: str
    matched_rules: List[str]
    explanation: str
    tokens_scanned: int
    prompt_length: int
    length_anomaly: bool


# ═══════════════════════════════════════════════════════════════════════════════
# HUGGING FACE API — SEMANTIC CLASSIFIER
# ═══════════════════════════════════════════════════════════════════════════════

def _hf_classify(prompt: str) -> Optional[float]:
    """
    Call the Hugging Face Inference Providers API with the ProtectAI DeBERTa model.

    Uses the modern huggingface_hub InferenceClient (replaces the deprecated
    api-inference.huggingface.co REST endpoint). Requires HF_TOKEN env var.

    Returns the injection probability (0.0 = safe, 1.0 = attack) or None if
    the API is unreachable, the token is missing, or any error occurs.
    When None is returned, the caller falls back to the regex engine.
    """
    try:
        from huggingface_hub import InferenceClient

        token = os.environ.get("HF_TOKEN")
        if not token:
            return None  # no token → fall back to regex silently

        client = InferenceClient(provider="hf-inference", api_key=token, timeout=HF_TIMEOUT)
        result = client.text_classification(prompt, model=HF_MODEL_ID)

        # result is a list of dicts: [{"label": "INJECTION", "score": 0.97}, ...]
        if isinstance(result, list) and len(result) > 0:
            results_list = result[0] if isinstance(result[0], list) else result
            if isinstance(results_list, list):
                injection_entry = next(
                    (r for r in results_list if r.get("label", "").upper() in HF_INJECTION_LABELS),
                    None,
                )
                if injection_entry:
                    return float(injection_entry["score"])
                return float(max(results_list, key=lambda x: x.get("score", 0))["score"])
            elif isinstance(results_list, dict):
                if results_list.get("label", "").upper() in HF_INJECTION_LABELS:
                    return float(results_list["score"])
                return float(results_list.get("score", 0))

        return None

    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# OPENAI MODERATION API — CONTENT POLICY CLASSIFIER
# ═══════════════════════════════════════════════════════════════════════════════

def _openai_moderate(prompt: str) -> Optional[dict]:
    """
    Call the OpenAI Moderation endpoint (omni-moderation-latest).

    Free endpoint that checks for harmful, hateful, violent, or self-harm content.
    Complements the HF prompt-injection classifier by catching content-policy
    violations that are orthogonal to prompt injection.

    Returns a dict with 'flagged', 'max_score', 'top_category', 'flagged_categories'
    or None if the API is unreachable or OPENAI_API_KEY is not set.
    """
    try:
        from openai import OpenAI

        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            return None

        client = OpenAI(api_key=api_key, timeout=OPENAI_TIMEOUT)
        response = client.moderations.create(
            input=prompt,
            model="text-moderation-latest",
        )
        result = response.results[0]

        try:
            scores = result.category_scores.model_dump()
            categories = result.categories.model_dump()
        except AttributeError:
            try:
                scores = dict(vars(result.category_scores))
                categories = dict(vars(result.categories))
            except Exception:
                scores = {}
                categories = {}

        flagged_cats = [k for k, v in categories.items() if v]
        top_cat = max(scores, key=lambda k: scores[k]) if scores else "unknown"
        max_score = float(scores.get(top_cat, 0))

        return {
            "flagged":            result.flagged,
            "flagged_categories": flagged_cats,
            "max_score":          max_score,
            "top_category":       top_cat,
        }

    except Exception:
        return None


def _result_from_hf(
    injection_score: float,
    prompt: str,
    prompt_length: int,
    tokens_scanned: int,
) -> InspectionResult:
    """Build an InspectionResult from the Hugging Face classifier output."""
    score_int = int(injection_score * 100)
    length_anomaly = prompt_length > 500

    # ── Classify into risk tier ───────────────────────────────────────────
    if injection_score >= 0.70:
        risk = "HIGH"
        matched_rules = ["ML semantic classifier: prompt injection detected"]
    elif injection_score >= 0.30:
        risk = "MEDIUM"
        matched_rules = ["ML semantic classifier: suspicious content flagged"]
    else:
        risk = "LOW"
        matched_rules = []

    # ── Clamp score to tier band ──────────────────────────────────────────
    if risk == "LOW":
        score = max(SCORE_MIN_LOW, min(24, score_int))
    elif risk == "MEDIUM":
        score = max(25, min(59, score_int))
    else:
        score = max(60, min(100, score_int))

    action, action_color = DECISION_MAP[risk]
    risk_color = RISK_COLORS[risk]
    icon = RISK_ICONS[risk]

    explanation = _build_explanation(
        risk, matched_rules, length_anomaly, prompt_length, method="hf", confidence_pct=score
    )

    return InspectionResult(
        risk_level=risk,
        score=score,
        action=action,
        action_color=action_color,
        risk_color=risk_color,
        icon=icon,
        matched_rules=matched_rules,
        explanation=explanation,
        tokens_scanned=tokens_scanned,
        prompt_length=prompt_length,
        length_anomaly=length_anomaly,
    )


def _result_from_openai(
    openai_result: dict,
    prompt_length: int,
    tokens_scanned: int,
) -> InspectionResult:
    """Build an InspectionResult from the OpenAI Moderation API output."""
    flagged    = openai_result["flagged"]
    max_score  = openai_result["max_score"]
    top_cat    = openai_result["top_category"].replace("_", " ").replace("/", " / ")
    flagged_cats = openai_result["flagged_categories"]

    score_int     = int(max_score * 100)
    length_anomaly = prompt_length > 500

    if flagged:
        risk = "HIGH"
        cats_str = ", ".join(c.replace("_", " ") for c in flagged_cats) if flagged_cats else top_cat
        matched_rules = ["OpenAI moderation: content policy violation detected"]
        extra_detail  = cats_str
    elif max_score >= 0.30:
        risk = "MEDIUM"
        matched_rules = ["OpenAI moderation: suspicious content detected"]
        extra_detail  = top_cat
    else:
        risk = "LOW"
        matched_rules = []
        extra_detail  = ""

    if risk == "LOW":
        score = max(SCORE_MIN_LOW, min(24, score_int))
    elif risk == "MEDIUM":
        score = max(25, min(59, score_int))
    else:
        score = max(60, min(100, score_int))

    action, action_color = DECISION_MAP[risk]
    risk_color = RISK_COLORS[risk]
    icon       = RISK_ICONS[risk]

    explanation = _build_explanation(
        risk, matched_rules, length_anomaly, prompt_length,
        method="openai", confidence_pct=score, extra_detail=extra_detail,
    )

    return InspectionResult(
        risk_level=risk,
        score=score,
        action=action,
        action_color=action_color,
        risk_color=risk_color,
        icon=icon,
        matched_rules=matched_rules,
        explanation=explanation,
        tokens_scanned=tokens_scanned,
        prompt_length=prompt_length,
        length_anomaly=length_anomaly,
    )


def _result_from_combined(
    hf_score: float,
    openai_result: dict,
    prompt: str,
    prompt_length: int,
    tokens_scanned: int,
) -> InspectionResult:
    """Merge HF and OpenAI results — the worse risk level wins."""
    hf_res = _result_from_hf(hf_score, prompt, prompt_length, tokens_scanned)
    oa_res = _result_from_openai(openai_result, prompt_length, tokens_scanned)

    dominant   = hf_res if RISK_RANK[hf_res.risk_level] >= RISK_RANK[oa_res.risk_level] else oa_res
    secondary  = oa_res if dominant is hf_res else hf_res

    combined_rules = dominant.matched_rules + [
        r for r in secondary.matched_rules if r not in dominant.matched_rules
    ]
    combined_score  = max(hf_res.score, oa_res.score)
    length_anomaly  = prompt_length > 500

    explanation = _build_explanation(
        dominant.risk_level, combined_rules, length_anomaly, prompt_length,
        method="combined", confidence_pct=combined_score,
    )

    return InspectionResult(
        risk_level=dominant.risk_level,
        score=combined_score,
        action=dominant.action,
        action_color=dominant.action_color,
        risk_color=dominant.risk_color,
        icon=dominant.icon,
        matched_rules=combined_rules,
        explanation=explanation,
        tokens_scanned=tokens_scanned,
        prompt_length=prompt_length,
        length_anomaly=length_anomaly,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# REGEX FALLBACK ENGINE (preserved from original)
# ═══════════════════════════════════════════════════════════════════════════════

def _result_from_regex(
    prompt: str,
    normalized: str,
    prompt_length: int,
    tokens_scanned: int,
) -> InspectionResult:
    """Build an InspectionResult from the weighted regex rule engine."""
    matched_high:   List[str] = []
    matched_medium: List[str] = []

    for pattern, reason in HIGH_PATTERNS:
        if re.search(pattern, normalized):
            matched_high.append(reason)

    for pattern, reason in MEDIUM_PATTERNS:
        if re.search(pattern, normalized):
            matched_medium.append(reason)

    for pattern, reason, tier in CUSTOM_PATTERNS:
        try:
            if re.search(pattern, normalized):
                if tier == "HIGH":
                    matched_high.append(f"[Custom] {reason}")
                else:
                    matched_medium.append(f"[Custom] {reason}")
        except re.error:
            pass

    length_anomaly = prompt_length > 500
    length_score_bonus = 0
    if prompt_length > 1000:
        length_score_bonus = SCORE_LENGTH_ALERT
    elif prompt_length > 500:
        length_score_bonus = SCORE_LENGTH_WARN

    raw_score = (
        len(matched_high)   * SCORE_PER_HIGH +
        len(matched_medium) * SCORE_PER_MEDIUM +
        length_score_bonus
    )

    if matched_high or raw_score >= 60:
        risk = "HIGH"
        matched_rules = matched_high + matched_medium
    elif matched_medium or raw_score >= 25:
        risk = "MEDIUM"
        matched_rules = matched_medium
    else:
        risk = "LOW"
        matched_rules = []

    if risk == "LOW":
        score = max(SCORE_MIN_LOW, min(24, raw_score + SCORE_MIN_LOW))
    elif risk == "MEDIUM":
        score = max(25, min(59, raw_score))
    else:
        score = max(60, min(100, raw_score))

    action, action_color = DECISION_MAP[risk]
    risk_color = RISK_COLORS[risk]
    icon = RISK_ICONS[risk]

    explanation = _build_explanation(
        risk, matched_rules, length_anomaly, prompt_length, method="regex"
    )

    return InspectionResult(
        risk_level=risk,
        score=score,
        action=action,
        action_color=action_color,
        risk_color=risk_color,
        icon=icon,
        matched_rules=matched_rules,
        explanation=explanation,
        tokens_scanned=tokens_scanned,
        prompt_length=prompt_length,
        length_anomaly=length_anomaly,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════════

def sanitise_prompt(prompt: str) -> str:
    """Return a redacted version of the prompt with dangerous patterns replaced."""
    sanitised = prompt
    for pattern, _ in HIGH_PATTERNS:
        sanitised = re.sub(pattern, "[REDACTED]", sanitised, flags=re.IGNORECASE)
    for pattern, _ in MEDIUM_PATTERNS:
        sanitised = re.sub(pattern, "[FLAGGED]", sanitised, flags=re.IGNORECASE)
    for pattern, _, tier in CUSTOM_PATTERNS:
        tag = "[REDACTED]" if tier == "HIGH" else "[FLAGGED]"
        sanitised = re.sub(pattern, tag, sanitised, flags=re.IGNORECASE)
    return sanitised


def inspect_prompt(prompt: str) -> InspectionResult:
    """
    Inspect a user-submitted prompt for adversarial content.

    Layer 1 (HF):     Hugging Face semantic classifier — detects prompt injection,
                      jailbreaks, and manipulation via transformer-based understanding.
    Layer 2 (OpenAI): OpenAI Moderation API — detects content-policy violations
                      (harmful, hateful, violent, or self-harm content).
    Combined:         When both keys are present both layers run; the worse result wins.
    Fallback:         Weighted regex rule engine — engages when both API layers fail.
    """
    normalized = prompt.lower().strip()
    tokens_scanned = len(normalized.split())
    prompt_length = len(prompt)

    # ── Run all layers (regex always runs as a baseline) ─────────────────
    hf_score      = _hf_classify(prompt)
    openai_result = _openai_moderate(prompt)
    regex_result  = _result_from_regex(prompt, normalized, prompt_length, tokens_scanned)

    # ── Build candidate list and pick the worst risk ──────────────────────
    candidates = [regex_result]

    if hf_score is not None and openai_result is not None:
        candidates.append(_result_from_combined(hf_score, openai_result, prompt, prompt_length, tokens_scanned))
    elif hf_score is not None:
        candidates.append(_result_from_hf(hf_score, prompt, prompt_length, tokens_scanned))
    elif openai_result is not None:
        candidates.append(_result_from_openai(openai_result, prompt_length, tokens_scanned))

    # Return the result with the highest risk rank (most conservative)
    return max(candidates, key=lambda r: (RISK_RANK[r.risk_level], r.score))


# ═══════════════════════════════════════════════════════════════════════════════
# EXPLANATION BUILDER
# ═══════════════════════════════════════════════════════════════════════════════

def _build_explanation(
    risk: str,
    rules: List[str],
    length_anomaly: bool = False,
    prompt_length: int = 0,
    method: str = "regex",
    confidence_pct: int = 0,
    extra_detail: str = "",
) -> str:
    length_note = ""
    if length_anomaly:
        length_note = (
            f" Additionally, the message length ({prompt_length} characters) exceeds "
            "the normal threshold and has been flagged as a length anomaly — "
            "unusually long messages are a common vector for prompt injection attacks."
        )

    # ── Hugging Face classifier explanations ──────────────────────────────
    if method == "hf":
        if risk == "HIGH":
            return (
                f"A transformer-based semantic classifier (ProtectAI DeBERTa) has "
                f"identified this message as a prompt injection attack with "
                f"{confidence_pct}% confidence. The gateway has blocked this message "
                f"— it will not reach the company's AI agent. This classification was "
                f"performed by a machine-learning model trained specifically to detect "
                f"adversarial prompt manipulation, rather than relying on static "
                f"keyword patterns.{length_note}"
            )
        elif risk == "MEDIUM":
            return (
                f"The semantic classifier flagged potentially manipulative language "
                f"in this request with {confidence_pct}% confidence. The message has "
                f"been held for security team review before any response is issued. "
                f"This protects the AI agent from subtle manipulation techniques that "
                f"may evade simpler detection methods.{length_note}"
            )
        else:
            return (
                "No injection or manipulation patterns were detected by the semantic "
                "classifier. The message passed the machine-learning inspection layer "
                "and has been forwarded to the company's AI agent for processing."
                f"{length_note}"
            )

    # ── OpenAI moderation explanations ─────────────────────────────────
    if method == "openai":
        detail_note = f" ({extra_detail})" if extra_detail else ""
        if risk == "HIGH":
            return (
                f"OpenAI's content moderation API flagged this message as a policy "
                f"violation{detail_note} with {confidence_pct}% confidence. The gateway "
                f"has blocked this message — it will not reach the company's AI agent. "
                f"This layer detects harmful, hateful, violent, or self-harm content "
                f"that is independent of prompt injection attacks.{length_note}"
            )
        elif risk == "MEDIUM":
            return (
                f"OpenAI's content moderation API identified potentially policy-violating "
                f"content in this request{detail_note} ({confidence_pct}% confidence). "
                f"The message has been held for security team review before any response "
                f"is issued.{length_note}"
            )
        else:
            return (
                "OpenAI's content moderation API found no policy violations in this "
                "request. The message passed the moderation layer and has been forwarded "
                f"to the company's AI agent for processing.{length_note}"
            )

    # ── Combined (HF + OpenAI) explanations ───────────────────────────
    if method == "combined":
        if risk == "HIGH":
            joined = "; ".join(rules)
            return (
                f"This message was assessed by two independent detection layers: the "
                f"Hugging Face ProtectAI DeBERTa prompt-injection classifier and OpenAI’s "
                f"content moderation API. Combined result: {joined}. The gateway has "
                f"blocked this message with {confidence_pct}% confidence — it will not "
                f"reach the company's AI agent.{length_note}"
            )
        elif risk == "MEDIUM":
            joined = "; ".join(rules)
            return (
                f"One or more detection layers flagged this message as suspicious "
                f"({confidence_pct}% confidence): {joined}. The message has been held "
                f"for security team review before any response is issued.{length_note}"
            )
        else:
            return (
                "Both detection layers (Hugging Face semantic classifier and OpenAI "
                "moderation) found no threats in this request. The message has been "
                f"forwarded to the company's AI agent for processing.{length_note}"
            )

    # ── Regex engine explanations (unchanged) ─────────────────────────────
    if risk == "HIGH":
        joined = "; ".join(rules)
        return (
            f"This external request triggered {len(rules)} rule(s) across inspection "
            f"tiers: {joined}. The gateway has blocked this message — it will not "
            f"reach the company's AI agent. This may indicate a prompt injection "
            f"attack, an attempt to extract confidential data, or an effort to "
            f"manipulate the AI's behavior.{length_note}"
        )
    elif risk == "MEDIUM":
        joined = "; ".join(rules)
        return (
            f"This external request matched {len(rules)} medium-severity pattern(s): "
            f"{joined}. The message has been flagged and is held for security team "
            f"review before any response is issued. This protects the AI agent from "
            f"subtle manipulation techniques used by external users.{length_note}"
        )
    else:
        base = (
            "No injection or manipulation patterns were detected in this request. "
            "The message passed all gateway inspection layers and has been forwarded "
            "to the company's AI agent for processing."
        )
        return base + length_note
