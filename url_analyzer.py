"""
url_analyzer.py

ENTERPRISE URL ANALYSIS & DECISION ENGINE (v2.2)

Design principles:
- Deterministic-first detection
- ML-assisted, never ML-dependent
- Advanced brand impersonation
- Fail-safe (never break production)
- Learning-safe (observe, do not auto-adapt)
"""

from urllib.parse import urlparse
import ipaddress
import re
from typing import Tuple, Dict

# =========================
# OPTIONAL ML IMPORT
# =========================

try:
    from model import predict_proba, MODEL_VERSION as ML_MODEL_VERSION
    ML_AVAILABLE = True
except Exception:
    ML_AVAILABLE = False
    ML_MODEL_VERSION = "ml-unavailable"

    def predict_proba(_: str, __: str) -> float:
        return 0.0

# =========================
# OPTIONAL LEARNING IMPORT
# =========================

try:
    from learning.logger import store_learning_sample
    LEARNING_ENABLED = True
except Exception:
    LEARNING_ENABLED = False

# =========================
# VERSIONING
# =========================

ANALYZER_VERSION = "analyzer-v2.2.0"

# =========================
# CONFIGURATION
# =========================

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "club", "click",
    "support", "loan", "cf", "gq", "ml"
}

PHISHING_KEYWORDS = {
    "login", "signin", "verify", "secure",
    "account", "update", "confirm",
    "billing", "payment", "reset"
}

# =========================
# BRAND DEFINITIONS
# =========================

BRANDS = {
    "paypal": {
        "official_domains": {
            "paypal.com",
            "paypalobjects.com"
        }
    },
    "google": {
        "official_domains": {
            "google.com",
            "googleapis.com",
            "accounts.google.com"
        }
    },
    "microsoft": {
        "official_domains": {
            "microsoft.com",
            "microsoftonline.com",
            "live.com",
            "office.com"
        }
    },
    "amazon": {
        "official_domains": {
            "amazon.com",
            "amazon.in",
            "aws.amazon.com"
        }
    }
}

# Common homoglyph tricks
HOMOGLYPHS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "@": "a"
}

# =========================
# URL UTILITIES
# =========================

def normalize_url(url: str) -> str:
    if not url:
        return ""
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".lower().rstrip("/")

def extract_domain(url: str) -> str:
    if not url:
        return ""
    if "://" not in url:
        url = "http://" + url
    return urlparse(url).netloc.split(":")[0].lower()

def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False

def tokenize_domain(domain: str):
    return [p for p in re.split(r"[.\-_]", domain) if p]

def deobfuscate(text: str) -> str:
    for fake, real in HOMOGLYPHS.items():
        text = text.replace(fake, real)
    return text

# =========================
# HEURISTIC SIGNALS
# =========================

def heuristic_score(url: str) -> int:
    domain = extract_domain(url)
    score = 0

    if len(url) > 90:
        score += 2
    if "@" in url:
        score += 3
    if is_ip_address(domain):
        score += 4
    if domain.count("-") >= 2:
        score += 2
    if len(domain) > 25:
        score += 2
    if any(k in url for k in PHISHING_KEYWORDS):
        score += 3
    if domain.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        score += 4

    return score

def reputation_score(domain: str) -> float:
    score = 0.0

    if domain.count("-") >= 2:
        score += 0.3
    if any(c.isdigit() for c in domain):
        score += 0.2
    if domain.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
        score += 0.5

    return min(score, 1.0)

# =========================
# ADVANCED BRAND IMPERSONATION
# =========================

def advanced_brand_impersonation(url: str):
    parsed = urlparse(url if "://" in url else "http://" + url)
    domain = parsed.netloc.split(":")[0].lower()
    path = parsed.path.lower()

    tokens = tokenize_domain(domain)
    clean_domain = deobfuscate(domain)

    confidence = 0.0
    reasons = []

    for brand, meta in BRANDS.items():
        brand_clean = deobfuscate(brand)

        brand_claimed = (
            brand in tokens or
            brand_clean in clean_domain or
            brand in path
        )

        if not brand_claimed:
            continue

        # Authorized domains
        if domain in meta["official_domains"] or any(
            domain.endswith("." + d) for d in meta["official_domains"]
        ):
            continue

        reasons.append(f"unauthorized_brand:{brand}")
        confidence += 0.6

        if domain.startswith(brand) or f".{brand}." in domain:
            reasons.append("brand_in_subdomain")
            confidence += 0.2

        if any(k in path for k in PHISHING_KEYWORDS):
            reasons.append("credential_harvesting_intent")
            confidence += 0.2

    confidence = min(confidence, 1.0)

    if confidence >= 0.6:
        return True, round(confidence, 2), {
            "domain": domain,
            "reasons": reasons
        }

    return False, 0.0, {}

# =========================
# CORE ANALYSIS
# =========================

def analyze_url(url: str) -> Tuple[str, float, Dict]:
    """
    Final production decision engine.
    Returns: (decision, confidence, metadata)
    """

    try:
        normalized = normalize_url(url)
        domain = extract_domain(normalized)

        if not normalized or not domain:
            return "legitimate", 0.0, {
                "reason": "invalid_url",
                "analyzer_version": ANALYZER_VERSION
            }

        heuristics = heuristic_score(normalized)
        reputation = reputation_score(domain)
        ml_score = predict_proba("", normalized) if ML_AVAILABLE else 0.0

        # =====================
        # HARD PHISHING RULES
        # =====================

        if is_ip_address(domain):
            decision = "phishing"
            confidence = 1.0
            metadata = {"reason": "ip_based_url"}

        else:
            brand_hit, brand_conf, brand_data = advanced_brand_impersonation(normalized)

            if brand_hit:
                decision = "phishing"
                confidence = brand_conf
                metadata = {
                    "reason": "brand_impersonation",
                    **brand_data
                }

            elif heuristics >= 8:
                decision = "phishing"
                confidence = 0.95
                metadata = {
                    "reason": "high_heuristic_score",
                    "heuristics": heuristics
                }

            else:
                # =====================
                # RISK AGGREGATION
                # =====================
                risk = 0.0
                risk += min(heuristics * 0.18, 0.55)
                risk += reputation * 0.30

                if ml_score >= 0.6:
                    risk += ml_score * 0.25

                risk = min(risk, 1.0)
                confidence = round(risk, 2)

                if risk >= 0.65:
                    decision = "phishing"
                elif risk >= 0.45:
                    decision = "suspicious"
                else:
                    decision = "legitimate"

                metadata = {
                    "heuristics": heuristics,
                    "reputation": round(reputation, 2),
                    "ml_probability": round(ml_score, 2),
                    "risk_score": confidence
                }

        # =====================
        # LEARNING (PRODUCTION POLICY)
        # =====================

        if LEARNING_ENABLED and decision in ("phishing", "suspicious"):
            try:
                store_learning_sample(
                    url=normalized,
                    verdict=decision,
                    risk_score=confidence,
                    heuristics=heuristics,
                    ml_score=ml_score,
                    brand=metadata.get("domain")
                )
            except Exception:
                pass  # learning must never break detection

        metadata.update({
            "decision": decision,
            "analyzer_version": ANALYZER_VERSION,
            "ml_model_version": ML_MODEL_VERSION
        })

        return decision, confidence, metadata

    except Exception:
        return "legitimate", 0.0, {
            "error": "analysis_failed",
            "analyzer_version": ANALYZER_VERSION
        }
