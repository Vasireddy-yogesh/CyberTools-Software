from urllib.parse import urlparse
from db.supabase_client import supabase
import datetime

def store_learning_sample(
    url: str,
    verdict: str,
    risk_score: float,
    heuristics: int,
    ml_score: float,
    brand: str = None
):
    """
    Store unknown but risky URLs for learning.
    This function must NEVER break detection.
    """

    try:
        # 🔍 DEBUG CONFIRMATION
        print("[LEARNING] storing:", url)

        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        tld = domain.split('.')[-1]
        path_tokens = parsed.path.strip("/").split("/") if parsed.path else []

        supabase.table("learning_urls").upsert({
            "url": url,
            "domain": domain,
            "verdict": verdict,
            "risk_score": risk_score,
            "heuristics": heuristics,
            "ml_score": ml_score,
            "brand": brand,
            "tld": tld,
            "path_tokens": path_tokens,
            "last_seen": datetime.datetime.utcnow().isoformat()
        }).execute()

    except Exception as e:
        # 🚨 Learning must NEVER crash production
        print("[LEARNING ERROR]", e)
