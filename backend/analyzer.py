"""VERIKLIK baseline detector: explainable URL heuristics. Never fetches the URL."""
import ipaddress, re
from datetime import datetime, timezone
from urllib.parse import urlsplit, unquote

BRANDS = ["paypal", "google", "microsoft", "apple", "amazon", "facebook",
          "netflix", "instagram", "whatsapp", "binance", "dropbox"]
COMMON_PORTS = {80, 443}


def parse_url(raw: str):
    """Validate and parse. Raises ValueError for anything not http(s)."""
    raw = (raw or "").strip()
    if not raw or len(raw) > 2048:
        raise ValueError("URL is empty or too long.")
    try:
        p = urlsplit(raw)
        port = p.port
    except ValueError:
        raise ValueError("Malformed URL.")
    if p.scheme.lower() not in ("http", "https"):
        raise ValueError("Only http and https URLs are supported.")
    if not p.hostname:
        raise ValueError("URL has no hostname.")
    return p, port


def analyze_url(raw: str) -> dict:
    raw = raw.strip()
    p, port = parse_url(raw)
    host = p.hostname.lower().rstrip(".")
    signals, passed = [], []

    def add(points, text):
        signals.append({"points": points, "text": text})

    is_ip = False
    try:
        ipaddress.ip_address(host); is_ip = True
    except ValueError:
        pass
    if is_ip:
        add(30, "Hostname is a raw IP address, not a domain name.")
    else:
        passed.append("Hostname is a domain name")
    if p.username is not None or p.password is not None or "@" in p.netloc:
        add(25, "URL embeds user information before the host (user@host), a common disguise.")
    else:
        passed.append("No embedded user information")
    labels = host.split(".")
    if any(l.startswith("xn--") for l in labels):
        add(20, "Hostname uses punycode (xn--), which can hide look-alike characters.")
    else:
        passed.append("No punycode labels")
    if not is_ip and len(labels) >= 5:
        add(10, f"Unusually many subdomains ({len(labels) - 2}).")
    if port is not None and port not in COMMON_PORTS:
        add(10, f"Unusual port {port}.")
    if not is_ip and len(labels) >= 2:
        # Approximation: last two labels as registered domain (no public-suffix list).
        reg = ".".join(labels[-2:])
        sub = ".".join(labels[:-2])
        hits = [b for b in BRANDS if b in sub and b != labels[-2]]
        if hits:
            add(25, f"Brand name '{hits[0]}' appears in a subdomain but the registered domain is '{reg}'.")
        elif any(b in labels[-2] and labels[-2] != b for b in BRANDS):
            add(15, "Domain combines a well-known brand name with extra text.")
    if len(raw) > 200:
        add(10, f"Very long URL ({len(raw)} characters).")
    elif len(raw) > 100:
        add(5, f"Long URL ({len(raw)} characters).")
    pct = len(re.findall(r"%[0-9a-fA-F]{2}", raw))
    if re.search(r"%25[0-9a-fA-F]{2}", raw):
        add(10, "Double-encoded characters found (possible obfuscation).")
    elif pct >= 8:
        add(5, f"Heavy percent-encoding ({pct} sequences).")
    else:
        passed.append("No suspicious encoding")
    if p.scheme.lower() == "http":
        add(5, "Connection is not encrypted (HTTP). HTTPS alone would not prove safety either.")

    score = min(100, sum(s["points"] for s in signals))
    category = "High Risk" if score >= 50 else "Suspicious" if score >= 20 else "Low Risk"
    rec = {"Low Risk": "No suspicious URL features found. This is not a guarantee of safety: "
                       "reputation was not verified. Be careful with logins and downloads.",
           "Suspicious": "Avoid entering credentials. Reach the site by typing its address yourself.",
           "High Risk": "Do not open this link or enter any information. Report it if it came by message."}[category]
    return {
        "submitted_url": raw, "hostname": host, "risk_score": score,
        "risk_category": category, "findings": signals, "checks_passed": passed,
        "checks_unavailable": ["Threat-intelligence reputation (not configured)",
                               "Domain age and page content (never fetched, by design)"],
        "threat_intel": {"status": "not_configured", "match": None},
        "recommendation": rec,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }
