"""
features.py — URL feature extraction for phishing detection.

Extracts 31 lexical, domain-level, and structural features from a raw URL string.
These features are designed to be independent of external lookups (no DNS/WHOIS at
runtime) so inference is fast; the training script injects simulated WHOIS signals
via distribution-sampled values that mimic real dataset statistics.
"""

import re
import math
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any

# ---------------------------------------------------------------------------
# Reference sets
# ---------------------------------------------------------------------------
SUSPICIOUS_TLDS: set[str] = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
    ".top", ".xyz", ".club", ".work", ".party",
    ".click", ".link", ".date", ".download", ".racing",
}

SUSPICIOUS_KEYWORDS: list[str] = [
    "login", "signin", "sign-in", "secure", "update", "verify",
    "account", "banking", "paypal", "amazon", "google", "microsoft",
    "apple", "facebook", "ebay", "confirm", "password", "credential",
    "wallet", "alert", "suspend", "urgent", "click", "free",
    "prize", "winner", "lucky", "offer", "verify", "validation",
    "webscr", "cmd=", "dispatch", "reset",
]

BRAND_NAMES: list[str] = [
    "paypal", "amazon", "google", "microsoft", "apple", "facebook",
    "twitter", "instagram", "linkedin", "netflix", "spotify", "ebay",
    "walmart", "chase", "wellsfargo", "citibank", "bankofamerica",
    "americanexpress", "usbank", "capitalonebank", "hsbc",
]

_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_HEX_RE = re.compile(r"%[0-9a-fA-F]{2}")


def _entropy(s: str) -> float:
    """Shannon entropy of a string in bits."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_features(url: str) -> Dict[str, Any]:
    """Return a flat dict of numeric features for *url*."""
    # Ensure scheme so urlparse works correctly
    if "://" not in url:
        url_for_parse = "http://" + url
    else:
        url_for_parse = url

    try:
        parsed = urlparse(url_for_parse)
    except Exception:
        parsed = urlparse("http://invalid.invalid/")

    scheme: str = parsed.scheme or "http"
    netloc: str = parsed.netloc or ""
    path: str = parsed.path or ""
    query: str = parsed.query or ""

    # Strip port from netloc
    host = netloc.split(":")[0]

    # -------------------------------------------------------------------
    # Normalize: strip "www." prefix so that www.github.com and github.com
    # produce identical features.  This prevents the model from relying
    # on the presence/absence of "www." which is not a security signal.
    # -------------------------------------------------------------------
    if host.lower().startswith("www."):
        host = host[4:]
        # Rebuild a normalized URL string for raw counters
        port_part = ":" + netloc.split(":")[1] if ":" in netloc.split(".", 1)[-1] else ""
        url = f"{scheme}://{host}{port_part}{path}"
        if query:
            url += "?" + query
        if parsed.fragment:
            url += "#" + parsed.fragment

    # -------------------------------------------------------------------
    # Has-IP detection
    # -------------------------------------------------------------------
    has_ip = int(bool(_IP_RE.match(host)))

    # -------------------------------------------------------------------
    # Domain decomposition
    # -------------------------------------------------------------------
    parts = host.split(".")
    if has_ip or len(parts) < 2:
        domain = host
        tld = ""
        subdomains: list[str] = []
    else:
        tld = "." + parts[-1]
        domain = ".".join(parts[-2:])          # e.g. "google.com"
        subdomains = [p for p in parts[:-2] if p]

    subdomain_str = ".".join(subdomains)
    num_subdomains = len(subdomains)

    # -------------------------------------------------------------------
    # Raw URL counters
    # -------------------------------------------------------------------
    url_len = len(url)
    domain_len = len(domain)
    path_len = len(path)

    num_dots = url.count(".")
    num_hyphens = url.count("-")
    num_at = url.count("@")
    num_question = url.count("?")
    num_equals = url.count("=")
    num_percent = url.count("%")
    num_slash = path.count("/")
    num_ampersand = url.count("&")
    num_digits_url = sum(c.isdigit() for c in url)
    num_digits_domain = sum(c.isdigit() for c in domain)

    # -------------------------------------------------------------------
    # Structural flags
    # -------------------------------------------------------------------
    has_at_symbol = int("@" in url)
    # Double-slash *after* the scheme's //
    has_double_slash = int("//" in path)
    has_http_in_path = int("http" in path.lower())

    # -------------------------------------------------------------------
    # TLD & keyword signals
    # -------------------------------------------------------------------
    suspicious_tld = int(tld.lower() in SUSPICIOUS_TLDS)
    tld_len = len(tld)

    url_lower = url.lower()
    keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    brand_in_subdomain = int(any(b in subdomain_str.lower() for b in BRAND_NAMES))
    brand_in_domain_part = int(
        any(b in domain.lower().split(".")[0] for b in BRAND_NAMES)
    )

    # -------------------------------------------------------------------
    # Domain-level heuristics
    # -------------------------------------------------------------------
    domain_has_hyphen = int("-" in domain)
    long_subdomain = int(len(subdomain_str) > 20)

    # -------------------------------------------------------------------
    # Entropy
    # -------------------------------------------------------------------
    url_entropy = _entropy(url)
    domain_entropy = _entropy(domain)

    # -------------------------------------------------------------------
    # Misc
    # -------------------------------------------------------------------
    has_https = int(scheme == "https")
    url_depth = len([p for p in path.split("/") if p])
    num_params = len(parse_qs(query))
    hex_count = len(_HEX_RE.findall(url))

    return {
        "url_length": url_len,
        "domain_length": domain_len,
        "path_length": path_len,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_at": num_at,
        "num_question": num_question,
        "num_equals": num_equals,
        "num_percent": num_percent,
        "num_slash": num_slash,
        "num_ampersand": num_ampersand,
        "num_digits_url": num_digits_url,
        "num_digits_domain": num_digits_domain,
        "has_at_symbol": has_at_symbol,
        "has_double_slash": has_double_slash,
        "has_http_in_path": has_http_in_path,
        "suspicious_tld": suspicious_tld,
        "tld_length": tld_len,
        "keyword_count": keyword_count,
        "brand_in_subdomain": brand_in_subdomain,
        "brand_in_domain_part": brand_in_domain_part,
        "domain_has_hyphen": domain_has_hyphen,
        "long_subdomain": long_subdomain,
        "num_subdomains": num_subdomains,
        "has_ip": has_ip,
        "url_entropy": url_entropy,
        "domain_entropy": domain_entropy,
        "has_https": has_https,
        "url_depth": url_depth,
        "num_params": num_params,
        "hex_count": hex_count,
    }


# Canonical feature ordering (matches training column order)
FEATURE_NAMES: list[str] = list(extract_features("http://example.com").keys())

# ---------------------------------------------------------------------------
# Human-readable explanations keyed by feature name
# ---------------------------------------------------------------------------
FEATURE_EXPLANATIONS: Dict[str, Dict[str, Any]] = {
    "has_ip": {
        "label": "IP address used as host",
        "template": "URL uses a raw IP address instead of a domain name — a strong phishing indicator.",
        "threshold": 1,
        "severity": "critical",
    },
    "suspicious_tld": {
        "label": "Suspicious top-level domain",
        "template": "TLD is associated with free/abused registrars (e.g., .tk, .ml, .ga).",
        "threshold": 1,
        "severity": "high",
    },
    "brand_in_subdomain": {
        "label": "Brand name in subdomain",
        "template": "A known brand appears in the subdomain — classic impersonation tactic.",
        "threshold": 1,
        "severity": "high",
    },
    "keyword_count": {
        "label": "Phishing-related keywords",
        "template": "{value} phishing-related keyword(s) found in the URL (e.g., 'login', 'verify', 'secure').",
        "threshold": 1,
        "severity": "high",
    },
    "has_at_symbol": {
        "label": "@ symbol in URL",
        "template": "The @ character forces browsers to treat everything before it as credentials.",
        "threshold": 1,
        "severity": "critical",
    },
    "has_double_slash": {
        "label": "Double-slash redirect in path",
        "template": "A '//' found in the URL path indicates a potential open-redirect attack.",
        "threshold": 1,
        "severity": "high",
    },
    "has_http_in_path": {
        "label": "HTTP/HTTPS embedded in path",
        "template": "The URL path contains 'http', suggesting a redirect or cloaking attack.",
        "threshold": 1,
        "severity": "critical",
    },
    "url_length": {
        "label": "Abnormally long URL",
        "template": "URL length of {value} characters — long URLs are often used to hide destination.",
        "threshold": 75,
        "severity": "medium",
    },
    "num_subdomains": {
        "label": "Excessive subdomains",
        "template": "{value} subdomain(s) detected — attackers chain subdomains to mimic legitimate paths.",
        "threshold": 2,
        "severity": "medium",
    },
    "domain_has_hyphen": {
        "label": "Hyphen in domain",
        "template": "Domain contains a hyphen — frequently used in typosquatting attacks.",
        "threshold": 1,
        "severity": "low",
    },
    "long_subdomain": {
        "label": "Unusually long subdomain",
        "template": "Subdomain string is >20 characters — common evasion technique.",
        "threshold": 1,
        "severity": "medium",
    },
    "num_digits_domain": {
        "label": "Digits in domain name",
        "template": "{value} digit(s) in the domain name — unusual for legitimate organisations.",
        "threshold": 2,
        "severity": "low",
    },
    "hex_count": {
        "label": "Percent-encoded characters",
        "template": "{value} percent-encoded character(s) found — may be used to obfuscate the destination.",
        "threshold": 2,
        "severity": "medium",
    },
    "url_depth": {
        "label": "Deep URL path",
        "template": "URL has {value} path segment(s) — unusually deep paths may hide malicious resources.",
        "threshold": 4,
        "severity": "low",
    },
    "has_https": {
        "label": "No HTTPS encryption",
        "template": "Connection is plain HTTP (not encrypted). Modern phishing sites also use HTTPS, but its absence is suspicious.",
        "threshold": 0,  # flag when value == 0
        "severity": "medium",
        "flag_when_zero": True,
    },
    "brand_in_domain_part": {
        "label": "Brand name in domain",
        "template": "A known brand name is embedded in the registered domain — possible lookalike domain.",
        "threshold": 1,
        "severity": "high",
    },
    "url_entropy": {
        "label": "High URL entropy",
        "template": "URL entropy of {value:.2f} bits — high entropy suggests random/obfuscated characters.",
        "threshold": 4.5,
        "severity": "medium",
    },
}


def get_suspicious_features(features: Dict[str, Any]) -> list[Dict[str, str]]:
    """
    Return a list of triggered suspicious feature explanations sorted by severity.
    """
    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings = []

    for key, meta in FEATURE_EXPLANATIONS.items():
        value = features.get(key, 0)
        flag_when_zero = meta.get("flag_when_zero", False)

        triggered = False
        if flag_when_zero and value == 0:
            triggered = True
        elif not flag_when_zero and value >= meta["threshold"]:
            triggered = True

        if triggered:
            tmpl: str = meta["template"]
            description = (
                tmpl.format(value=value)
                if "{value" in tmpl
                else tmpl
            )
            findings.append(
                {
                    "label": meta["label"],
                    "description": description,
                    "severity": meta["severity"],
                }
            )

    findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 9))
    return findings
