import math
import re
from typing import Dict, Any, List, Optional
from app.detectors.url_detector import parse_url_components, KNOWN_BRAND_DOMAINS, DECEPTIVE_TERMS, calculate_str_entropy, brand_in_text

def calculate_entropy(text: str) -> float:
    return calculate_str_entropy(text)

def extract_url_features(url: str, http_metadata: Optional[Dict[str, Any]] = None) -> Dict[str, float]:
    """
    Extracts high-dimensional numerical feature vector for Supervised ML and Anomaly detection.
    Covers lexical, structural, userinfo deception, brand impersonation, and infrastructure signals.
    """
    http_metadata = http_metadata or {}
    parsed = parse_url_components(url)
    
    hostname = parsed["hostname"]
    userinfo = parsed["userinfo"]
    subdomains = parsed["subdomains"]
    path = parsed["path"]
    query = parsed["query"]
    registrable_domain = parsed["registrableDomain"]

    length = float(len(url))
    hostname_length = float(len(hostname))
    hostname_entropy = calculate_entropy(hostname)
    path_entropy = calculate_entropy(path)
    
    # Userinfo Deception Features
    has_userinfo = 1.0 if parsed["hasUserinfo"] else 0.0
    userinfo_length = float(len(userinfo))
    userinfo_entropy = calculate_entropy(userinfo)
    
    u_lower = userinfo.lower()
    userinfo_brand_hits = sum(1.0 for b in KNOWN_BRAND_DOMAINS if b in u_lower)
    userinfo_deceptive_hits = sum(1.0 for t in DECEPTIVE_TERMS if t in u_lower)
    userinfo_brand_keyword_count = float(userinfo_brand_hits * 2.0 + userinfo_deceptive_hits)
    userinfo_domain_like = 1.0 if re.search(r"(-tv|-com|-net|-org|\.com|\.tv|\.org|\.net|www-|http-|https-)", u_lower) else 0.0

    # Subdomain & Hostname Structure
    subdomain_length = float(len(subdomains))
    subdomain_depth = float(parsed["subdomainDepth"])
    hyphen_count = float(url.count("-"))
    subdomain_hyphen_count = float(subdomains.count("-"))
    
    is_tunnel_service = 1.0 if parsed["infrastructureProvider"] is not None else 0.0
    
    # Brand Keyword Signal (cross-vector)
    brand_keyword_signal = 0.0
    for brand, official_domain in KNOWN_BRAND_DOMAINS.items():
        brand_in_user = brand_in_text(brand, u_lower)
        brand_in_sub = brand_in_text(brand, subdomains.lower())
        brand_in_p = brand_in_text(brand, path.lower())
        is_official = (
            registrable_domain == official_domain or
            hostname == official_domain or
            hostname.endswith("." + official_domain) or
            official_domain.split(".")[0] in registrable_domain
        )
        if (brand_in_user or brand_in_sub or brand_in_p) and not is_official:
            brand_keyword_signal += 2.0
    
    # Structural features
    has_ip = 1.0 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname) else 0.0
    is_punycode = 1.0 if "xn--" in hostname.lower() else 0.0
    
    digit_count = sum(c.isdigit() for c in url)
    digit_ratio = round(digit_count / length if length > 0 else 0.0, 4)
    
    special_chars = sum(not c.isalnum() for c in url)
    special_char_ratio = round(special_chars / length if length > 0 else 0.0, 4)
    
    encoded_count = url.count("%")
    encoded_ratio = round(encoded_count / length if length > 0 else 0.0, 4)
    
    query_param_count = float(len(query.split("&"))) if query else 0.0
    
    # Global Suspicious Keywords
    url_lower = url.lower()
    keyword_hits = float(sum(term in url_lower for term in DECEPTIVE_TERMS))
    
    # HTTP signals
    has_https = 1.0 if parsed["scheme"] == "https" else 0.0
    redirect_count = float(http_metadata.get("redirectChainLength", 0))

    return {
        "url_length": length,
        "hostname_length": hostname_length,
        "hostname_entropy": hostname_entropy,
        "path_entropy": path_entropy,
        "has_userinfo": has_userinfo,
        "userinfo_length": userinfo_length,
        "userinfo_entropy": userinfo_entropy,
        "userinfo_brand_keyword_count": userinfo_brand_keyword_count,
        "userinfo_domain_like": userinfo_domain_like,
        "subdomain_length": subdomain_length,
        "subdomain_depth": subdomain_depth,
        "hyphen_count": hyphen_count,
        "subdomain_hyphen_count": subdomain_hyphen_count,
        "is_tunnel_service": is_tunnel_service,
        "brand_keyword_signal": brand_keyword_signal,
        "has_ip_hostname": has_ip,
        "is_punycode": is_punycode,
        "digit_ratio": digit_ratio,
        "special_char_ratio": special_char_ratio,
        "encoded_ratio": encoded_ratio,
        "query_param_count": query_param_count,
        "keyword_hits": keyword_hits,
        "has_https": has_https,
        "redirect_count": redirect_count,
    }

