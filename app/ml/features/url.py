import math
import re
from urllib.parse import urlparse
from typing import Dict, Any, List

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def extract_url_features(url: str, http_metadata: Dict[str, Any] = None) -> Dict[str, float]:
    """
    Extracts numerical feature vector for ML and Anomaly detection.
    """
    http_metadata = http_metadata or {}
    parsed = urlparse(url if "://" in url else f"http://{url}")
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    length = float(len(url))
    hostname_length = float(len(hostname))
    hostname_entropy = calculate_entropy(hostname)
    path_entropy = calculate_entropy(path)
    
    # Structural features
    subdomain_count = float(max(0, len(hostname.split(".")) - 2))
    has_ip = 1.0 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname) else 0.0
    is_punycode = 1.0 if "xn--" in hostname.lower() else 0.0
    
    digit_count = sum(c.isdigit() for c in url)
    digit_ratio = round(digit_count / length if length > 0 else 0.0, 4)
    
    special_chars = sum(not c.isalnum() for c in url)
    special_char_ratio = round(special_chars / length if length > 0 else 0.0, 4)
    
    encoded_count = url.count("%")
    encoded_ratio = round(encoded_count / length if length > 0 else 0.0, 4)
    
    query_param_count = float(len(query.split("&"))) if query else 0.0
    
    # Suspicious keywords presence
    suspicious_terms = ["login", "verify", "update", "secure", "bank", "account", "wallet", "free", "claim", "signin"]
    keyword_hits = float(sum(term in url.lower() for term in suspicious_terms))
    
    # HTTP signals
    has_https = 1.0 if parsed.scheme == "https" else 0.0
    redirect_count = float(http_metadata.get("redirectChainLength", 0))

    return {
        "url_length": length,
        "hostname_length": hostname_length,
        "hostname_entropy": hostname_entropy,
        "path_entropy": path_entropy,
        "subdomain_count": subdomain_count,
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
