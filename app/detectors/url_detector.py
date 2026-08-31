import ipaddress
import math
import socket
import urllib.parse
from typing import Dict, Any, List
import httpx

def calculate_str_entropy(text: str) -> float:
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    char_counts = {}
    for c in text:
        char_counts[c] = char_counts.get(c, 0) + 1
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private or
            ip.is_loopback or
            ip.is_link_local or
            ip.is_multicast or
            ip.is_reserved or
            str(ip) == "169.254.169.254"
        )
    except ValueError:
        return False

async def analyze_url_target(raw_url: str) -> Dict[str, Any]:
    """
    Performs SSRF-safe analysis on the given URL target.
    Extracts structural features, DNS records, headers, and look-alike / homograph anomalies.
    """
    indicators: List[Dict[str, Any]] = []

    # Scheme validation
    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        raw_url = "http://" + raw_url

    try:
        parsed = urllib.parse.urlparse(raw_url)
    except Exception:
        return {
            "error": "Invalid URL formatting",
            "indicators": [{
                "id": "URL-000",
                "category": "URL",
                "name": "Malformed URL",
                "description": "URL cannot be parsed safely.",
                "severity": "HIGH",
                "confidence": 0.99,
                "score": 35,
                "evidence": raw_url,
                "source": "URL Parser"
            }]
        }

    hostname = parsed.hostname or ""
    port = parsed.port
    path = parsed.path
    query = parsed.query

    # SSRF & Private Network Check
    resolved_ips = []
    is_internal = False

    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for item in addr_info:
            ip = item[4][0]
            resolved_ips.append(ip)
            if is_private_ip(ip):
                is_internal = True
    except Exception:
        # Host might not resolve
        pass

    if hostname.lower() in {"localhost", "127.0.0.1", "0.0.0.0"} or is_internal:
        indicators.append({
            "id": "URL-SSRF-01",
            "category": "NETWORK",
            "name": "Internal Network / SSRF Target",
            "description": f"URL resolves to local/private network space ({hostname}). Request blocked by defensive filter.",
            "severity": "CRITICAL",
            "confidence": 1.0,
            "score": 50,
            "evidence": f"Host: {hostname} -> Resolved IPs: {resolved_ips}",
            "source": "SSRF Guard"
        })
        return {
            "url": raw_url,
            "hostname": hostname,
            "resolvedIPs": resolved_ips,
            "indicators": indicators,
            "blocked": True
        }

    # Structural Heuristic 1: Raw IP used as hostname
    is_raw_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_raw_ip = True
    except ValueError:
        pass

    if is_raw_ip:
        indicators.append({
            "id": "URL-001",
            "category": "URL",
            "name": "Raw IP Address as Hostname",
            "description": "Target specifies a numerical IP address instead of a domain name to evade reputation-based domain filtering.",
            "severity": "MEDIUM",
            "confidence": 0.90,
            "score": 25,
            "evidence": f"Raw IP Host: {hostname}",
            "source": "URL Structure Inspector"
        })

    # Structural Heuristic 2: Excessive length or subdomains
    subdomains = hostname.split(".")
    if len(subdomains) >= 4 and not is_raw_ip:
        indicators.append({
            "id": "URL-002",
            "category": "DOMAIN",
            "name": "Excessive Subdomain Depth",
            "description": f"Domain contains {len(subdomains)} levels of subdomains, a common pattern in fast-flux DNS or DNS tunneling.",
            "severity": "MEDIUM",
            "confidence": 0.80,
            "score": 18,
            "evidence": f"Hostname: {hostname} ({len(subdomains)} components)",
            "source": "Domain Analyzer"
        })

    # Structural Heuristic 3: Suspicious Keywords / Brand Squatting
    brand_keywords = ["login", "verify", "secure", "account", "paypal", "apple", "microsoft", "google", "bank", "update", "signin"]
    found_keywords = [kw for kw in brand_keywords if kw in raw_url.lower()]
    if len(found_keywords) >= 2:
        indicators.append({
            "id": "URL-003",
            "category": "DOMAIN",
            "name": "Phishing Keyword Stacking",
            "description": f"URL stacks multiple credential-harvesting keywords ({', '.join(found_keywords)}).",
            "severity": "HIGH",
            "confidence": 0.85,
            "score": 30,
            "evidence": f"Matched keywords: {found_keywords}",
            "source": "Homograph & Phishing Classifier"
        })

    # Structural Heuristic 4: Punycode / IDN Homograph
    if "xn--" in hostname.lower():
        indicators.append({
            "id": "URL-004",
            "category": "DOMAIN",
            "name": "Internationalized / Punycode Domain",
            "description": "Domain uses Punycode encoding, often used in visual homograph attacks to spoof brand names.",
            "severity": "HIGH",
            "confidence": 0.90,
            "score": 30,
            "evidence": f"Punycode Host: {hostname}",
            "source": "Homograph Analyzer"
        })

    # Structural Heuristic 5: Non-standard Ports
    if port and port not in {80, 443, 8080, 8443}:
        indicators.append({
            "id": "URL-005",
            "category": "NETWORK",
            "name": "Non-Standard HTTP Port",
            "description": f"Target operates on atypical port {port}.",
            "severity": "LOW",
            "confidence": 0.70,
            "score": 10,
            "evidence": f"Port: {port}",
            "source": "Network Inspector"
        })

    # Safe Live HTTP Probe
    http_meta = {}
    try:
        async with httpx.AsyncClient(timeout=4.0, follow_redirects=True) as client:
            resp = await client.get(raw_url, headers={"User-Agent": "CyberShield-Security-Auditor/1.0"})
            http_meta = {
                "statusCode": resp.status_code,
                "server": resp.headers.get("server", "Hidden"),
                "contentType": resp.headers.get("content-type", "Unknown"),
                "finalUrl": str(resp.url),
                "redirectChainLength": len(resp.history),
                "hasHttps": str(resp.url).startswith("https://")
            }

            if len(resp.history) >= 3:
                indicators.append({
                    "id": "URL-006",
                    "category": "NETWORK",
                    "name": "Extended Redirect Chain",
                    "description": f"Request was redirected {len(resp.history)} times before reaching final destination.",
                    "severity": "MEDIUM",
                    "confidence": 0.85,
                    "score": 20,
                    "evidence": f"Redirects: {len(resp.history)} hops",
                    "source": "HTTP Inspector"
                })
    except Exception as e:
        http_meta = {
            "probeStatus": "Unreachable / Timed out",
            "error": str(e)
        }

    return {
        "url": raw_url,
        "hostname": hostname,
        "resolvedIPs": resolved_ips,
        "entropy": calculate_str_entropy(raw_url),
        "indicators": indicators,
        "httpMetadata": http_meta
    }
