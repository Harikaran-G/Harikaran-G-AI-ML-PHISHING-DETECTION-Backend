import ipaddress
import math
import re
import socket
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple
import httpx

# Comprehensive list of recognized brands and their official base domains
KNOWN_BRAND_DOMAINS = {
    "twitch": "twitch.tv",
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "steam": "steampowered.com",
    "discord": "discord.com",
    "roblox": "roblox.com",
    "binance": "binance.com",
    "coinbase": "coinbase.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "citibank": "citi.com",
    "outlook": "live.com",
    "yahoo": "yahoo.com",
    "whatsapp": "whatsapp.com",
    "telegram": "telegram.org",
    "spotify": "spotify.com",
    "twitter": "twitter.com",
    "x": "x.com",
    "ebay": "ebay.com",
    "walmart": "walmart.com",
    "adobe": "adobe.com",
    "dropbox": "dropbox.com",
}

# Deceptive and credential harvesting terms
DECEPTIVE_TERMS = [
    "login", "signin", "auth", "verify", "verification", "security", "account",
    "support", "free", "gift", "reward", "promo", "bonus", "claim", "billing",
    "wallet", "portal", "secure", "access", "confirm", "session", "token",
    "user", "admin", "helpdesk", "service", "payment", "unlock", "validate",
    "update", "recover", "protection", "suspended", "alert"
]

# Recognized ephemeral / reverse tunnel and dynamic DNS providers
TUNNEL_INFRASTRUCTURE_PROVIDERS = {
    "trycloudflare.com": "Cloudflare Quick Tunnel",
    "ngrok.io": "Ngrok Tunnel",
    "ngrok-free.app": "Ngrok Tunnel",
    "localtunnel.me": "Localtunnel",
    "pagekite.me": "Pagekite",
    "duckdns.org": "DuckDNS Dynamic DNS",
    "serveo.net": "Serveo Port Forwarding",
    "telebit.io": "Telebit Relay",
    "portmap.io": "Portmap OpenVPN Tunnel",
    "workers.dev": "Cloudflare Workers",
    "pages.dev": "Cloudflare Pages",
    "vercel.app": "Vercel Edge Platform",
    "netlify.app": "Netlify Platform",
    "glitch.me": "Glitch Container Hosting",
    "firebaseapp.com": "Firebase Hosting",
    "web.app": "Firebase App Hosting",
}

MULTI_PART_CCTLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "com.br", "net.br", "org.br",
    "co.jp", "ne.jp", "ac.jp", "go.jp",
    "com.sg", "edu.sg", "gov.sg",
    "co.in", "net.in", "org.in", "gen.in", "firm.in"
}

def calculate_str_entropy(text: str) -> float:
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    char_counts: Dict[str, int] = {}
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

def brand_in_text(brand: str, text: str) -> bool:
    if not brand or not text:
        return False
    if len(brand) <= 2:
        return bool(re.search(r"(?:^|[^a-z0-9])" + re.escape(brand) + r"(?:[^a-z0-9]|$)", text))
    return brand in text

def extract_domain_hierarchy(hostname: str) -> Tuple[str, str, int]:
    """
    Extracts (registrable_domain, subdomains, subdomain_depth) with multi-part TLD
    and dynamic tunnel service domain support.
    """
    if not hostname:
        return "", "", 0

    # Check if raw IP
    try:
        ipaddress.ip_address(hostname)
        return hostname, "", 0
    except ValueError:
        pass

    parts = hostname.split(".")
    if len(parts) <= 1:
        return hostname, "", 0

    # 1. Check if hosted under a known tunnel/service provider (e.g. trycloudflare.com, ngrok-free.app, duckdns.org)
    for service_domain in sorted(TUNNEL_INFRASTRUCTURE_PROVIDERS.keys(), key=len, reverse=True):
        if hostname == service_domain:
            return service_domain, "", 0
        if hostname.endswith("." + service_domain):
            service_parts = service_domain.split(".")
            num_svc = len(service_parts)
            subdomain_parts = parts[:-num_svc]
            subdomains = ".".join(subdomain_parts)
            return service_domain, subdomains, len(subdomain_parts)

    # 2. Check multi-part ccTLDs (e.g. .co.uk, .com.au)
    matched_cctld = None
    for multi_tld in sorted(MULTI_PART_CCTLDS, key=len, reverse=True):
        if hostname == multi_tld:
            return multi_tld, "", 0
        if hostname.endswith("." + multi_tld):
            matched_cctld = multi_tld
            break

    if matched_cctld:
        tld_parts = matched_cctld.split(".")
        num_tld = len(tld_parts)
        if len(parts) >= num_tld + 1:
            base_label = parts[-(num_tld + 1)]
            registrable_domain = f"{base_label}.{matched_cctld}"
            subdomain_parts = parts[:-(num_tld + 1)]
            subdomains = ".".join(subdomain_parts)
            return registrable_domain, subdomains, len(subdomain_parts)
        return hostname, "", 0

    # 3. Standard single-part TLD (e.g. example.com, test.co)
    if len(parts) >= 2:
        registrable_domain = f"{parts[-2]}.{parts[-1]}"
        subdomain_parts = parts[:-2]
        subdomains = ".".join(subdomain_parts)
        return registrable_domain, subdomains, len(subdomain_parts)

    return hostname, "", 0

def parse_url_components(raw_url: str) -> Dict[str, Any]:
    """
    Standards-compliant RFC 3986 URL decomposition separating userinfo from hostname.
    """
    cleaned_url = raw_url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", cleaned_url):
        cleaned_url = "http://" + cleaned_url

    parsed = urllib.parse.urlsplit(cleaned_url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc

    userinfo = ""
    username = ""
    password = ""
    host_port = netloc

    if "@" in netloc:
        userinfo_part, host_port = netloc.split("@", 1)
        userinfo = userinfo_part
        if ":" in userinfo_part:
            u_parts = userinfo_part.split(":", 1)
            username, password = u_parts[0], u_parts[1]
        else:
            username = userinfo_part

    # Extract hostname and port
    hostname = ""
    port: Optional[int] = None
    if host_port.startswith("[") and "]" in host_port:
        # IPv6
        idx = host_port.find("]")
        hostname = host_port[1:idx].lower()
        rest = host_port[idx+1:]
        if rest.startswith(":"):
            try:
                port = int(rest[1:])
            except ValueError:
                pass
    elif ":" in host_port:
        parts = host_port.split(":", 1)
        hostname = parts[0].lower()
        try:
            port = int(parts[1])
        except ValueError:
            pass
    else:
        hostname = host_port.lower()

    path = parsed.path or "/"
    query = parsed.query
    fragment = parsed.fragment

    # Extract registrable domain and subdomains
    registrable_domain, subdomains, subdomain_depth = extract_domain_hierarchy(hostname)

    # Check for recognized infrastructure providers
    infra_provider = None
    for known_suffix, provider_name in TUNNEL_INFRASTRUCTURE_PROVIDERS.items():
        if hostname == known_suffix or hostname.endswith("." + known_suffix):
            infra_provider = provider_name
            break

    return {
        "rawUrl": raw_url,
        "normalizedUrl": cleaned_url,
        "scheme": scheme,
        "hasUserinfo": bool(userinfo),
        "userinfo": userinfo,
        "username": username,
        "password": password,
        "hostname": hostname,
        "registrableDomain": registrable_domain,
        "subdomains": subdomains,
        "subdomainDepth": subdomain_depth,
        "port": port,
        "path": path,
        "query": query,
        "fragment": fragment,
        "infrastructureProvider": infra_provider,
    }

async def analyze_url_target(raw_url: str) -> Dict[str, Any]:
    """
    Performs comprehensive SSRF-safe analysis, userinfo deception detection,
    brand keyword spoofing analysis, subdomain anomaly inspection, and indicator aggregation.
    """
    indicators: List[Dict[str, Any]] = []

    parsed = parse_url_components(raw_url)
    hostname = parsed["hostname"]
    userinfo = parsed["userinfo"]
    subdomains = parsed["subdomains"]
    registrable_domain = parsed["registrableDomain"]
    infra_provider = parsed["infrastructureProvider"]
    port = parsed["port"]
    path = parsed["path"]

    if not hostname:
        indicators.append({
            "id": "URL-000",
            "category": "URL",
            "name": "Malformed URL",
            "description": "URL cannot be parsed safely or contains an empty hostname.",
            "severity": "HIGH",
            "confidence": 0.99,
            "score": 35,
            "evidence": raw_url,
            "source": "URL Parser"
        })
        return {
            "url": raw_url,
            "hostname": "",
            "riskScore": 35,
            "resolvedIPs": [],
            "indicators": indicators,
            "entropy": calculate_str_entropy(raw_url),
            "parsed": parsed,
        }

    # 1. SSRF & Private Network Check
    resolved_ips: List[str] = []
    is_internal = False

    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for item in addr_info:
            ip = item[4][0]
            if ip not in resolved_ips:
                resolved_ips.append(ip)
            if is_private_ip(ip):
                is_internal = True
    except Exception:
        # Host might not resolve
        pass

    if hostname in {"localhost", "127.0.0.1", "0.0.0.0"} or is_internal:
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
            "riskScore": 50,
            "resolvedIPs": resolved_ips,
            "indicators": indicators,
            "blocked": True,
            "entropy": calculate_str_entropy(raw_url),
            "parsed": parsed,
        }

    # 2. USERINFO PHISHING DETECTION (USERINFO_DECEPTION)
    if parsed["hasUserinfo"]:
        # Basic userinfo deception indicator
        indicators.append({
            "id": "URL-USERINFO-01",
            "category": "DECEPTION",
            "name": "Misleading URL Userinfo (Deception Vector)",
            "description": "The URL contains user-controlled text before the @ symbol that can deceive users into believing the destination belongs to a different organization or service.",
            "severity": "HIGH",
            "confidence": 0.95,
            "score": 40,
            "evidence": f"Userinfo: '{userinfo}' (Actual destination host: '{hostname}')",
            "source": "Userinfo Deception Detector"
        })

        # Check for brand names and deceptive keywords inside userinfo
        u_lower = userinfo.lower()
        brands_in_userinfo = [b for b in KNOWN_BRAND_DOMAINS if brand_in_text(b, u_lower)]
        terms_in_userinfo = [t for t in DECEPTIVE_TERMS if brand_in_text(t, u_lower)]
        domain_like_patterns = bool(re.search(r"(-tv|-com|-net|-org|\.com|\.tv|\.org|\.net|www-|http-|https-)", u_lower))

        if brands_in_userinfo or terms_in_userinfo or domain_like_patterns:
            findings_desc = []
            if brands_in_userinfo:
                findings_desc.append(f"brand terms: {', '.join(brands_in_userinfo)}")
            if terms_in_userinfo:
                findings_desc.append(f"deceptive keywords: {', '.join(terms_in_userinfo)}")
            if domain_like_patterns:
                findings_desc.append("domain-like mimicking syntax")

            indicators.append({
                "id": "URL-USERINFO-BRAND",
                "category": "DECEPTION",
                "name": "Brand-like Deception in URL Userinfo",
                "description": f"Userinfo incorporates {'; '.join(findings_desc)} to simulate an official login or promotional destination.",
                "severity": "HIGH",
                "confidence": 0.95,
                "score": 35,
                "evidence": f"Matched in userinfo '{userinfo}': {findings_desc}",
                "source": "Brand & Keyword Deception Engine"
            })

    # 3. BRAND & CROSS-DOMAIN SPOOFING DETECTION
    # Scan subdomains, path, and hostname for brand spoofing outside official domain
    hostname_lower = hostname.lower()
    subdomain_lower = subdomains.lower()
    path_lower = path.lower()

    for brand, official_domain in KNOWN_BRAND_DOMAINS.items():
        brand_in_sub = brand_in_text(brand, subdomain_lower)
        brand_in_path = brand_in_text(brand, path_lower)
        is_official = (
            registrable_domain == official_domain or
            hostname == official_domain or
            hostname.endswith("." + official_domain) or
            official_domain.split(".")[0] in registrable_domain
        )

        if (brand_in_sub or brand_in_path) and not is_official:
            severity = "HIGH" if brand_in_sub else "MEDIUM"
            indicators.append({
                "id": f"URL-BRAND-SPOOF-{brand.upper()}",
                "category": "DECEPTION",
                "name": f"Brand Impersonation ({brand.capitalize()})",
                "description": f"Target references brand '{brand}' in its {'subdomain' if brand_in_sub else 'path'}, but resolves to unrelated domain '{registrable_domain}'.",
                "severity": severity,
                "confidence": 0.90,
                "score": 30 if severity == "HIGH" else 20,
                "evidence": f"Brand: {brand} | Host: {hostname} (Official domain: {official_domain})",
                "source": "Brand Impersonation Detector"
            })

    # 4. SUSPICIOUS SUBDOMAIN & ENTROPY DETECTION
    subdomain_length = len(subdomains)
    subdomain_hyphens = subdomains.count("-")
    subdomain_entropy = calculate_str_entropy(subdomains)

    if (subdomain_length >= 20 or subdomain_hyphens >= 3 or (subdomain_entropy >= 3.8 and subdomain_length >= 12)) and not is_private_ip(hostname):
        indicators.append({
            "id": "URL-SUBDOMAIN-ANOMALY",
            "category": "DOMAIN",
            "name": "Suspicious Subdomain Structure",
            "description": f"Subdomain exhibits automated/ephemeral generation patterns ({subdomain_hyphens} hyphens, {subdomain_length} chars, entropy: {subdomain_entropy}) frequently associated with disposable phishing campaigns.",
            "severity": "MEDIUM",
            "confidence": 0.85,
            "score": 22,
            "evidence": f"Subdomain: '{subdomains}' (Length: {subdomain_length}, Hyphens: {subdomain_hyphens}, Entropy: {subdomain_entropy})",
            "source": "Subdomain Structure Analyzer"
        })
    elif parsed["subdomainDepth"] >= 3:
        indicators.append({
            "id": "URL-002",
            "category": "DOMAIN",
            "name": "Excessive Subdomain Depth",
            "description": f"Domain contains {parsed['subdomainDepth']} levels of subdomains, a common pattern in fast-flux DNS or DNS tunneling.",
            "severity": "MEDIUM",
            "confidence": 0.80,
            "score": 18,
            "evidence": f"Hostname: {hostname} ({parsed['subdomainDepth']} subdomain levels)",
            "source": "Domain Analyzer"
        })

    # 5. INFRASTRUCTURE & REVERSE TUNNEL RECOGNITION
    if infra_provider:
        indicators.append({
            "id": "URL-INFRA-TUNNEL",
            "category": "INFRASTRUCTURE",
            "name": "Ephemeral / Reverse Tunnel Infrastructure Detected",
            "description": f"Target is hosted on {infra_provider} ({registrable_domain}), an ephemeral reverse tunnel or public forwarding service frequently abused for temporary phishing drops.",
            "severity": "LOW",
            "confidence": 0.80,
            "score": 15,
            "evidence": f"Infrastructure Provider: {infra_provider} (Domain: {registrable_domain})",
            "source": "Threat Infrastructure Profiler"
        })

    # 6. Raw IP as Hostname
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

    # 7. Punycode / IDN Homograph
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

    # 8. Non-standard Ports
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

    # 9. Live HTTP Probe (Safe & Non-blocking)
    http_meta: Dict[str, Any] = {}
    try:
        async with httpx.AsyncClient(timeout=3.5, follow_redirects=True) as client:
            resp = await client.get(parsed["normalizedUrl"], headers={"User-Agent": "CyberShield-Security-Auditor/1.0"})
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

    # Aggregate Rule-Based Risk Score
    rule_risk_score = min(100, sum(ind.get("score", 0) for ind in indicators))

    return {
        "url": raw_url,
        "normalizedUrl": parsed["normalizedUrl"],
        "hostname": hostname,
        "registrableDomain": registrable_domain,
        "subdomains": subdomains,
        "infrastructureProvider": infra_provider,
        "resolvedIPs": resolved_ips,
        "entropy": calculate_str_entropy(raw_url),
        "hostnameEntropy": calculate_str_entropy(hostname),
        "indicators": indicators,
        "riskScore": rule_risk_score,
        "httpMetadata": http_meta,
        "parsed": parsed,
    }
