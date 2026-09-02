import hashlib
import math
import os
import re
from typing import Dict, Any, List
import pefile

def calculate_entropy(data: bytes) -> float:
    """Calculates the Shannon entropy of a byte array."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    for count in byte_counts:
        if count == 0:
            continue
        p = float(count) / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def extract_strings(data: bytes, min_len: int = 4) -> List[str]:
    """Extracts printable ASCII and UTF-8 strings from binary data."""
    pattern = rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}"
    found = re.findall(pattern, data)
    return [s.decode("ascii", errors="ignore") for s in found[:500]]

def analyze_file_content(filename: str, content: bytes) -> Dict[str, Any]:
    """
    Performs safe static dissection on file contents.
    Extracts hashes, entropy, magic bytes, extension heuristics, embedded strings,
    and Portable Executable (PE) headers if applicable.
    """
    file_size = len(content)
    md5_hash = hashlib.md5(content).hexdigest()
    sha1_hash = hashlib.sha1(content).hexdigest()
    sha256_hash = hashlib.sha256(content).hexdigest()
    entropy = calculate_entropy(content)

    indicators: List[Dict[str, Any]] = []

    # Heuristic 1: Double extension detection
    name_parts = filename.split(".")
    executable_exts = {"exe", "dll", "vbs", "bat", "ps1", "scr", "pif", "cmd", "js", "hta", "jar", "sh"}
    document_exts = {"pdf", "docx", "doc", "xlsx", "xls", "pptx", "txt", "jpg", "png", "jpeg", "csv"}

    if len(name_parts) > 2:
        inner_ext = name_parts[-2].lower()
        outer_ext = name_parts[-1].lower()
        if inner_ext in document_exts and outer_ext in executable_exts:
            indicators.append({
                "id": "FILE-001",
                "category": "FILE",
                "name": "Deceptive Double Extension",
                "description": f"File uses disguised extension pattern (.{inner_ext}.{outer_ext}) to mask executable payload.",
                "severity": "HIGH",
                "confidence": 0.98,
                "score": 30,
                "evidence": f"Filename: '{filename}' (Inner: .{inner_ext}, Outer: .{outer_ext})",
                "source": "Extension Heuristic Engine"
            })

    # Heuristic 2: Shannon Entropy
    if entropy >= 7.2:
        indicators.append({
            "id": "FILE-002",
            "category": "SIGNATURE",
            "name": "High Shannon Entropy Payload",
            "description": f"Entropy of {entropy} indicates packed, obfuscated, or encrypted binary code.",
            "severity": "HIGH",
            "confidence": 0.90,
            "score": 25,
            "evidence": f"Calculated Entropy: {entropy}/8.0 (Threshold: 7.2)",
            "source": "Entropy Analyzer"
        })
    elif entropy >= 6.5:
        indicators.append({
            "id": "FILE-003",
            "category": "SIGNATURE",
            "name": "Elevated Entropy Section",
            "description": f"Entropy of {entropy} suggests partial code compression or encrypted strings.",
            "severity": "MEDIUM",
            "confidence": 0.75,
            "score": 15,
            "evidence": f"Calculated Entropy: {entropy}/8.0",
            "source": "Entropy Analyzer"
        })

    # Heuristic 3: Magic bytes & signature check
    magic_bytes = content[:4].hex().upper()
    is_pe = content[:2] == b"MZ"
    is_elf = content[:4] == b"\x7fELF"
    is_pdf = content[:4] == b"%PDF"
    is_zip = content[:4] == b"PK\x03\x04"

    detected_type = "Binary / Unknown"
    if is_pe:
        detected_type = "Windows Executable (PE/MZ)"
        # Check if file has document extension but is actually PE
        ext = name_parts[-1].lower() if name_parts else ""
        if ext in document_exts:
            indicators.append({
                "id": "FILE-004",
                "category": "FILE",
                "name": "Executable Disguised as Document",
                "description": f"File possesses MZ PE header but uses .{ext} document extension.",
                "severity": "CRITICAL",
                "confidence": 0.99,
                "score": 40,
                "evidence": f"Magic bytes: 'MZ' header with .{ext} extension",
                "source": "Signature Validator"
            })
    elif is_elf:
        detected_type = "Linux Executable (ELF)"
    elif is_pdf:
        detected_type = "PDF Document"
    elif is_zip:
        detected_type = "ZIP / Compressed Archive"

    # Heuristic 4: Embedded Strings, C2, and IP discovery
    strings = extract_strings(content)
    ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    url_pattern = re.compile(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w .?=%&-]*")
    powershell_pattern = re.compile(r"(powershell|invoke-expression|iex|downloadstring|cmd\.exe|wscript)", re.IGNORECASE)

    discovered_ips = set()
    discovered_urls = set()
    suspicious_commands = set()

    for s in strings:
        ips = ip_pattern.findall(s)
        for ip in ips:
            # Skip loopback and broadcast
            if not ip.startswith("127.") and ip != "0.0.0.0" and ip != "255.255.255.255":
                discovered_ips.add(ip)
        
        urls = url_pattern.findall(s)
        for u in urls:
            if not "w3.org" in u and not "schema.org" in u:
                discovered_urls.add(u)

        if powershell_pattern.search(s):
            suspicious_commands.add(s[:60])

    if discovered_ips:
        indicators.append({
            "id": "FILE-005",
            "category": "NETWORK",
            "name": "Hardcoded External IP Address",
            "description": "Binary contains direct external IP addresses, often used to bypass DNS resolution in C2 communication.",
            "severity": "MEDIUM",
            "confidence": 0.85,
            "score": 20,
            "evidence": f"Found IPs: {', '.join(list(discovered_ips)[:3])}",
            "source": "String Analyzer"
        })

    if discovered_urls:
        indicators.append({
            "id": "FILE-006",
            "category": "NETWORK",
            "name": "Embedded Remote URL String",
            "description": "File references external web endpoints that could be downloaders or beacons.",
            "severity": "MEDIUM",
            "confidence": 0.80,
            "score": 15,
            "evidence": f"Discovered URLs: {', '.join(list(discovered_urls)[:2])}",
            "source": "String Analyzer"
        })

    if suspicious_commands:
        indicators.append({
            "id": "FILE-007",
            "category": "BEHAVIOR",
            "name": "Command Shell / PowerShell Artifacts",
            "description": "Contains shell execution strings, downloader commands, or scripting engine invocations.",
            "severity": "HIGH",
            "confidence": 0.88,
            "score": 25,
            "evidence": f"Artifact: {list(suspicious_commands)[0]}",
            "source": "String Analyzer"
        })

    # Heuristic 5: PE Header parsing if PE
    pe_details = {}
    if is_pe:
        try:
            pe = pefile.PE(data=content)
            file_header = getattr(pe, "FILE_HEADER", None)
            machine = getattr(file_header, "Machine", 0) if file_header else 0
            num_sections = getattr(file_header, "NumberOfSections", 0) if file_header else 0
            timestamp = getattr(file_header, "TimeDateStamp", 0) if file_header else 0
            pe_sections = getattr(pe, "sections", [])

            pe_details = {
                "machine": hex(machine) if isinstance(machine, int) else str(machine),
                "sections": [s.Name.decode('utf-8', errors='ignore').strip('\x00') for s in pe_sections],
                "numberOfSections": num_sections,
                "timestamp": timestamp
            }
            # Check suspicious section names
            suspicious_sec_names = {".upx0", ".upx1", ".themida", ".vmp", ".aspack"}
            for sec in pe_sections:
                sec_name = sec.Name.decode('utf-8', errors='ignore').strip('\x00').lower()
                if sec_name in suspicious_sec_names:
                    indicators.append({
                        "id": "FILE-008",
                        "category": "SIGNATURE",
                        "name": "Known Packer Section Header",
                        "description": f"PE section '{sec_name}' corresponds to known packing/obfuscation software.",
                        "severity": "HIGH",
                        "confidence": 0.95,
                        "score": 30,
                        "evidence": f"Section name: {sec_name}",
                        "source": "PE Dissector"
                    })
        except Exception:
            pass

    return {
        "filename": filename,
        "fileSize": file_size,
        "detectedType": detected_type,
        "hashes": {
            "md5": md5_hash,
            "sha1": sha1_hash,
            "sha256": sha256_hash
        },
        "entropy": entropy,
        "magicBytes": magic_bytes,
        "indicators": indicators,
        "metadata": {
            "detectedType": detected_type,
            "discoveredIPs": list(discovered_ips)[:10],
            "discoveredURLs": list(discovered_urls)[:10],
            "peDetails": pe_details
        }
    }
