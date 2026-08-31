import math
from typing import Dict, Any

def extract_file_features(
    file_size: int,
    entropy: float,
    indicators_count: int,
    discovered_ips_count: int,
    discovered_urls_count: int,
    has_double_ext: bool,
    pe_details: Dict[str, Any] = None,
) -> Dict[str, float]:
    """
    Extracts numerical feature vector for static File ML analysis.
    """
    pe_details = pe_details or {}
    section_count = float(len(pe_details.get("sections", [])))
    suspicious_sections = float(len(pe_details.get("suspiciousSections", [])))
    imports_count = float(len(pe_details.get("importedSymbols", [])))
    
    return {
        "file_size_kb": round(float(file_size) / 1024.0, 2),
        "entropy": float(entropy),
        "has_high_entropy": 1.0 if entropy > 7.0 else 0.0,
        "has_double_extension": 1.0 if has_double_ext else 0.0,
        "discovered_ips_count": float(discovered_ips_count),
        "discovered_urls_count": float(discovered_urls_count),
        "indicators_count": float(indicators_count),
        "pe_section_count": section_count,
        "pe_suspicious_sections": suspicious_sections,
        "pe_imports_count": imports_count,
        "is_pe_executable": 1.0 if pe_details.get("isPE") else 0.0,
    }
