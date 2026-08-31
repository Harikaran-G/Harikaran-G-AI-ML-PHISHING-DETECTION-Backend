from typing import Dict, Any, List

def build_ioc_relationship_graph(
    target: str,
    scan_type: str,
    sha256: str = None,
    discovered_ips: List[str] = None,
    discovered_urls: List[str] = None,
    hostname: str = None,
    resolved_ips: List[str] = None,
    package_name: str = None,
) -> Dict[str, Any]:
    """
    Constructs an IOC relationship graph linking targets, hashes, domains, resolved IPs, and discovered endpoints.
    """
    nodes = []
    links = []
    node_set = set()

    def add_node(node_id: str, label: str, node_type: str, severity: str = "INFO"):
        if node_id not in node_set:
            node_set.add(node_id)
            nodes.append({
                "id": node_id,
                "label": label,
                "type": node_type,
                "severity": severity,
            })

    # Root Target Node
    root_id = f"target:{target}"
    add_node(root_id, target, f"{scan_type}_TARGET", "HIGH")

    # Hash Node
    if sha256:
        hash_id = f"sha256:{sha256[:12]}"
        add_node(hash_id, f"SHA256: {sha256[:8]}...", "HASH", "INFO")
        links.append({"source": root_id, "target": hash_id, "relation": "HAS_CHECKSUM"})

    # Hostname & Domain Node
    if hostname:
        host_id = f"domain:{hostname}"
        add_node(host_id, hostname, "DOMAIN", "MEDIUM")
        links.append({"source": root_id, "target": host_id, "relation": "HOSTED_ON"})

    # Resolved IPs
    if resolved_ips:
        for ip in resolved_ips[:4]:
            ip_id = f"ip:{ip}"
            add_node(ip_id, ip, "IP_ADDRESS", "MEDIUM")
            if hostname:
                links.append({"source": f"domain:{hostname}", "target": ip_id, "relation": "RESOLVES_TO"})
            else:
                links.append({"source": root_id, "target": ip_id, "relation": "CONNECTS_TO"})

    # Discovered IPs in file/APK
    if discovered_ips:
        for ip in discovered_ips[:4]:
            ip_id = f"ip:{ip}"
            add_node(ip_id, ip, "C2_IP_ENDPOINT", "HIGH")
            links.append({"source": root_id, "target": ip_id, "relation": "EMBEDDED_IP"})

    # Discovered URLs in file/APK
    if discovered_urls:
        for u in discovered_urls[:3]:
            u_id = f"url:{u[:30]}"
            add_node(u_id, u[:28] + ("..." if len(u) > 28 else ""), "EXTERNAL_ENDPOINT", "HIGH")
            links.append({"source": root_id, "target": u_id, "relation": "EXTRACTED_URL"})

    # Package Name in APK
    if package_name:
        pkg_id = f"pkg:{package_name}"
        add_node(pkg_id, package_name, "ANDROID_PACKAGE", "INFO")
        links.append({"source": root_id, "target": pkg_id, "relation": "DEFINES_PACKAGE"})

    return {
        "nodes": nodes,
        "links": links,
        "totalEntities": len(nodes),
        "totalRelationships": len(links),
    }
