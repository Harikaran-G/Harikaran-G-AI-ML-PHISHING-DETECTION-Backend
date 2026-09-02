from typing import Dict, Any, List, Optional

def build_ioc_relationship_graph(
    target: str,
    scan_type: str,
    sha256: Any = None,
    discovered_ips: Any = None,
    discovered_urls: Any = None,
    hostname: Any = None,
    resolved_ips: Any = None,
    package_name: Any = None,
    userinfo: Any = None,
    registrable_domain: Any = None,
    infrastructure_provider: Any = None,
) -> Dict[str, Any]:
    """
    Constructs an IOC relationship graph linking targets, userinfo spoofs, base domains,
    infrastructure providers, resolved IPs, and discovered endpoints.
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

    # 1. Root Target Node
    root_id = f"target:{target}"
    add_node(root_id, target, f"{scan_type}_TARGET", "HIGH")

    # 2. Deceptive Userinfo Node
    if userinfo:
        u_id = f"userinfo:{userinfo}"
        add_node(u_id, f"Userinfo: {userinfo}", "USERINFO_DECEPTION", "HIGH")
        links.append({"source": root_id, "target": u_id, "relation": "EMBEDS_USERINFO"})

    # 3. Hostname Node
    if hostname:
        host_id = f"domain:{hostname}"
        add_node(host_id, hostname, "DESTINATION_HOST", "MEDIUM")
        links.append({"source": root_id, "target": host_id, "relation": "HOSTED_ON"})

        # 4. Registrable Base Domain Node
        if registrable_domain and registrable_domain != hostname:
            base_id = f"basedomain:{registrable_domain}"
            add_node(base_id, f"Base Domain: {registrable_domain}", "REGISTRABLE_DOMAIN", "INFO")
            links.append({"source": host_id, "target": base_id, "relation": "SUBDOMAIN_OF"})

            # 5. Infrastructure Provider Node
            if infrastructure_provider:
                infra_id = f"infra:{infrastructure_provider}"
                add_node(infra_id, f"Provider: {infrastructure_provider}", "INFRASTRUCTURE_PROVIDER", "LOW")
                links.append({"source": base_id, "target": infra_id, "relation": "SERVICE_PROVIDER"})

    # 6. Checksum Node
    if sha256:
        hash_id = f"sha256:{sha256[:12]}"
        add_node(hash_id, f"SHA256: {sha256[:8]}...", "HASH", "INFO")
        links.append({"source": root_id, "target": hash_id, "relation": "HAS_CHECKSUM"})

    # 7. Resolved IPs
    if resolved_ips:
        for ip in resolved_ips[:4]:
            ip_id = f"ip:{ip}"
            add_node(ip_id, ip, "IP_ADDRESS", "MEDIUM")
            if hostname:
                links.append({"source": f"domain:{hostname}", "target": ip_id, "relation": "RESOLVES_TO"})
            else:
                links.append({"source": root_id, "target": ip_id, "relation": "CONNECTS_TO"})

    # 8. Discovered IPs in file/APK
    if discovered_ips:
        for ip in discovered_ips[:4]:
            ip_id = f"ip:{ip}"
            add_node(ip_id, ip, "C2_IP_ENDPOINT", "HIGH")
            links.append({"source": root_id, "target": ip_id, "relation": "EMBEDDED_IP"})

    # 9. Discovered URLs in file/APK
    if discovered_urls:
        for u in discovered_urls[:3]:
            u_id = f"url:{u[:30]}"
            add_node(u_id, u[:28] + ("..." if len(u) > 28 else ""), "EXTERNAL_ENDPOINT", "HIGH")
            links.append({"source": root_id, "target": u_id, "relation": "EXTRACTED_URL"})

    # 10. Package Name in APK
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

