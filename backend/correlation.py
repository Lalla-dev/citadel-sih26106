"""
Citadel Security Platform - Threat Correlation & Forensic Graph Engine
Builds node-edge entity correlation graphs linking analyzed emails, senders,
domains, URLs, IPs, ASNs, and Threat Actor campaigns.
Supports SOC pivot analysis and cross-incident correlation.
"""
from typing import Dict, Any, List, Optional
import uuid

# Color palette for graph nodes (matching Citadel CSS design system)
NODE_COLORS = {
    "EMAIL": "#38bdf8",          # Sky blue
    "SENDER": "#a855f7",         # Purple
    "DOMAIN": "#3b82f6",         # Royal blue
    "URL": "#f59e0b",            # Amber
    "IP": "#ef4444",             # Red
    "ASN": "#10b981",            # Emerald
    "THREAT_ACTOR": "#dc2626",   # Crimson
    "CAMPAIGN": "#ec4899"        # Pink
}


def build_threat_graph(analysis_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Builds a forensic graph representing all entity nodes and correlation edges
    from an AnalysisResult dictionary.
    """
    nodes = []
    edges = []
    node_ids = set()

    def add_node(nid: str, label: str, ntype: str, risk: str = "LOW", details: Optional[Dict[str, Any]] = None):
        if nid not in node_ids:
            node_ids.add(nid)
            nodes.append({
                "id": nid,
                "label": label,
                "type": ntype,
                "color": NODE_COLORS.get(ntype, "#64748b"),
                "risk": risk,
                "details": details or {}
            })

    def add_edge(src: str, tgt: str, relationship: str, severity: str = "NORMAL"):
        edges.append({
            "source": src,
            "target": tgt,
            "relationship": relationship,
            "severity": severity
        })

    # 1. Root Email Node
    case_id = analysis_data.get("case_id", "CASE-ROOT")
    meta = analysis_data.get("metadata", {})
    risk_level = analysis_data.get("risk_level", "LOW")
    threat_score = analysis_data.get("threat_score", 0)

    add_node(
        case_id,
        label=f"{case_id}\n({threat_score}/100)",
        ntype="EMAIL",
        risk=risk_level,
        details={
            "subject": meta.get("subject", ""),
            "threat_score": threat_score,
            "risk_level": risk_level,
            "archetype": analysis_data.get("threat_archetype", "")
        }
    )

    # 2. Sender Node
    sender_email = meta.get("sender_email", "")
    if sender_email:
        sender_id = f"sender:{sender_email}"
        add_node(
            sender_id,
            label=f"Sender:\n{sender_email}",
            ntype="SENDER",
            risk="HIGH" if analysis_data.get("authentication", {}).get("display_name_spoofed") else "LOW",
            details={
                "display_name": meta.get("sender_display_name", ""),
                "reply_to": meta.get("reply_to", "")
            }
        )
        add_edge(case_id, sender_id, "ORIGINATED_FROM")

        # Sender Domain Node
        if "@" in sender_email:
            s_domain = sender_email.split("@")[-1].lower().strip()
            s_dom_id = f"domain:{s_domain}"
            add_node(
                s_dom_id,
                label=f"Domain:\n{s_domain}",
                ntype="DOMAIN",
                risk="LOW",
                details={"domain": s_domain, "role": "sender_domain"}
            )
            add_edge(sender_id, s_dom_id, "HOSTED_ON")

    # 3. URL Nodes
    urls = analysis_data.get("urls", [])
    for idx, u in enumerate(urls):
        url_str = u.get("url", "")
        domain_str = u.get("domain", "")
        u_risk = u.get("risk_category", "SAFE")
        url_id = f"url:{idx}_{domain_str}"

        add_node(
            url_id,
            label=f"URL:\n{domain_str[:18]}...",
            ntype="URL",
            risk=u_risk,
            details={
                "full_url": url_str,
                "entropy": u.get("shannon_entropy", 0.0),
                "risk_score": u.get("risk_score", 0.0),
                "triggers": u.get("triggers", [])
            }
        )
        add_edge(case_id, url_id, "CONTAINS_HYPERLINK", severity="ALERT" if u_risk != "SAFE" else "NORMAL")

        # Domain Node for URL
        if domain_str:
            dom_id = f"domain:{domain_str}"
            add_node(
                dom_id,
                label=f"Domain:\n{domain_str}",
                ntype="DOMAIN",
                risk=u_risk,
                details={"domain": domain_str}
            )
            add_edge(url_id, dom_id, "RESOLVES_DOMAIN")

    # 4. Enrichment IPs and ASNs
    enrichment = analysis_data.get("enrichment", {})
    ips = enrichment.get("ips", {})
    for ip_str, geo in ips.items():
        ip_id = f"ip:{ip_str}"
        ip_risk = "CRITICAL" if geo.get("risk_category") in ("CRITICAL_RISK", "HIGH_RISK", "ANONYMIZER_TOR") else "LOW"
        add_node(
            ip_id,
            label=f"IP: {ip_str}\n({geo.get('country_code', 'XX')})",
            ntype="IP",
            risk=ip_risk,
            details={
                "country": geo.get("country", ""),
                "city": geo.get("city", ""),
                "org": geo.get("org", ""),
                "asn": geo.get("asn", "")
            }
        )

        # Connect IP to matching domain
        for d_name, d_info in enrichment.get("domains", {}).items():
            dns_ips = d_info.get("dns_resolution", {}).get("ip_addresses", [])
            if ip_str in dns_ips or d_name == ip_str:
                dom_id = f"domain:{d_name}"
                if dom_id in node_ids:
                    add_edge(dom_id, ip_id, "DNS_A_RECORD", severity="ALERT" if ip_risk == "CRITICAL" else "NORMAL")

        # ASN Node
        asn_str = geo.get("asn", "")
        if asn_str and asn_str != "AS0":
            asn_id = f"asn:{asn_str}"
            add_node(
                asn_id,
                label=f"{asn_str}\n{geo.get('org', '')[:16]}",
                ntype="ASN",
                risk="HIGH" if "Bulletproof" in geo.get("org", "") else "LOW",
                details={"asn": asn_str, "org": geo.get("org", "")}
            )
            add_edge(ip_id, asn_id, "ROUTED_BY")

    # 5. Threat Intelligence Campaign & Actor Nodes
    threat_intel = enrichment.get("threat_intel", {})
    if threat_intel.get("matched"):
        for m in threat_intel.get("matches", []):
            actor_name = m.get("threat_group", "Unknown Actor")
            actor_id = f"actor:{actor_name}"
            add_node(
                actor_id,
                label=f"🚨 Threat Actor:\n{actor_name}",
                ntype="THREAT_ACTOR",
                risk="CRITICAL",
                details={
                    "threat_type": m.get("threat_type", ""),
                    "confidence": m.get("confidence", 0.0),
                    "tags": m.get("tags", [])
                }
            )

            # Link threat actor to the matched indicator node
            ioc_ind = m.get("indicator", "")
            ioc_type = m.get("ioc_type", "")
            if ioc_type == "domain":
                target_id = f"domain:{ioc_ind}"
            elif ioc_type == "ip":
                target_id = f"ip:{ioc_ind}"
            elif ioc_type == "sender":
                target_id = f"sender:{ioc_ind}"
            else:
                target_id = case_id

            if target_id in node_ids:
                add_edge(target_id, actor_id, "ATTRIBUTED_TO", severity="CRITICAL")
            else:
                add_edge(case_id, actor_id, "ATTRIBUTED_TO", severity="CRITICAL")

    # Graph Metadata Summary
    summary = {
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "node_breakdown": {
            ntype: sum(1 for n in nodes if n["type"] == ntype)
            for ntype in NODE_COLORS.keys()
        },
        "critical_pivots": [
            n["id"] for n in nodes if n["risk"] in ("CRITICAL", "HIGH") and n["type"] != "EMAIL"
        ]
    }

    return {
        "nodes": nodes,
        "edges": edges,
        "summary": summary
    }
