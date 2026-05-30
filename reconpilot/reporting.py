import json
from pathlib import Path

from reconpilot.state import add_artifact
from reconpilot.session_store import ARTIFACTS_DIR, display_output_path


REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"


def _truncate(text, limit=160):
    if text is None:
        return ""
    if isinstance(text, (dict, list)):
        text = json.dumps(text, sort_keys=True)
    cleaned = " ".join(str(text).split())
    return cleaned[:limit]


def _normalize_artifact(artifact):
    return {
        "service": artifact.get("service", "unknown"),
        "port": artifact.get("port", 0),
        "type": artifact.get("type", "unknown"),
        "source": artifact.get("source", artifact.get("path", "")),
        "retrieved": bool(artifact.get("retrieved", False)),
        "content": _truncate(artifact.get("content", artifact.get("name", "")), limit=200),
    }


def _icmp_status(prechecks):
    icmp = prechecks.get("icmp", {})
    if not icmp.get("ping_available"):
        return "unavailable"
    if icmp.get("icmp_reachable") is True:
        return "reachable"
    if icmp.get("icmp_reachable") is False:
        return "unreachable"
    return "unknown"


def _nmap_status(nmap):
    parsed = nmap.get("parsed", {})
    if parsed.get("success"):
        return "completed"
    if parsed.get("error"):
        return "failed"
    return "skipped"


def _service_label(service):
    return f"{service.get('port')}/{service.get('protocol')} {service.get('service')}"


def format_inventory_label(service_record):
    inventory = service_record.get("inventory") or {}
    product = " ".join(str(inventory.get("product") or "").split()).strip()
    version = " ".join(str(inventory.get("version") or "").split()).strip()
    extra_info = " ".join(str(inventory.get("extra_info") or "").split()).strip()
    if not product:
        return None
    label = " ".join(part for part in [product, version] if part)
    if extra_info:
        label = f"{label} {extra_info}"
    return label


def _service_summary_label(service):
    inventory_label = format_inventory_label(service)
    return f"{_service_label(service)} - {inventory_label}" if inventory_label else _service_label(service)


def _count_vulnerability_matches(report):
    total = 0
    for entry in report["inventory"]:
        total += len(entry.get("vulnerabilities", []))
        for api_result in entry.get("vulnerability_api", []):
            total += len(api_result.get("matches", []))
    for item in report.get("vulnerability_api_results", []):
        total += len(item.get("matches", []))
    return total


def _build_summary_text(report):
    return (
        f"services: {len(report['services'])}, "
        f"web targets: {len(report['web_targets'])}, "
        f"inventory: {len(report['inventory'])}, "
        f"findings: {len(report['findings'])}, "
        f"vulnerability matches: {_count_vulnerability_matches(report)}"
    )


def build_recon_report(state):
    normalized_artifacts = [_normalize_artifact(item) for item in state["artifacts"]]
    state["artifacts"] = normalized_artifacts
    report = {
        "target": state["target"],
        "mode": state["mode"],
        "started_at": state["started_at"],
        "finished_at": state.get("finished_at"),
        "target_summary": {
            "input": state["target"],
            "target_type": state["prechecks"]["resolution"].get("target_type"),
            "resolved_ip": state["prechecks"]["resolution"].get("resolved_ip"),
            "hostname": state["prechecks"]["resolution"].get("hostname"),
        },
        "scan_summary": {
            "reachability": _icmp_status(state["prechecks"]),
            "open_ports": state["nmap"]["parsed"].get("scan_summary", {}).get("total_open_ports", 0),
            "web_targets_analyzed": len(state.get("web_targets", [])),
            "inventory_entries": len(state.get("inventory", [])),
            "findings": len(state.get("findings", [])),
            "version_detection_attempted": bool(state.get("nmap", {}).get("version_detection_attempted")),
            "version_detection_status": state.get("nmap", {}).get("version_detection_status", "skipped"),
        },
        "host_summary": {
            "target": state["target"],
            "resolved_ip": state["prechecks"]["resolution"].get("resolved_ip"),
            "icmp_status": _icmp_status(state["prechecks"]),
            "nmap_status": _nmap_status(state["nmap"]),
            "detected_services": len(state["nmap"]["parsed"].get("open_ports", [])),
        },
        "services": state.get("services", []),
        "web_targets": state.get("web_targets", []),
        "inventory": state.get("inventory", []),
        "findings": state.get("findings", []),
        "provider_status": state.get("provider_status", {}),
        "vulnerability_api_results": state.get("vulnerability_api_results", []),
        "artifacts": normalized_artifacts,
        "executions": state.get("executions", []),
        "nmap": state.get("nmap", {}),
    }
    report["scan_summary"]["vulnerability_matches"] = _count_vulnerability_matches(report)
    report["summary"] = _build_summary_text(report)
    return report


def _render_terminal_report(report):
    lines = [
        "ReconPilot Report",
        "=================",
        f"Target: {report['target_summary']['input']} ({report['target_summary']['target_type']})",
        f"Mode: {report['mode']}",
        f"Resolved IP: {report['target_summary']['resolved_ip'] or 'unresolved'}",
        f"Reachability: {report['scan_summary']['reachability']}",
        f"Open ports: {report['scan_summary']['open_ports']}",
        f"Version detection attempted: {'yes' if report['scan_summary']['version_detection_attempted'] else 'no'}",
        f"Version detection status: {report['scan_summary']['version_detection_status']}",
        "",
        "Open Services:",
    ]
    if report["services"]:
        for service in report["services"]:
            inventory = service.get("inventory") or {}
            label = _service_summary_label(service)
            details = []
            if inventory.get("detection_source"):
                details.append(inventory["detection_source"])
            if inventory.get("confidence"):
                details.append(inventory["confidence"])
            lines.append(f"- {label}" + (f" [{', '.join(details)}]" if details else ""))
    else:
        lines.append("- none")

    lines.extend(["", "Web Targets:"])
    if report["web_targets"]:
        for item in report["web_targets"]:
            details = [
                f"status={item.get('status_code')}",
                f"final={item.get('final_url') or item.get('url')}",
            ]
            if item.get("title"):
                details.append(f"title={item.get('title')}")
            if item.get("server"):
                details.append(f"server={item.get('server')}")
            if item.get("content_type"):
                details.append(f"content-type={item.get('content_type')}")
            if item.get("script_src_count") is not None:
                details.append(f"scripts={item.get('script_src_count')}")
            if item.get("fetched_js_count") is not None:
                details.append(f"fetched_js={item.get('fetched_js_count')}")
            if item.get("whatweb_status"):
                details.append(f"whatweb={item.get('whatweb_status')}")
            lines.append(f"- {item.get('url')} " + " ".join(details))
            if item.get("technology_hints"):
                lines.append(f"  technologies: {', '.join(item.get('technology_hints')[:8])}")
            if item.get("nmap_evidence"):
                evidence = item["nmap_evidence"]
                nmap_bits = []
                if evidence.get("http_title"):
                    nmap_bits.append(f"http-title={evidence.get('http_title')}")
                if evidence.get("requested_resource"):
                    nmap_bits.append(f"requested={evidence.get('requested_resource')}")
                if evidence.get("ssl_cert_subject"):
                    nmap_bits.append(f"ssl-cert-subject={_truncate(evidence.get('ssl_cert_subject'), 80)}")
                if evidence.get("ssl_cert_san"):
                    nmap_bits.append(f"san={evidence.get('ssl_cert_san')}")
                if evidence.get("http_methods"):
                    nmap_bits.append(f"methods={','.join(evidence.get('http_methods'))}")
                if nmap_bits:
                    lines.append(f"  nmap: {'; '.join(nmap_bits)}")
    else:
        lines.append("- none")

    lines.extend(["", "Inventory:"])
    if report["inventory"]:
        for item in report["inventory"][:12]:
            location = item.get("url") or f"{item.get('host')}:{item.get('port')}"
            vuln_state = "yes" if item.get("vulnerability_lookup_ready") else f"skip:{item.get('vulnerability_lookup_reason')}"
            label = f"{item.get('product') or item.get('service_name') or 'unknown'} {item.get('version') or ''}".rstrip()
            lines.append(
                f"- {label}"
                f" @ {location} sources={','.join(item.get('sources', [])) or 'unknown'}"
                f" confidence={item.get('confidence')} vuln={vuln_state}"
            )
        if len(report["inventory"]) > 12:
            lines.append(f"- ... {len(report['inventory']) - 12} more")
    else:
        lines.append("- none")

    lines.extend(["", "Findings:"])
    if report["findings"]:
        for finding in report["findings"][:12]:
            lines.append(f"- [{finding.get('severity')}] {finding.get('title')} -> {finding.get('affected') or 'n/a'}")
        if len(report["findings"]) > 12:
            lines.append(f"- ... {len(report['findings']) - 12} more")
    else:
        lines.append("- none")

    lines.extend(["", "Potential Vulnerabilities:"])
    vuln_count = 0
    for item in report["inventory"]:
        for match in item.get("vulnerabilities", []):
            vuln_count += 1
            lines.append(f"- {match.get('id')} on {item.get('product')} {item.get('version')} [{match.get('severity')}] manual verification required")
    for item in report.get("vulnerability_api_results", []):
        for match in item.get("matches", []):
            vuln_count += 1
            lines.append(f"- {match.get('vuln_id')} via {match.get('provider')} [{match.get('severity')}] confidence={match.get('confidence')} manual verification required")
    if vuln_count == 0:
        lines.append("- none")

    lines.extend(["", "Provider Status:"])
    for name, status in report["provider_status"].items():
        lines.append(
            f"- {name}: status={status.get('status')} queries={status.get('queries')} "
            f"matches={status.get('matches')} skipped={status.get('skipped')}"
        )
        if status.get("reasons"):
            lines.append(f"  reasons: {'; '.join(status.get('reasons'))}")
    return lines


def print_runtime_summary(state, session_path=None):
    report = build_recon_report(state)
    for line in _render_terminal_report(report):
        print(line)
    if session_path is not None:
        print(f"[SUMMARY] session: {display_output_path(session_path)}")
    return report


def _render_markdown(report):
    scan_summary = report.get("scan_summary", {})
    lines = [
        "# ReconPilot Report",
        "",
        "## Target Summary",
        f"- Input: `{report['target_summary']['input']}`",
        f"- Target type: `{report['target_summary']['target_type']}`",
        f"- Mode: `{report['mode']}`",
        f"- Resolved IP: `{report['target_summary']['resolved_ip'] or 'unresolved'}`",
        f"- Started: `{report['started_at']}`",
        f"- Finished: `{report['finished_at'] or 'in-progress'}`",
        "",
        "## Scan Summary",
        f"- Reachability: `{scan_summary.get('reachability', 'unknown')}`",
        f"- Open ports: `{scan_summary.get('open_ports', 0)}`",
        f"- Web targets analyzed: `{scan_summary.get('web_targets_analyzed', 0)}`",
        f"- Inventory entries: `{scan_summary.get('inventory_entries', 0)}`",
        f"- Findings: `{scan_summary.get('findings', 0)}`",
        f"- Version detection attempted: `{'yes' if scan_summary.get('version_detection_attempted') else 'no'}`",
        f"- Version detection status: `{scan_summary.get('version_detection_status', 'skipped')}`",
        f"- Vulnerability matches: `{scan_summary.get('vulnerability_matches', 0)}`",
        "",
        "## Open Services",
    ]
    if report["services"]:
        for service in report["services"]:
            inventory = service.get("inventory") or {}
            lines.append(
                f"- `{service.get('port')}/{service.get('protocol')} {service.get('service')}`"
                f" product=`{inventory.get('product') or 'unknown'}` version=`{inventory.get('version') or 'unknown'}`"
            )
    else:
        lines.append("- None")
    lines.extend(["", "## Web Analysis"])
    if report["web_targets"]:
        for item in report["web_targets"]:
            lines.append(
                f"- `{item.get('url')}` status=`{item.get('status_code')}` final=`{item.get('final_url') or item.get('url')}`"
            )
            lines.append(f"  title=`{item.get('title') or 'unknown'}` server=`{item.get('server') or 'unknown'}` x-powered-by=`{item.get('x_powered_by') or 'unknown'}`")
            lines.append(f"  content-type=`{item.get('content_type') or 'unknown'}` scripts=`{item.get('script_src_count', 0)}` fetched_js=`{item.get('fetched_js_count', 0)}` whatweb=`{item.get('whatweb_status') or 'unknown'}`")
            if item.get("whatweb_excerpt"):
                lines.append(f"  whatweb_excerpt=`{_truncate(item.get('whatweb_excerpt'), 120)}`")
            if item.get("technology_hints"):
                lines.append(f"  technologies=`{', '.join(item.get('technology_hints')[:8])}`")
            if item.get("nmap_evidence"):
                lines.append(f"  nmap_evidence=`{_truncate(item.get('nmap_evidence'), 180)}`")
    else:
        lines.append("- None")
    lines.extend(["", "## Detected Technologies / Inventory"])
    if report["inventory"]:
        for item in report["inventory"]:
            location = item.get("url") or f"{item.get('host')}:{item.get('port')}"
            vuln_label = "yes" if item.get("vulnerability_lookup_ready") else f"skipped ({item.get('vulnerability_lookup_reason')})"
            lines.append(
                f"- `{item.get('product') or item.get('service_name') or 'unknown'}`"
                f" version=`{item.get('version') or 'unknown'}` location=`{location}`"
                f" sources=`{', '.join(item.get('sources', [])) or 'unknown'}`"
                f" confidence=`{item.get('confidence')}` vuln_lookup=`{vuln_label}`"
            )
    else:
        lines.append("- None")
    lines.extend(["", "## Web Findings"])
    if report["findings"]:
        for finding in report["findings"]:
            lines.append(
                f"- `{finding.get('severity')}` {finding.get('title')} affected=`{finding.get('affected') or 'n/a'}` evidence=`{_truncate(finding.get('evidence'), 120)}`"
            )
    else:
        lines.append("- None")
    lines.extend(["", "## Potential Vulnerabilities"])
    found_vulns = False
    for item in report["inventory"]:
        for match in item.get("vulnerabilities", []):
            found_vulns = True
            lines.append(
                f"- `{match.get('id')}` severity=`{match.get('severity')}` product=`{item.get('product')}` version=`{item.get('version')}`"
                f" provider=`{match.get('source')}` confidence=`{match.get('confidence')}` manual verification required"
            )
    for item in report.get("vulnerability_api_results", []):
        for match in item.get("matches", []):
            found_vulns = True
            lines.append(
                f"- `{match.get('vuln_id')}` severity=`{match.get('severity')}` provider=`{match.get('provider')}`"
                f" confidence=`{match.get('confidence')}` matched_by=`{match.get('matched_by')}` manual verification required"
            )
    if not found_vulns:
        lines.append("- None")
    lines.extend(["", "## Provider Status"])
    for name, status in report["provider_status"].items():
        lines.append(
            f"- `{name}` status=`{status.get('status')}` queries=`{status.get('queries')}` matches=`{status.get('matches')}`"
            f" skipped=`{status.get('skipped')}` reasons=`{'; '.join(status.get('reasons', [])) or 'none'}`"
        )
    lines.extend([
        "",
        "## Recommendations",
        "- Verify version-based matches manually before making exploitability claims.",
        "- Prioritize high and medium findings first.",
        "- Review exposed services and interesting web endpoints.",
        "",
    ])
    return "\n".join(lines)


def save_recon_report(state, report):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    base_name = state["started_at"].replace(":", "-")
    json_path = REPORTS_DIR / f"{base_name}.json"
    markdown_path = REPORTS_DIR / f"{base_name}.md"

    report_artifact = _normalize_artifact({
        "service": "report",
        "port": 0,
        "type": "report_markdown",
        "source": str(markdown_path),
        "retrieved": True,
        "content": f"ReconPilot markdown report for {state['target']}",
    })
    add_artifact(state, report_artifact)
    report["artifacts"] = [_normalize_artifact(item) for item in state["artifacts"]]
    report["summary"] = _build_summary_text(report)

    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    markdown_path.write_text(_render_markdown(report), encoding="utf-8")
    return {"json": json_path, "markdown": markdown_path}


def write_output_report(report, output_path):
    path = Path(output_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_render_markdown(report), encoding="utf-8")
        return path, None
    except OSError as exc:
        return None, str(exc)


def print_recon_report(report, report_paths):
    print("[REPORT] generated")
    print(f"[SUMMARY] report: {display_output_path(report_paths['markdown'])}")
