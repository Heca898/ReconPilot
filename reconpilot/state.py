from __future__ import annotations

from copy import deepcopy
from datetime import datetime

from reconpilot.engine.executor import normalize_command_output


CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}


def _normalize_artifact(artifact):
    return {
        "service": str(artifact.get("service", "unknown")),
        "port": int(artifact.get("port", 0) or 0),
        "type": str(artifact.get("type", "unknown")),
        "source": str(artifact.get("source", artifact.get("path", ""))),
        "retrieved": bool(artifact.get("retrieved", False)),
        "content": " ".join(str(artifact.get("content", artifact.get("name", ""))).split())[:200],
    }


def _normalize_value(value):
    cleaned = " ".join(str(value or "").split()).strip()
    return cleaned or None


def _normalize_raw_evidence(value):
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return deepcopy(value)
    cleaned = " ".join(str(value).split()).strip()
    return cleaned or None


def _normalize_sources(value):
    if isinstance(value, (list, tuple, set)):
        return sorted({_normalize_value(item) for item in value if _normalize_value(item)})
    single = _normalize_value(value)
    return [single] if single else []


def _normalize_tags(value):
    if isinstance(value, (list, tuple, set)):
        return sorted({str(item).strip().lower() for item in value if str(item).strip()})
    if not value:
        return []
    return [str(value).strip().lower()]


def _precise_cpe(value):
    normalized = _normalize_value(value)
    if not normalized:
        return False
    lowered = normalized.lower()
    if lowered.startswith("cpe:2.3:"):
        parts = normalized.split(":")
        if len(parts) < 6:
            return False
        version = parts[5].strip()
        return bool(version and version not in {"*", "-"})
    if lowered.startswith("cpe:/"):
        return False
    return False


def _ensure_inventory_shape(entry):
    return {
        "type": _normalize_value(entry.get("type")) or "service",
        "host": _normalize_value(entry.get("host")),
        "url": _normalize_value(entry.get("url")),
        "port": int(entry["port"]) if entry.get("port") not in {None, ""} else None,
        "protocol": _normalize_value(entry.get("protocol")),
        "service_name": _normalize_value(entry.get("service_name")),
        "product": _normalize_value(entry.get("product")),
        "version": _normalize_value(entry.get("version")),
        "cpe": _normalize_value(entry.get("cpe")),
        "source": _normalize_value(entry.get("source")),
        "sources": _normalize_sources(entry.get("sources") or entry.get("source")),
        "confidence": (_normalize_value(entry.get("confidence")) or "low").lower(),
        "raw_evidence": [_normalize_raw_evidence(item) for item in (entry.get("raw_evidence") or [])]
        if isinstance(entry.get("raw_evidence"), list)
        else ([_normalize_raw_evidence(entry.get("raw_evidence"))] if _normalize_raw_evidence(entry.get("raw_evidence")) else []),
        "tags": _normalize_tags(entry.get("tags")),
        "version_conflict": bool(entry.get("version_conflict", False)),
        "vulnerability_lookup_ready": bool(entry.get("vulnerability_lookup_ready", False)),
        "vulnerability_lookup_reason": _normalize_value(entry.get("vulnerability_lookup_reason")),
    }


def create_session_state(args):
    mode = getattr(args, "mode", "recon")
    vuln_provider = getattr(args, "vuln_provider", "local")
    vuln_api_enabled = bool(getattr(args, "vuln_api", False))
    vuln_api_provider = getattr(args, "vuln_api_provider", "nvd")
    debug_vulns = bool(getattr(args, "debug_vulns", False))
    debug_web = bool(getattr(args, "debug_web", False))
    render_web = bool(getattr(args, "render_web", False))
    timeout = float(getattr(args, "timeout", 120) or 120)
    output_path = getattr(args, "output", None)
    save_session = bool(getattr(args, "save_session", False))
    session_output = getattr(args, "session_output", None)
    ports = getattr(args, "ports", "top-1000") or "top-1000"
    return {
        "target": args.target,
        "mode": mode,
        "timeout": timeout,
        "output": output_path,
        "ports": ports,
        "save_session": save_session,
        "session_output": session_output,
        "vuln_provider": vuln_provider,
        "vuln_api": vuln_api_enabled,
        "vuln_api_provider": vuln_api_provider,
        "debug_vulns": debug_vulns,
        "debug_web": debug_web,
        "render_web": render_web,
        "started_at": datetime.now().isoformat(),
        "finished_at": None,
        "target_info": {
            "input": args.target,
            "target_type": None,
            "hostname": None,
            "normalized_target": None,
            "resolved_ip": None,
            "scheme": None,
            "port": None,
            "path": None,
        },
        "prechecks": {
            "resolution": {
                "input": args.target,
                "target_type": None,
                "hostname": None,
                "normalized_target": None,
                "resolved_ip": None,
                "scheme": None,
                "port": None,
                "path": None,
                "dns_resolution_success": False,
                "error": None,
            },
            "icmp": {
                "ping_available": False,
                "icmp_reachable": None,
                "command": [],
                "error": None,
            },
            "http_candidates": [],
        },
        "nmap": {
            "raw": "",
            "parsed": {
                "host_up": False,
                "open_ports": [],
                "scan_summary": {
                    "total_open_ports": 0,
                },
                "command": [],
                "returncode": None,
                "success": False,
                "timed_out": False,
                "duration_seconds": None,
                "error": None,
                "scan_context": {},
            },
            "phases": [],
            "version_detection_attempted": False,
            "version_detection_status": "skipped",
        },
        "services": [],
        "web_targets": [],
        "inventory": [],
        "findings": [],
        "provider_status": {
            "local": {"status": "pending", "matches": 0, "queries": 0, "skipped": 0, "reasons": []},
            "nvd": {"status": "disabled", "matches": 0, "queries": 0, "skipped": 0, "reasons": []},
        },
        "artifacts": [],
        "executions": [],
    }


def add_artifact(state, artifact):
    artifact = _normalize_artifact(artifact)
    if artifact not in state["artifacts"]:
        state["artifacts"].append(artifact)


def add_execution(state, stage, execution_result, repair_attempt=0):
    state["executions"].append({
        "stage": stage,
        "repair_attempt": repair_attempt,
        "command": execution_result["command"],
        "returncode": execution_result["returncode"],
        "stdout": normalize_command_output(execution_result.get("stdout")),
        "stderr": normalize_command_output(execution_result.get("stderr")),
        "success": execution_result["success"],
    })


def add_web_target(state, entry):
    normalized = {
        "url": _normalize_value(entry.get("url")),
        "source": _normalize_value(entry.get("source")) or "unknown",
        "reachable": bool(entry.get("reachable", False)),
        "status_code": entry.get("status_code"),
        "final_url": _normalize_value(entry.get("final_url")),
        "title": _normalize_value(entry.get("title")),
        "server": _normalize_value(entry.get("server")),
        "x_powered_by": _normalize_value(entry.get("x_powered_by")),
        "content_type": _normalize_value(entry.get("content_type")),
        "script_src_count": int(entry.get("script_src_count", 0) or 0),
        "fetched_js_count": int(entry.get("fetched_js_count", 0) or 0),
        "whatweb_status": _normalize_value(entry.get("whatweb_status")),
        "whatweb_excerpt": _normalize_value(entry.get("whatweb_excerpt")),
        "technology_hints": list(entry.get("technology_hints") or []),
        "nmap_evidence": dict(entry.get("nmap_evidence") or {}),
    }
    for current in state["web_targets"]:
        if current.get("url") != normalized["url"]:
            continue
        current["source"] = current.get("source") or normalized["source"]
        current["reachable"] = current.get("reachable") or normalized["reachable"]
        if normalized.get("status_code") is not None:
            current["status_code"] = normalized["status_code"]
        if normalized.get("final_url"):
            current["final_url"] = normalized["final_url"]
        for key in ("title", "server", "x_powered_by", "content_type", "whatweb_status", "whatweb_excerpt"):
            if normalized.get(key):
                current[key] = normalized[key]
        for key in ("script_src_count", "fetched_js_count"):
            if normalized.get(key):
                current[key] = normalized[key]
        if normalized.get("technology_hints"):
            known = set(current.get("technology_hints", []))
            for item in normalized["technology_hints"]:
                if item not in known:
                    current.setdefault("technology_hints", []).append(item)
                    known.add(item)
        if normalized.get("nmap_evidence"):
            current.setdefault("nmap_evidence", {}).update({k: v for k, v in normalized["nmap_evidence"].items() if v})
        return
    state["web_targets"].append(normalized)


def add_finding(state, finding):
    normalized = {
        "title": _normalize_value(finding.get("title")) or "Untitled finding",
        "severity": (_normalize_value(finding.get("severity")) or "info").lower(),
        "affected": _normalize_value(finding.get("affected") or finding.get("url") or finding.get("service")),
        "evidence": finding.get("evidence"),
        "recommendation": _normalize_value(finding.get("recommendation")),
        "source": _normalize_value(finding.get("source")) or "unknown",
        "type": _normalize_value(finding.get("type")),
    }
    if normalized not in state["findings"]:
        state["findings"].append(normalized)


def update_provider_status(state, provider_name, *, status=None, matches=0, queries=0, skipped=0, reason=None):
    provider = state.setdefault("provider_status", {}).setdefault(
        provider_name,
        {"status": "pending", "matches": 0, "queries": 0, "skipped": 0, "reasons": []},
    )
    if status:
        provider["status"] = status
    provider["matches"] += int(matches or 0)
    provider["queries"] += int(queries or 0)
    provider["skipped"] += int(skipped or 0)
    normalized_reason = _normalize_value(reason)
    if normalized_reason and normalized_reason not in provider["reasons"]:
        provider["reasons"].append(normalized_reason)


def inventory_lookup_ready(entry):
    cpe = _normalize_value(entry.get("cpe"))
    if _precise_cpe(cpe):
        return True, None
    product = _normalize_value(entry.get("product"))
    version = _normalize_value(entry.get("version"))
    service_name = (_normalize_value(entry.get("service_name")) or "").lower()
    if not product:
        return False, "insufficient product/version evidence"
    if not version:
        return False, "insufficient product/version evidence"
    if product.lower() in {"http", "https", "http-proxy", "https-alt", "ibm-db2-admin", "unknown", "tcpwrapped"}:
        return False, "generic product"
    if service_name in {"http", "https"} and product.lower() in {"nginx", "apache httpd", "apache"} and not version:
        return False, "insufficient product/version evidence"
    return True, None


def _normalized_identity(value):
    return (_normalize_value(value) or "").lower()


def _inventory_entries_should_merge(current, candidate):
    current_product = _normalized_identity(current.get("product"))
    candidate_product = _normalized_identity(candidate.get("product"))
    current_service = _normalized_identity(current.get("service_name"))
    candidate_service = _normalized_identity(candidate.get("service_name"))
    same_url = bool(current.get("url") and candidate.get("url") and current["url"] == candidate["url"])
    same_host = bool(current.get("host") and candidate.get("host") and current["host"] == candidate["host"])
    same_port = current.get("port") == candidate.get("port") and current.get("protocol") == candidate.get("protocol")
    compatible_types = {current["type"], candidate["type"]}

    if current["type"] != candidate["type"] and compatible_types != {"service", "web_component"}:
        return False

    if current["type"] == "service":
        return same_host and same_port and (
            current_service == candidate_service
            or not current_service
            or not candidate_service
        )

    if compatible_types == {"service", "web_component"} and current_product and candidate_product and current_product == candidate_product:
        return (same_url or same_host) and same_port

    if current_product and candidate_product:
        if current_product == candidate_product:
            if current["type"] == "web_component" and same_url:
                return True
            return (same_url or same_host) and (same_port or current_service == candidate_service)
        return False

    if current_service and candidate_service and current_service == candidate_service:
        return (same_url or same_host) and same_port

    return False


def upsert_inventory_entry(state, entry):
    candidate = _ensure_inventory_shape(entry)
    ready, reason = inventory_lookup_ready(candidate)
    candidate["vulnerability_lookup_ready"] = ready
    candidate["vulnerability_lookup_reason"] = reason

    best_index = None
    best_score = -1
    for index, current in enumerate(state["inventory"]):
        if not _inventory_entries_should_merge(current, candidate):
            continue
        shared_port = current.get("port") == candidate.get("port") and current.get("protocol") == candidate.get("protocol")
        shared_host = bool(current.get("host") and candidate.get("host") and current["host"] == candidate["host"])
        shared_url = bool(current.get("url") and candidate.get("url") and current["url"] == candidate["url"])
        shared_product = bool(
            current.get("product")
            and candidate.get("product")
            and current["product"].lower() == candidate["product"].lower()
        )
        score = int(shared_port) + int(shared_host) + int(shared_url) + int(shared_product)
        if score > best_score:
            best_index = index
            best_score = score

    if best_index is None:
        state["inventory"].append(candidate)
        return candidate

    current = state["inventory"][best_index]
    for key in ("host", "url", "port", "protocol", "service_name"):
        incoming = candidate.get(key)
        if not current.get(key) and incoming:
            current[key] = incoming
    if candidate.get("product") and not current.get("product"):
        current["product"] = candidate["product"]
    if candidate.get("cpe") and not current.get("cpe"):
        current["cpe"] = candidate["cpe"]

    current_confidence = CONFIDENCE_RANK.get(current.get("confidence"), 0)
    incoming_confidence = CONFIDENCE_RANK.get(candidate.get("confidence"), 0)
    if incoming_confidence > current_confidence:
        current["confidence"] = candidate["confidence"]
    if candidate.get("version"):
        if not current.get("version"):
            current["version"] = candidate["version"]
        elif current["version"] != candidate["version"]:
            current["version_conflict"] = True
            if incoming_confidence > current_confidence:
                current["version"] = candidate["version"]
                current["confidence"] = candidate["confidence"]
    if candidate.get("source") and candidate["source"] not in current["sources"]:
        current["sources"].append(candidate["source"])
        current["sources"].sort()
    current["tags"] = sorted(set(current.get("tags", [])) | set(candidate.get("tags", [])))
    for item in candidate.get("raw_evidence", []):
        if item and item not in current["raw_evidence"]:
            current["raw_evidence"].append(item)
    if candidate.get("source") and not current.get("source"):
        current["source"] = candidate["source"]
    ready, reason = inventory_lookup_ready(current)
    current["vulnerability_lookup_ready"] = ready
    current["vulnerability_lookup_reason"] = reason
    return current
