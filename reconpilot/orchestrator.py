from __future__ import annotations

from dataclasses import asdict
from datetime import datetime

from reconpilot.engine.executor import normalize_command_output
from reconpilot.modules import is_web_service, run_service_module, select_module_for_service
from reconpilot.modules.common import build_service_result, build_service_target
from reconpilot.parsers.nmap_parser import parse_nmap_output
from reconpilot.prechecks.reachability import ping_target
from reconpilot.prechecks.target_utils import resolve_target
from reconpilot.runners.nmap_runner import run_nmap_scan
from reconpilot.session_store import save_state_snapshot
from reconpilot.state import (
    add_execution,
    add_web_target,
    create_session_state,
    update_provider_status,
    upsert_inventory_entry,
)
from reconpilot.vulns.local_matcher import match_vulnerabilities
from reconpilot.vulns.providers import VulnerabilityProviderResult, VulnerabilityQuery, get_api_vulnerability_provider, get_local_vulnerability_providers


def _log(stage, message):
    print(f"[{stage}] {message}")


def _provider_result_to_dict(result):
    data = asdict(result)
    for match in data["matches"]:
        if match.get("raw") is None:
            match.pop("raw", None)
    return data


def _serialize_execution(result):
    return {
        "command": result.get("command") or [],
        "returncode": result["returncode"] if result.get("returncode") is not None else -1,
        "stdout": normalize_command_output(result.get("stdout")),
        "stderr": normalize_command_output(result.get("stderr")),
        "success": result.get("success", False),
    }


def _store_nmap_phase(state, name, result, parsed):
    state["nmap"]["phases"].append({
        "name": name,
        "raw": normalize_command_output(result.get("stdout")),
        "parsed": parsed,
        "scan_context": result.get("scan_context") or {},
        "command": result.get("command") or [],
        "returncode": result.get("returncode"),
        "success": result.get("success", False),
        "timed_out": result.get("timed_out", False),
        "duration_seconds": result.get("duration_seconds"),
        "error": normalize_command_output(result.get("stderr")) or None,
    })


def _merge_open_ports(primary, followup):
    merged = {}
    for item in primary:
        merged[(item["port"], item["protocol"])] = dict(item)
    for item in followup:
        key = (item["port"], item["protocol"])
        if key not in merged:
            merged[key] = dict(item)
            continue
        current = merged[key]
        for field in ("product", "version", "extra_info", "cpe", "raw_evidence", "detection_source", "confidence", "service"):
            if item.get(field):
                current[field] = item[field]
        if item.get("script_evidence"):
            current.setdefault("script_evidence", {}).update(item["script_evidence"])
    return list(merged.values())


def _session_output_path(state):
    return state.get("session_output") if state.get("save_session") else None


def _save_session_snapshot(state):
    if not state.get("save_session"):
        return None
    return save_state_snapshot(state, path=_session_output_path(state))


def _needs_version_detection(state, open_ports):
    if not open_ports:
        return False
    if state["mode"] == "version-detect" or state.get("vuln_api"):
        return True
    for item in open_ports:
        if item.get("product") and item.get("version"):
            continue
        return True
    return False


def _version_detection_timeout(state):
    base_timeout = int(state.get("timeout", 120))
    if state["mode"] == "version-detect":
        return max(min(base_timeout, 180), 90)
    return min(base_timeout, 120)


def _discovered_web_ports(open_ports):
    ports = []
    for item in open_ports:
        if is_web_service(item.get("service"), item.get("port")):
            ports.append(item.get("port"))
    return sorted({int(port) for port in ports if port})


def _should_run_nmap(state):
    target_type = state["prechecks"]["resolution"].get("target_type")
    if target_type == "url":
        return False
    if state["mode"] == "web-basic" and target_type == "domain":
        return False
    return True


def _candidate_web_urls_for_domain(state):
    resolution = state["prechecks"]["resolution"]
    hostname = resolution.get("hostname") or state["target"]
    urls = [f"https://{hostname}", f"http://{hostname}"]
    return [{"url": url, "service": "http", "port": 443 if url.startswith("https://") else 80, "protocol": "tcp"} for url in urls]


def _candidate_web_urls_from_services(state):
    resolution = state["prechecks"]["resolution"]
    host = resolution.get("hostname") or resolution.get("resolved_ip") or state["target"]
    candidates = []
    for service in state["nmap"]["parsed"].get("open_ports", []):
        if not is_web_service(service.get("service"), service.get("port")):
            continue
        scheme = "https" if service["port"] in {443, 8443} or "https" in str(service.get("service", "")).lower() else "http"
        url = f"{scheme}://{host}:{service['port']}"
        candidates.append({
            "url": url,
            "service": service.get("service") or "http",
            "port": service["port"],
            "protocol": service["protocol"],
        })
    deduped = []
    for item in candidates:
        if item not in deduped:
            deduped.append(item)
    return deduped


def _probe_web_candidate(state, candidate):
    from reconpilot.modules.http import run_http_module

    result = run_http_module(state, {
        "target": state["prechecks"]["resolution"].get("hostname") or state["prechecks"]["resolution"].get("resolved_ip") or state["target"],
        "host": state["prechecks"]["resolution"].get("resolved_ip") or state["target"],
        "hostname": state["prechecks"]["resolution"].get("hostname"),
        "port": candidate["port"],
        "protocol": candidate["protocol"],
        "service": candidate["service"],
        "url": candidate["url"],
        "inventory": {"detection_source": "web_probe", "confidence": "medium"},
    })
    result["module"] = "http"
    result["host"] = state["prechecks"]["resolution"].get("resolved_ip") or state["target"]
    return result


def _build_vulnerability_query(state, inventory_entry):
    return VulnerabilityQuery(
        target=state.get("target"),
        service_name=inventory_entry.get("service_name"),
        product=inventory_entry.get("product"),
        version=inventory_entry.get("version"),
        cpe=inventory_entry.get("cpe"),
        confidence=inventory_entry.get("confidence"),
        port=inventory_entry.get("port"),
        protocol=inventory_entry.get("protocol"),
        raw_banner=str(inventory_entry.get("raw_evidence")),
        source=inventory_entry.get("source"),
    )


def _attach_local_vulnerabilities(state):
    providers = get_local_vulnerability_providers(state.get("vuln_provider", "local"))
    if not providers:
        update_provider_status(state, "local", status="disabled")
        return

    any_query = False
    total_matches = 0
    for entry in state["inventory"]:
        if not entry.get("vulnerability_lookup_ready"):
            update_provider_status(state, "local", skipped=1, reason=entry.get("vulnerability_lookup_reason"))
            continue
        any_query = True
        matches = match_vulnerabilities(entry, providers=providers, debug=bool(state.get("debug_vulns")))
        if matches:
            entry.setdefault("vulnerabilities", [])
            for match in matches:
                if match not in entry["vulnerabilities"]:
                    entry["vulnerabilities"].append(match)
            total_matches += len(matches)
        update_provider_status(state, "local", queries=1, matches=len(matches))
    update_provider_status(state, "local", status="completed" if any_query else "empty")

    for service in state["services"]:
        service["vulnerabilities"] = []
        for entry in state["inventory"]:
            if entry.get("port") == service.get("port") and entry.get("protocol") == service.get("protocol"):
                for match in entry.get("vulnerabilities", []):
                    if match not in service["vulnerabilities"]:
                        service["vulnerabilities"].append(match)


def _attach_api_vulnerabilities(state):
    provider_name = state.get("vuln_api_provider", "nvd")
    if not state.get("vuln_api"):
        update_provider_status(state, provider_name, status="disabled")
        return
    provider = get_api_vulnerability_provider(provider_name)
    if provider is None:
        update_provider_status(state, provider_name, status="failed", reason="unsupported provider")
        return
    if hasattr(provider, "debug"):
        provider.debug = bool(state.get("debug_vulns"))

    queried = 0
    results = []
    matched = 0
    skipped = 0
    statuses = []
    reasons = []
    for entry in state["inventory"]:
        if not entry.get("vulnerability_lookup_ready"):
            skipped += 1
            if entry.get("vulnerability_lookup_reason"):
                reasons.append(entry.get("vulnerability_lookup_reason"))
            results.append(_provider_result_to_dict(VulnerabilityProviderResult(
                provider=provider_name,
                query=_build_vulnerability_query(state, entry),
                status="skipped",
                error=entry.get("vulnerability_lookup_reason"),
            )))
            continue
        queried += 1
        query = _build_vulnerability_query(state, entry)
        try:
            result = provider.search(query)
        except Exception as exc:
            result = VulnerabilityProviderResult(provider=provider_name, query=query, status="failed", error=str(exc))
        results.append(_provider_result_to_dict(result))
        statuses.append(result.status)
        matched += len(result.matches)
        if result.error:
            reasons.append(result.error)
        if result.matches:
            entry.setdefault("vulnerability_api", [])
            entry["vulnerability_api"].append(_provider_result_to_dict(result))
    final_status = "empty"
    if queried == 0 and skipped > 0:
        final_status = "skipped"
    elif matched > 0 and any(status in {"failed", "timeout", "rate_limited", "partial"} for status in statuses):
        final_status = "partial"
    elif matched > 0:
        final_status = "completed"
    elif queried == 0:
        final_status = "empty"
    elif any(status in {"failed", "timeout", "rate_limited"} for status in statuses):
        if any(status in {"completed", "empty"} for status in statuses):
            final_status = "partial"
        else:
            final_status = statuses[-1]
    elif any(status == "completed" for status in statuses):
        final_status = "completed"
    elif any(status == "empty" for status in statuses):
        final_status = "empty"
    state["provider_status"][provider_name] = {
        "status": final_status,
        "matches": matched,
        "queries": queried,
        "skipped": skipped,
        "reasons": sorted({reason for reason in reasons if reason}),
    }
    state["vulnerability_api_results"] = results


def run_prechecks(state):
    resolution = resolve_target(state["target"])
    state["prechecks"]["resolution"] = resolution
    state["target_info"] = {
        key: resolution.get(key)
        for key in ("input", "target_type", "hostname", "normalized_target", "resolved_ip", "scheme", "port", "path")
    }

    if resolution["target_type"] == "url":
        state["prechecks"]["icmp"] = {
            "ping_available": False,
            "icmp_reachable": None,
            "command": [],
            "returncode": -1,
            "stdout": "",
            "stderr": "",
            "success": False,
            "error": "skipped for URL target",
        }
        add_web_target(state, {"url": resolution["normalized_target"], "source": "input", "reachable": False, "status_code": None, "final_url": resolution["normalized_target"]})
        _log("PRECHECK", "done")
        return

    if not resolution["dns_resolution_success"]:
        state["prechecks"]["icmp"] = {
            "ping_available": False,
            "icmp_reachable": None,
            "command": [],
            "returncode": -1,
            "stdout": "",
            "stderr": "",
            "success": False,
            "error": "skipped because target resolution failed",
        }
        _log("PRECHECK", "done")
        return

    icmp = ping_target(resolution["resolved_ip"])
    state["prechecks"]["icmp"] = icmp
    if icmp["command"]:
        add_execution(state, "precheck", {
            "command": icmp["command"],
            "returncode": icmp["returncode"],
            "stdout": icmp["stdout"],
            "stderr": icmp["stderr"],
            "success": icmp["success"],
        })
    if resolution["target_type"] == "domain":
        state["prechecks"]["http_candidates"] = _candidate_web_urls_for_domain(state)
    _log("PRECHECK", "done")


def run_nmap(state):
    resolution = state["prechecks"]["resolution"]
    if not _should_run_nmap(state):
        state["nmap"]["parsed"]["error"] = "nmap skipped for this target/mode"
        _log("NMAP", "scan skipped")
        return
    if not resolution["resolved_ip"]:
        state["nmap"]["parsed"]["error"] = "nmap skipped because target resolution failed"
        _log("NMAP", "scan skipped (target unresolved)")
        return

    result = run_nmap_scan(
        target=resolution["resolved_ip"],
        mode="web-basic" if state["mode"] == "web-basic" else "recon",
        icmp_reachable=state["prechecks"]["icmp"]["icmp_reachable"],
        timeout=int(state.get("timeout", 120)),
        ports=state.get("ports", "top-1000"),
    )
    add_execution(state, "nmap", _serialize_execution(result))
    parsed = parse_nmap_output(normalize_command_output(result.get("stdout")))
    parsed["command"] = result.get("command") or []
    parsed["returncode"] = result.get("returncode")
    parsed["success"] = result.get("success", False)
    parsed["timed_out"] = result.get("timed_out", False)
    parsed["duration_seconds"] = result.get("duration_seconds")
    parsed["error"] = normalize_command_output(result.get("stderr")) or None
    parsed["scan_context"] = result.get("scan_context") or {}
    _store_nmap_phase(state, "initial", result, parsed)

    open_ports = parsed["open_ports"]
    if _needs_version_detection(state, open_ports):
        state["nmap"]["version_detection_attempted"] = True
        followup = run_nmap_scan(
            target=resolution["resolved_ip"],
            mode="recon",
            icmp_reachable=state["prechecks"]["icmp"]["icmp_reachable"],
            timeout=_version_detection_timeout(state),
            open_ports=[item["port"] for item in open_ports],
            version_detection=True,
            ports=state.get("ports", "top-1000"),
        )
        add_execution(state, "nmap:version_detection", _serialize_execution(followup))
        followup_parsed = parse_nmap_output(normalize_command_output(followup.get("stdout")))
        followup_parsed["command"] = followup.get("command") or []
        followup_parsed["returncode"] = followup.get("returncode")
        followup_parsed["success"] = followup.get("success", False)
        followup_parsed["timed_out"] = followup.get("timed_out", False)
        followup_parsed["duration_seconds"] = followup.get("duration_seconds")
        followup_parsed["error"] = normalize_command_output(followup.get("stderr")) or None
        followup_parsed["scan_context"] = followup.get("scan_context") or {}
        _store_nmap_phase(state, "version_detection", followup, followup_parsed)
        parsed["open_ports"] = _merge_open_ports(parsed["open_ports"], followup_parsed["open_ports"])
        parsed["scan_summary"]["total_open_ports"] = len(parsed["open_ports"])
        if followup.get("timed_out"):
            state["nmap"]["version_detection_status"] = "timeout"
        elif followup.get("success"):
            state["nmap"]["version_detection_status"] = "completed"
        elif followup_parsed["open_ports"]:
            state["nmap"]["version_detection_status"] = "partial"
        else:
            state["nmap"]["version_detection_status"] = "failed"
        result_stdout = normalize_command_output(result.get("stdout"))
        followup_stdout = normalize_command_output(followup.get("stdout"))
        if followup_stdout:
            state["nmap"]["raw"] = f"{result_stdout}\n\n--- VERSION DETECTION ---\n\n{followup_stdout}"
        else:
            state["nmap"]["raw"] = result_stdout
    else:
        state["nmap"]["version_detection_status"] = "skipped"
        state["nmap"]["raw"] = normalize_command_output(result.get("stdout"))

    web_ports = _discovered_web_ports(parsed["open_ports"])
    if web_ports:
        web_evidence = run_nmap_scan(
            target=resolution["resolved_ip"],
            mode="recon",
            icmp_reachable=state["prechecks"]["icmp"]["icmp_reachable"],
            timeout=min(int(state.get("timeout", 120)), 120),
            open_ports=web_ports,
            ports=state.get("ports", "top-1000"),
            scripts=["http-title", "http-server-header", "http-methods", "ssl-cert"],
        )
        add_execution(state, "nmap:web_evidence", _serialize_execution(web_evidence))
        web_parsed = parse_nmap_output(normalize_command_output(web_evidence.get("stdout")))
        web_parsed["command"] = web_evidence.get("command") or []
        web_parsed["returncode"] = web_evidence.get("returncode")
        web_parsed["success"] = web_evidence.get("success", False)
        web_parsed["timed_out"] = web_evidence.get("timed_out", False)
        web_parsed["duration_seconds"] = web_evidence.get("duration_seconds")
        web_parsed["error"] = normalize_command_output(web_evidence.get("stderr")) or None
        web_parsed["scan_context"] = web_evidence.get("scan_context") or {}
        _store_nmap_phase(state, "web_evidence", web_evidence, web_parsed)
        parsed["open_ports"] = _merge_open_ports(parsed["open_ports"], web_parsed["open_ports"])
        parsed["scan_summary"]["total_open_ports"] = len(parsed["open_ports"])
        web_evidence_stdout = normalize_command_output(web_evidence.get("stdout"))
        if web_evidence_stdout:
            state["nmap"]["raw"] = f"{state['nmap']['raw']}\n\n--- WEB EVIDENCE ---\n\n{web_evidence_stdout}".strip()

    state["nmap"]["parsed"] = parsed
    open_count = parsed["scan_summary"]["total_open_ports"]
    if parsed.get("success"):
        _log("NMAP", f"scan completed ({open_count} ports)")
    else:
        reason = parsed.get("error") or "unknown error"
        _log("NMAP", f"scan failed ({reason})")


def run_modules(state):
    state["services"] = []
    open_ports = state["nmap"]["parsed"].get("open_ports", [])
    if not open_ports:
        _log("MODULES", "done (0 services)")
        return

    for port_entry in open_ports:
        service_target = build_service_target(state, port_entry)
        try:
            module_name = select_module_for_service(service_target["service"], service_target["port"])
        except TypeError:
            module_name = select_module_for_service(service_target["service"])
        _log(module_name.upper(), "started")
        try:
            result = run_service_module(state, {**service_target, "module": module_name})
        except Exception as exc:
            result = build_service_result(service_target, status="failed", errors=[str(exc)])
        result["module"] = module_name
        state["services"].append(result)
        artifact_count = len(result["artifacts"])
        artifact_label = "artifact" if artifact_count == 1 else "artifacts"
        if result["status"] == "completed":
            _log(module_name.upper(), f"done ({artifact_count} {artifact_label})")
        elif result["status"] == "dead_end":
            _log(module_name.upper(), "done (0 artifacts)")
        elif result["status"] == "skipped":
            _log(module_name.upper(), "skipped")
        else:
            _log(module_name.upper(), "failed")
    _log("MODULES", f"done ({len(state['services'])} services)")


def run_web_analysis(state):
    resolution = state["prechecks"]["resolution"]
    candidates = []
    if resolution.get("target_type") == "url":
        candidates = [{
            "url": resolution["normalized_target"],
            "service": "http" if resolution.get("scheme") == "http" else "https",
            "port": resolution.get("port") or (443 if resolution.get("scheme") == "https" else 80),
            "protocol": "tcp",
        }]
    elif resolution.get("target_type") == "domain":
        candidates = list(state["prechecks"].get("http_candidates", []))
    else:
        candidates = _candidate_web_urls_from_services(state)

    seen = set()
    for candidate in candidates:
        if candidate["url"] in seen:
            continue
        seen.add(candidate["url"])
        _log("WEB", f"analyzing {candidate['url']}")
        result = _probe_web_candidate(state, candidate)
        merged = False
        for service in state["services"]:
            if service.get("port") == result.get("port") and service.get("protocol") == result.get("protocol"):
                service["findings"].extend(item for item in result["findings"] if item not in service["findings"])
                service["artifacts"].extend(item for item in result["artifacts"] if item not in service["artifacts"])
                service["fingerprints"].extend(item for item in result["fingerprints"] if item not in service["fingerprints"])
                if not service.get("url"):
                    service["url"] = result.get("url")
                if result.get("inventory", {}).get("product"):
                    service["inventory"] = result["inventory"]
                merged = True
                break
        if not merged:
            state["services"].append(result)


def run_pipeline(state):
    run_prechecks(state)
    _save_session_snapshot(state)

    run_nmap(state)
    _save_session_snapshot(state)

    run_modules(state)
    run_web_analysis(state)
    _attach_local_vulnerabilities(state)
    _attach_api_vulnerabilities(state)
    state["finished_at"] = datetime.now().isoformat()
    session_path = _save_session_snapshot(state)
    return state, session_path
