import re

from reconpilot.engine.executor import check_tool_available, evaluate_command_result, execute_command, normalize_command_output
from reconpilot.state import add_artifact, add_execution, upsert_inventory_entry


FINGERPRINT_CONFIDENCE_LEVELS = {"high", "medium", "low"}
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


def build_service_inventory(port_entry):
    inventory = {
        "product": port_entry.get("product"),
        "version": port_entry.get("version"),
        "extra_info": port_entry.get("extra_info"),
        "detection_source": str(port_entry.get("detection_source", "nmap_port_label")),
        "confidence": str(port_entry.get("confidence", "medium")),
        "raw_evidence": port_entry.get("raw_evidence"),
    }
    if port_entry.get("cpe"):
        inventory["cpe"] = port_entry.get("cpe")
    return inventory


def build_service_target(state, port_entry):
    resolution = state["prechecks"]["resolution"]
    target_host = resolution.get("hostname") or resolution.get("resolved_ip") or state["target"]
    return {
        "target": target_host,
        "host": target_host,
        "hostname": resolution.get("hostname"),
        "port": port_entry.get("port"),
        "protocol": port_entry.get("protocol"),
        "state": port_entry.get("state", "open"),
        "service": port_entry.get("service", ""),
        "inventory": build_service_inventory(port_entry),
        "script_evidence": dict(port_entry.get("script_evidence") or {}),
    }


def build_module_result(service_target, status="completed"):
    return {
        "host": service_target.get("host") or service_target.get("target"),
        "url": service_target.get("url"),
        "port": service_target["port"],
        "protocol": service_target["protocol"],
        "service": service_target["service"],
        "state": service_target.get("state", "open"),
        "inventory": dict(service_target.get("inventory", build_service_inventory({}))),
        "status": status,
        "priority": "unknown",
        "findings": [],
        "fingerprints": [],
        "vulnerabilities": [],
        "vulnerability_api": [],
        "artifacts": [],
        "errors": [],
    }


def build_service_result(service_target, status="completed", priority="unknown", errors=None):
    result = build_module_result(service_target, status=status)
    result["priority"] = priority
    result["errors"] = list(errors or [])
    return result


def create_fingerprint(product, source, confidence, vendor=None, version=None):
    normalized_product = " ".join(str(product or "").split()).strip()
    normalized_source = " ".join(str(source or "").split()).strip()
    normalized_confidence = str(confidence or "").strip().lower()
    normalized_vendor = " ".join(str(vendor or "").split()).strip()
    normalized_version = " ".join(str(version or "").split()).strip()
    if not normalized_product or not normalized_source or normalized_confidence not in FINGERPRINT_CONFIDENCE_LEVELS:
        return None
    fingerprint = {"product": normalized_product, "source": normalized_source, "confidence": normalized_confidence}
    if normalized_vendor:
        fingerprint["vendor"] = normalized_vendor
    if normalized_version:
        fingerprint["version"] = normalized_version
    return fingerprint


def append_fingerprint(result, fingerprint):
    if not fingerprint:
        return
    result.setdefault("fingerprints", [])
    signature = (
        fingerprint["product"].lower(),
        fingerprint.get("vendor", "").lower(),
        fingerprint.get("version", "").lower(),
        fingerprint["source"].lower(),
    )
    known = {
        (
            item.get("product", "").lower(),
            item.get("vendor", "").lower(),
            item.get("version", "").lower(),
            item.get("source", "").lower(),
        )
        for item in result["fingerprints"]
    }
    if signature not in known:
        result["fingerprints"].append(fingerprint)


def add_fingerprint(result, product, version, extra_info, source, confidence, raw_evidence):
    fingerprint = create_fingerprint(product=product, source=source, confidence=confidence, version=version)
    if not fingerprint:
        return None
    normalized_extra_info = " ".join(str(extra_info or "").split()).strip()
    normalized_raw_evidence = " ".join(str(raw_evidence or "").split()).strip()
    if normalized_extra_info:
        fingerprint["extra_info"] = normalized_extra_info
    if normalized_raw_evidence:
        fingerprint["raw_evidence"] = normalized_raw_evidence
    append_fingerprint(result, fingerprint)
    return fingerprint


def _normalize_product_label(product):
    return " ".join(str(product or "").split()).strip().lower()


def _observation_strength(confidence, product, version):
    return (CONFIDENCE_RANK.get(str(confidence or "").lower(), -1), 1 if version else 0, 1 if product else 0)


def _products_are_similar(left, right):
    normalized_left = _normalize_product_label(left)
    normalized_right = _normalize_product_label(right)
    if not normalized_left or not normalized_right:
        return False
    return normalized_left == normalized_right or normalized_left in normalized_right or normalized_right in normalized_left


def merge_inventory_observation(result, product, version, extra_info, source, confidence, raw_evidence, cpe=None):
    normalized_product = " ".join(str(product or "").split()).strip()
    normalized_version = " ".join(str(version or "").split()).strip()
    normalized_extra_info = " ".join(str(extra_info or "").split()).strip()
    normalized_source = " ".join(str(source or "").split()).strip()
    normalized_confidence = str(confidence or "").strip().lower()
    normalized_raw_evidence = " ".join(str(raw_evidence or "").split()).strip()
    if not normalized_product or normalized_confidence not in FINGERPRINT_CONFIDENCE_LEVELS:
        return False

    inventory = result.setdefault("inventory", build_service_inventory({}))
    current_product = inventory.get("product")
    current_version = inventory.get("version")
    current_strength = _observation_strength(inventory.get("confidence"), current_product, current_version)
    incoming_strength = _observation_strength(normalized_confidence, normalized_product, normalized_version or None)

    should_update = False
    if not current_product:
        should_update = True
    elif _products_are_similar(current_product, normalized_product):
        if not current_version and normalized_version:
            should_update = True
        elif incoming_strength > current_strength:
            should_update = True
    elif current_strength[0] < incoming_strength[0] and current_strength[0] < CONFIDENCE_RANK["high"]:
        should_update = True

    if not should_update:
        return False

    inventory["product"] = normalized_product
    inventory["version"] = normalized_version or None
    inventory["extra_info"] = normalized_extra_info or None
    inventory["detection_source"] = normalized_source or inventory.get("detection_source")
    inventory["confidence"] = normalized_confidence
    inventory["raw_evidence"] = normalized_raw_evidence or inventory.get("raw_evidence")
    if cpe:
        inventory["cpe"] = cpe
    return True


def publish_service_inventory(state, result, entry_type="service", tags=None, url=None):
    inventory = result.get("inventory") or {}
    return upsert_inventory_entry(state, {
        "type": entry_type,
        "host": result.get("host"),
        "url": url or result.get("url"),
        "port": result.get("port"),
        "protocol": result.get("protocol"),
        "service_name": result.get("service"),
        "product": inventory.get("product"),
        "version": inventory.get("version"),
        "cpe": inventory.get("cpe"),
        "source": inventory.get("detection_source"),
        "confidence": inventory.get("confidence"),
        "raw_evidence": inventory.get("raw_evidence"),
        "tags": list(tags or []),
    })


def append_service_artifact(state, result, artifact):
    add_artifact(state, artifact)
    result["artifacts"].append(artifact)


def run_batch_step(state, module_name, command, timeout=20):
    tool_name = command[0] if command else ""
    if not check_tool_available(tool_name):
        execution_result = {
            "command": list(command),
            "returncode": -1,
            "stdout": "",
            "stderr": normalize_command_output(f"{tool_name} not found in PATH"),
            "success": False,
        }
        add_execution(state, f"module:{module_name}", execution_result)
        return {**execution_result, "evaluation": {"success": False, "timed_out": False, "useful_output": False, "reason": "tool_not_available"}}

    execution_result = execute_command(command, timeout=timeout)
    execution_result["stdout"] = normalize_command_output(execution_result.get("stdout"))
    execution_result["stderr"] = normalize_command_output(execution_result.get("stderr"))
    add_execution(state, f"module:{module_name}", execution_result)
    evaluation = evaluate_command_result(
        execution_result["command"],
        execution_result["returncode"],
        execution_result["stdout"],
        execution_result["stderr"],
    )
    return {**execution_result, "evaluation": evaluation}


def extract_http_title(text):
    match = re.search(r"<title[^>]*>(.*?)</title>", text or "", re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title or None


def summarize_text(text, limit=240):
    if not text:
        return ""
    cleaned = re.sub(r"\s+", " ", normalize_command_output(text)).strip()
    return cleaned[:limit]


def finalize_result(result):
    result.setdefault("fingerprints", [])
    if result["status"] == "skipped":
        result["priority"] = "unknown"
    elif result["status"] == "failed":
        result["priority"] = "unknown"
    elif result["findings"] or result["artifacts"]:
        result["status"] = "completed"
        result["priority"] = "promising"
    else:
        result["status"] = "dead_end"
        result["priority"] = "dead_end"
    return result
