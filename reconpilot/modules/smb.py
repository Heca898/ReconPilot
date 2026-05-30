import re

from reconpilot.modules.common import (
    add_fingerprint,
    append_service_artifact,
    build_module_result,
    finalize_result,
    merge_inventory_observation,
    publish_service_inventory,
    run_batch_step,
    summarize_text,
)
from reconpilot.state import add_finding


def _looks_like_share_output(text):
    lowered = text.lower()
    markers = [
        "sharename",
        "disk",
        "ipc$",
        "print$",
        "administrative",
        "comment",
    ]
    return any(marker in lowered for marker in markers)


def _extract_smb_observations(text):
    observations = []
    if not text:
        return observations

    patterns = [
        re.compile(r"\b(Samba)\s+([0-9][A-Za-z0-9.\-]*)", re.IGNORECASE),
        re.compile(r"\b(Windows Server)\s+([0-9][A-Za-z0-9.\-]*)", re.IGNORECASE),
        re.compile(r"\b(Windows)\s+([0-9][A-Za-z0-9.\-]*)", re.IGNORECASE),
    ]

    for pattern in patterns:
        for match in pattern.finditer(text):
            observations.append({
                "product": match.group(1),
                "version": match.group(2),
                "extra_info": None,
                "source": "probe:smbclient",
                "confidence": "high" if match.group(2) else "medium",
                "raw_evidence": match.group(0),
            })
    return observations


def run_smb_module(state, service_target):
    result = build_module_result(service_target)
    target = service_target["target"]
    port = str(service_target["port"])
    service_uri = f"//{target}"

    shares_result = run_batch_step(
        state,
        module_name="smb",
        command=["smbclient", "-N", "-L", service_uri, "-p", port],
        timeout=20,
    )
    shares_text = ((shares_result["stdout"] or "") + "\n" + (shares_result["stderr"] or "")).strip()
    for observation in _extract_smb_observations(shares_text):
        add_fingerprint(result, **observation)
        merge_inventory_observation(result, **observation)
    if shares_text and _looks_like_share_output(shares_text):
        excerpt = summarize_text(shares_text, limit=500)
        access_value = "anonymous_or_null_session_available"
        lowered = shares_text.lower()
        if "access denied" in lowered or "nt_status_logon_failure" in lowered:
            access_value = "access_denied"
        result["findings"].append({"type": "share_enum", "value": excerpt})
        result["findings"].append({"type": "access", "value": access_value})
        add_finding(state, {
            "title": "SMB share enumeration returned data",
            "severity": "info" if access_value == "access_denied" else "medium",
            "affected": service_uri,
            "evidence": excerpt,
            "recommendation": "Review SMB share exposure and signing settings manually.",
            "source": "smb",
            "type": "share_enum",
        })
        append_service_artifact(state, result, {
            "service": service_target["service"],
            "port": service_target["port"],
            "type": "smb_share_list",
            "source": service_uri,
            "retrieved": True,
            "content": excerpt,
        })
    elif shares_text:
        result["findings"].append({
            "type": "access",
            "value": "access_denied_or_no_share_data",
        })
        if shares_result["stderr"]:
            result["errors"].append(summarize_text(shares_result["stderr"]))
    elif shares_result["stderr"]:
        result["errors"].append(summarize_text(shares_result["stderr"]))

    if not shares_result["success"] and not result["findings"] and not result["artifacts"]:
        result["status"] = "failed"
        if not result["errors"]:
            result["errors"].append("no useful SMB data retrieved")
    publish_service_inventory(state, result, tags=["smb", "service"])
    return finalize_result(result)
