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


def _extract_ftp_banner_observation(text):
    if not text:
        return None

    for line in text.splitlines():
        candidate = line.strip()
        if not candidate.startswith("220"):
            continue

        match = re.search(r"\b(vsftpd|ProFTPD|Pure-FTPd)(?:[\s/_-]+([0-9][A-Za-z0-9.\-]*))?", candidate, re.IGNORECASE)
        if not match:
            continue

        return {
            "product": match.group(1),
            "version": match.group(2) or None,
            "extra_info": None,
            "source": "banner:ftp",
            "confidence": "high" if match.group(2) else "medium",
            "raw_evidence": candidate,
        }
    return None


def run_ftp_module(state, service_target):
    result = build_module_result(service_target)
    base_url = f"ftp://{service_target['target']}:{service_target['port']}/"

    banner_result = run_batch_step(
        state,
        module_name="ftp",
        command=["curl", "-v", "--max-time", "10", base_url],
        timeout=15,
    )
    banner_text = ((banner_result["stdout"] or "") + "\n" + (banner_result["stderr"] or "")).strip()
    if banner_text:
        result["findings"].append({
            "type": "banner",
            "value": summarize_text(banner_text, limit=300),
        })
        add_finding(state, {
            "title": "FTP banner collected",
            "severity": "info",
            "affected": base_url,
            "evidence": summarize_text(banner_text, limit=300),
            "recommendation": "Review the exposed FTP service and banner manually.",
            "source": "ftp",
            "type": "banner",
        })
        banner_observation = _extract_ftp_banner_observation(banner_text)
        if banner_observation:
            add_fingerprint(result, **banner_observation)
            merge_inventory_observation(result, **banner_observation)

    anonymous_result = run_batch_step(
        state,
        module_name="ftp",
        command=["curl", "-sS", "--list-only", "--user", "anonymous:anonymous", "--max-time", "10", base_url],
        timeout=15,
    )
    listing = anonymous_result["stdout"].strip()
    if listing:
        result["findings"].append({"type": "anonymous_access", "value": "allowed"})
        excerpt = summarize_text(listing, limit=400)
        result["findings"].append({"type": "directory_listing", "value": excerpt})
        add_finding(state, {
            "title": "Anonymous FTP access allowed",
            "severity": "medium",
            "affected": base_url,
            "evidence": excerpt,
            "recommendation": "Disable anonymous FTP if it is not explicitly required.",
            "source": "ftp",
            "type": "anonymous_access",
        })
        append_service_artifact(state, result, {
            "service": service_target["service"],
            "port": service_target["port"],
            "type": "ftp_listing",
            "source": base_url,
            "retrieved": True,
            "content": excerpt,
        })
    else:
        result["findings"].append({"type": "anonymous_access", "value": "denied_or_unavailable"})
        if anonymous_result["stderr"]:
            result["errors"].append(summarize_text(anonymous_result["stderr"]))

    if (
        not banner_result["success"]
        and not anonymous_result["success"]
        and not result["findings"]
        and not result["artifacts"]
    ):
        result["status"] = "failed"
        if not result["errors"]:
            result["errors"].append("no useful FTP data retrieved")
    publish_service_inventory(state, result, tags=["ftp", "service"])
    return finalize_result(result)
