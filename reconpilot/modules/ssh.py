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


def _extract_ssh_banner_observations(text, source):
    observations = []
    if not text:
        return observations

    patterns = [
        re.compile(r"\b(OpenSSH)(?:[_\s/-]+([0-9][A-Za-z0-9.\-]*))?", re.IGNORECASE),
        re.compile(r"\b(dropbear)(?:[_\s/-]+([0-9][A-Za-z0-9.\-]*))?", re.IGNORECASE),
    ]

    for pattern in patterns:
        for match in pattern.finditer(text):
            observations.append({
                "product": match.group(1),
                "version": match.group(2) or None,
                "extra_info": None,
                "source": source,
                "confidence": "high" if match.group(2) else "medium",
                "raw_evidence": match.group(0),
            })
    return observations


def run_ssh_module(state, service_target):
    result = build_module_result(service_target)
    target = service_target["target"]
    port = str(service_target["port"])

    keyscan_result = run_batch_step(
        state,
        module_name="ssh",
        command=["ssh-keyscan", "-T", "5", "-p", port, target],
        timeout=8,
    )
    if keyscan_result["stdout"].strip():
        excerpt = summarize_text(keyscan_result["stdout"], limit=500)
        result["findings"].append({"type": "host_key", "value": excerpt})
        add_finding(state, {
            "title": "SSH host key collected",
            "severity": "info",
            "affected": f"{target}:{port}",
            "evidence": excerpt,
            "recommendation": "Review the SSH banner and key material manually.",
            "source": "ssh",
            "type": "banner",
        })
        append_service_artifact(state, result, {
            "service": service_target["service"],
            "port": service_target["port"],
            "type": "ssh_host_key",
            "source": f"{target}:{port}",
            "retrieved": True,
            "content": excerpt,
        })
        for observation in _extract_ssh_banner_observations(keyscan_result["stdout"], "banner:ssh"):
            add_fingerprint(result, **observation)
            merge_inventory_observation(result, **observation)
    elif keyscan_result["stderr"]:
        result["errors"].append(summarize_text(keyscan_result["stderr"]))

    auth_probe_result = run_batch_step(
        state,
        module_name="ssh",
        command=[
            "ssh",
            "-o",
            "PreferredAuthentications=none",
            "-o",
            "NumberOfPasswordPrompts=0",
            "-o",
            "ConnectTimeout=3",
            "-o",
            "ConnectionAttempts=1",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-p",
            port,
            target,
            "exit",
        ],
        timeout=5,
    )
    auth_text = ((auth_probe_result["stdout"] or "") + "\n" + (auth_probe_result["stderr"] or "")).strip()
    if auth_text:
        result["findings"].append({
            "type": "auth_behavior",
            "value": summarize_text(auth_text, limit=300),
        })
        add_finding(state, {
            "title": "SSH authentication behavior observed",
            "severity": "info",
            "affected": f"{target}:{port}",
            "evidence": summarize_text(auth_text, limit=300),
            "recommendation": "Review allowed SSH authentication mechanisms manually.",
            "source": "ssh",
            "type": "auth_behavior",
        })
        for observation in _extract_ssh_banner_observations(auth_text, "banner:ssh"):
            add_fingerprint(result, **observation)
            merge_inventory_observation(result, **observation)
    if auth_probe_result["stderr"] and not auth_text:
        result["errors"].append(summarize_text(auth_probe_result["stderr"]))

    if (
        not keyscan_result["success"]
        and not auth_probe_result["success"]
        and not result["findings"]
        and not result["artifacts"]
    ):
        result["status"] = "failed"
        if not result["errors"]:
            result["errors"].append("no useful SSH data retrieved")
    publish_service_inventory(state, result, tags=["ssh", "service"])
    return finalize_result(result)
