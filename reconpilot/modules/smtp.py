import re

from reconpilot.modules.common import add_fingerprint, build_module_result, finalize_result, merge_inventory_observation, publish_service_inventory, run_batch_step, summarize_text
from reconpilot.state import add_finding


def _extract_smtp_observation(text):
    match = re.search(r"\b(Postfix|Exim|Microsoft ESMTP|OpenSMTPD)(?:[\s/-]+([0-9][A-Za-z0-9.\-]*))?", text or "", re.IGNORECASE)
    if not match:
        return None
    return {
        "product": match.group(1),
        "version": match.group(2) or None,
        "extra_info": None,
        "source": "banner:smtp",
        "confidence": "high" if match.group(2) else "medium",
        "raw_evidence": summarize_text(match.group(0), limit=120),
    }


def run_smtp_module(state, service_target):
    result = build_module_result(service_target)
    target = service_target["target"]
    port = str(service_target["port"])

    probe = run_batch_step(
        state,
        module_name="smtp",
        command=["curl", "-v", "--max-time", "8", f"smtp://{target}:{port}"],
        timeout=10,
    )
    text = summarize_text(f"{probe.get('stdout', '')}\n{probe.get('stderr', '')}", limit=400)
    if text:
        result["findings"].append({"type": "banner", "value": text})
        add_finding(state, {
            "title": "SMTP service exposed",
            "severity": "info",
            "affected": f"{target}:{port}",
            "evidence": text,
            "recommendation": "Review exposed SMTP banner, commands, and STARTTLS support.",
            "source": "smtp",
            "type": "banner",
        })
        observation = _extract_smtp_observation(text)
        if observation:
            add_fingerprint(result, **observation)
            merge_inventory_observation(result, **observation)

    publish_service_inventory(state, result, tags=["smtp", "service"])
    return finalize_result(result)
