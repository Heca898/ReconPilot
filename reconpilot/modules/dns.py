from reconpilot.modules.common import build_module_result, finalize_result, publish_service_inventory, run_batch_step, summarize_text
from reconpilot.state import add_finding


def run_dns_module(state, service_target):
    result = build_module_result(service_target)
    target = service_target["target"]

    bind_result = run_batch_step(
        state,
        module_name="dns",
        command=["dig", "+short", f"@{target}", "version.bind", "txt", "chaos"],
        timeout=8,
    )
    bind_output = summarize_text(bind_result.get("stdout"), limit=240)
    if bind_output:
        result["findings"].append({"type": "version.bind", "value": bind_output})
        add_finding(state, {
            "title": "DNS version.bind disclosed",
            "severity": "info",
            "affected": f"{target}:53",
            "evidence": bind_output,
            "recommendation": "Review whether version disclosure should be disabled.",
            "source": "dns",
            "type": "version.bind",
        })

    hostname = state["prechecks"]["resolution"].get("hostname")
    if hostname:
        axfr_result = run_batch_step(
            state,
            module_name="dns",
            command=["dig", f"@{target}", hostname, "AXFR"],
            timeout=10,
        )
        axfr_output = summarize_text(axfr_result.get("stdout"), limit=400)
        if axfr_output and "Transfer failed." not in axfr_output:
            result["findings"].append({"type": "axfr", "value": axfr_output})
            add_finding(state, {
                "title": "DNS zone transfer may be exposed",
                "severity": "medium",
                "affected": f"{target}:53",
                "evidence": axfr_output,
                "recommendation": "Restrict zone transfers to authorized secondaries only.",
                "source": "dns",
                "type": "axfr",
            })

    publish_service_inventory(state, result, tags=["dns", "service"])
    return finalize_result(result)
