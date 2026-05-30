from reconpilot.modules.common import build_module_result, finalize_result, publish_service_inventory
from reconpilot.state import add_finding


def run_generic_service_module(state, service_target):
    result = build_module_result(service_target)
    inventory = result.get("inventory") or {}
    if inventory.get("product") or inventory.get("version"):
        add_finding(state, {
            "title": "Exposed network service detected",
            "severity": "info",
            "affected": f"{service_target['target']}:{service_target['port']}",
            "evidence": {
                "service": service_target.get("service"),
                "product": inventory.get("product"),
                "version": inventory.get("version"),
            },
            "recommendation": "Review whether this service should be publicly reachable.",
            "source": "generic_service",
            "type": "exposed_service",
        })
        result["findings"].append({"type": "service_detected", "value": inventory})
    publish_service_inventory(state, result, tags=["service"])
    return finalize_result(result)
