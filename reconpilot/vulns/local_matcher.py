from reconpilot.vulns.normalization import build_software_identity
from reconpilot.vulns.providers import LocalRulesProvider, VulnerabilityQuery


def match_vulnerabilities(inventory_entry, providers=None, debug=False):
    if providers is None:
        providers = [LocalRulesProvider()]
    software_identity = build_software_identity(inventory_entry)
    if not software_identity:
        if debug:
            print(f"[VULN] skipped inventory product={inventory_entry.get('product')} version={inventory_entry.get('version')} reason=no software identity")
        return []
    if debug:
        print(
            f"[VULN] provider_count={len(providers)} product={software_identity.get('display_product')} "
            f"version={software_identity.get('version')}"
        )
    matches = []
    seen = set()
    for provider in providers:
        try:
            result = provider.search(VulnerabilityQuery(
                product=software_identity.get("display_product") or software_identity.get("product"),
                version=software_identity.get("version"),
                cpe=software_identity.get("cpe"),
                confidence=software_identity.get("confidence"),
                source=software_identity.get("source"),
                raw_banner=str(software_identity.get("raw_evidence")),
            ))
            provider_matches = []
            for item in result.matches:
                provider_matches.append({
                    "id": item.vuln_id,
                    "source": item.provider,
                    "severity": item.severity or "unknown",
                    "title": item.title or item.description or "No description available.",
                    "matched_product": software_identity.get("display_product") or software_identity.get("product"),
                    "matched_version": software_identity.get("version"),
                    "confidence": "test" if item.provider == "local_rules" else "external",
                    "url": None,
                    "notes": f"Matched via {item.provider}.",
                })
        except Exception:
            if debug:
                print(f"[VULN] provider={getattr(provider, 'name', 'unknown')} error=provider failure")
            continue
        for match in provider_matches or []:
            signature = (match.get("id"), match.get("source"))
            if signature in seen:
                continue
            seen.add(signature)
            matches.append(match)
    return matches
