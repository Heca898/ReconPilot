from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


VULNERABILITY_PROVIDER_STATUSES = {
    "completed",
    "empty",
    "failed",
    "partial",
    "skipped",
    "rate_limited",
    "timeout",
}

VULNERABILITY_CONFIDENCE_LEVELS = {"low", "medium", "high"}


@dataclass(frozen=True)
class VulnerabilityQuery:
    target: str | None = None
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    cpe: str | None = None
    confidence: str | None = None
    port: int | None = None
    protocol: str | None = None
    raw_banner: str | None = None
    source: str | None = None


@dataclass
class VulnerabilityMatch:
    provider: str
    vuln_id: str
    title: str | None = None
    description: str | None = None
    severity: str | None = None
    cvss_score: float | None = None
    published: str | None = None
    last_modified: str | None = None
    references: list[str] = field(default_factory=list)
    affected_hint: str | None = None
    confidence: str = "low"
    matched_by: str = "unknown"
    raw: dict[str, Any] | None = None


@dataclass
class VulnerabilityProviderResult:
    provider: str
    query: VulnerabilityQuery
    status: str
    matches: list[VulnerabilityMatch] = field(default_factory=list)
    error: str | None = None
    raw_count: int = 0
    elapsed_seconds: float | None = None


class VulnerabilityProvider(Protocol):
    name: str

    def search(self, query: VulnerabilityQuery) -> VulnerabilityProviderResult:
        ...


class LocalRulesProvider:
    name = "local_rules"

    RULES = {
        ("apache httpd", "2.4.57"): {
            "id": "LOCAL-TEST-APACHE-2457",
            "severity": "medium",
            "title": "Local test match for Apache httpd 2.4.57",
            "matched_product": "Apache httpd",
            "matched_version": "2.4.57",
        },
        ("openssh", "8.9p1"): {
            "id": "LOCAL-TEST-OPENSSH-89P1",
            "severity": "low",
            "title": "Local test match for OpenSSH 8.9p1",
            "matched_product": "OpenSSH",
            "matched_version": "8.9p1",
        },
        ("vsftpd", "3.0.3"): {
            "id": "LOCAL-TEST-VSFTPD-303",
            "severity": "medium",
            "title": "Local test match for vsftpd 3.0.3",
            "matched_product": "vsftpd",
            "matched_version": "3.0.3",
        },
    }

    def search(self, query: VulnerabilityQuery) -> VulnerabilityProviderResult:
        product = " ".join(str(query.product or "").split()).strip().lower()
        version = " ".join(str(query.version or "").split()).strip()
        if not product or not version:
            return VulnerabilityProviderResult(provider=self.name, query=query, status="skipped", error="insufficient product/version evidence")

        rule = self.RULES.get((product, version))
        if not rule:
            return VulnerabilityProviderResult(provider=self.name, query=query, status="empty")

        match = VulnerabilityMatch(
            provider=self.name,
            vuln_id=rule["id"],
            title=rule["title"],
            description=rule["title"],
            severity=rule["severity"],
            confidence="high",
            matched_by="product_version",
        )
        return VulnerabilityProviderResult(provider=self.name, query=query, status="completed", matches=[match], raw_count=1)
def get_local_vulnerability_providers(provider_name):
    if provider_name == "local":
        return [LocalRulesProvider()]
    return []


def get_api_vulnerability_provider(provider_name: str) -> VulnerabilityProvider | None:
    if provider_name == "nvd":
        from reconpilot.vulns.nvd_provider import NVDProvider

        return NVDProvider()
    return None
