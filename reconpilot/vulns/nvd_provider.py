from __future__ import annotations

import json
import os
import re
import socket
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from reconpilot.vulns.providers import VulnerabilityMatch, VulnerabilityProviderResult, VulnerabilityQuery
from reconpilot.vulns.normalization import build_nvd_aliases, normalize_product_name, normalize_vendor_name, normalize_version


class NVDHTTPError(Exception):
    def __init__(self, status_code: int, message: str | None = None):
        self.status_code = status_code
        self.message = message or f"http {status_code}"
        super().__init__(self.message)


class NVDHTTPClient:
    def get_json(self, url: str, headers: dict[str, str] | None = None, timeout: float = 5.0) -> dict[str, Any]:
        request = Request(url, headers=headers or {})
        try:
            with urlopen(request, timeout=timeout) as response:
                payload = response.read().decode("utf-8")
        except HTTPError as exc:
            raise NVDHTTPError(exc.code, str(exc)) from exc
        except URLError as exc:
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, socket.timeout):
                raise TimeoutError("request timed out") from exc
            raise OSError(str(reason)) from exc
        except socket.timeout as exc:
            raise TimeoutError("request timed out") from exc

        try:
            return json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid json response") from exc


class NVDProvider:
    name = "nvd"
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    cpe_base_url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    cpematch_base_url = "https://services.nvd.nist.gov/rest/json/cpematch/2.0"
    generic_service_names = {
        "http",
        "https",
        "http-alt",
        "http-proxy",
        "https-alt",
        "ssl/http",
        "unknown",
        "tcpwrapped",
    }
    generic_detection_sources = {"nmap_port_label"}

    def __init__(
        self,
        client: NVDHTTPClient | None = None,
        timeout: float = 8.0,
        max_results: int = 5,
        min_delay_seconds: float = 0.6,
        api_key: str | None = None,
        sleep_func=None,
        time_func=None,
        debug: bool = False,
    ):
        self.client = client or NVDHTTPClient()
        self.timeout = timeout
        self.max_results = max_results
        self.min_delay_seconds = min_delay_seconds
        self.api_key = api_key if api_key is not None else os.getenv("RECONPILOT_NVD_API_KEY")
        self.sleep_func = sleep_func or time.sleep
        self.time_func = time_func or time.monotonic
        self._last_request_at: float | None = None
        self.debug = debug

    def _debug(self, message: str):
        if self.debug:
            print(f"[VULN][NVD] {message}")

    def _normalize_term(self, value: str | None) -> str | None:
        cleaned = " ".join(str(value or "").split()).strip()
        if not cleaned:
            return None
        return cleaned[:120]

    def _has_precise_cpe(self, value: str | None) -> bool:
        normalized = self._normalize_term(value)
        if not normalized:
            return False
        lowered = normalized.lower()
        if not lowered.startswith("cpe:2.3:"):
            return False
        parts = normalized.split(":")
        if len(parts) < 6:
            return False
        version = parts[5].strip()
        return bool(version and version not in {"*", "-"})

    def _generic_or_weak_reason(self, query: VulnerabilityQuery) -> str | None:
        product = self._normalize_term(query.product)
        service_name = self._normalize_term(query.service_name)
        source = str(query.source or "").strip().lower()
        cpe = self._normalize_term(query.cpe)
        version = self._normalize_term(query.version)

        if cpe and self._has_precise_cpe(cpe):
            return None
        if cpe and not self._has_precise_cpe(cpe):
            return "insufficient product/version evidence"
        if not product and service_name and service_name.lower() in self.generic_service_names:
            return "weak or generic software identity"
        if product and product.lower() in self.generic_service_names:
            return "weak or generic software identity"
        if product and not version:
            return "insufficient product/version evidence"
        if source in self.generic_detection_sources and not product:
            return "weak or generic software identity"
        return None

    def _headers(self) -> dict[str, str]:
        headers = {"User-Agent": "ReconPilot/1.0.0"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def _apply_rate_limit_delay(self):
        if self._last_request_at is None:
            return
        elapsed = self.time_func() - self._last_request_at
        if elapsed < self.min_delay_seconds:
            self.sleep_func(self.min_delay_seconds - elapsed)

    def _build_url(self, search_term: str, matched_by: str = "keyword") -> str:
        params = {"resultsPerPage": self.max_results}
        if matched_by == "cpe":
            params["cpeName"] = search_term
        else:
            params["keywordSearch"] = search_term
        params = urlencode(params)
        return f"{self.base_url}?{params}"

    def _build_cpe_url(self, search_term: str) -> str:
        params = urlencode({"resultsPerPage": self.max_results, "keywordSearch": search_term})
        return f"{self.cpe_base_url}?{params}"

    def _build_cpematch_url(self, match_string: str) -> str:
        params = urlencode({"resultsPerPage": self.max_results, "matchStringSearch": match_string})
        return f"{self.cpematch_base_url}?{params}"

    def _build_virtual_match_url(self, match_string: str) -> str:
        params = urlencode({"resultsPerPage": self.max_results, "virtualMatchString": match_string})
        return f"{self.base_url}?{params}"

    def _query_identity(self, query: VulnerabilityQuery) -> dict[str, Any]:
        normalized_product = normalize_product_name(query.product)
        normalized_version = normalize_version(query.version)
        aliases = build_nvd_aliases(query.product)
        products = aliases.get("product_aliases", []) or ([] if not normalized_product else [normalized_product])
        if normalized_product and normalized_product not in products:
            products.insert(0, normalized_product)
        vendors = aliases.get("vendor_aliases", [])
        return {
            "product": normalized_product,
            "version": normalized_version,
            "products": products,
            "vendors": vendors,
        }

    def build_search_plan(self, query: VulnerabilityQuery) -> list[dict[str, Any]]:
        if self._generic_or_weak_reason(query):
            return []

        identity = self._query_identity(query)
        cpe = self._normalize_term(query.cpe)
        version = identity["version"]
        products = identity["products"]
        vendors = identity["vendors"]
        plan = []
        if cpe:
            plan.append({"mode": "cpe", "term": cpe, "url": self._build_url(cpe, matched_by="cpe"), "matched_by": "cpe"})
        if products and version:
            plan.append({
                "mode": "keyword_product_version",
                "term": f"{products[0]} {version}",
                "url": self._build_url(f"{products[0]} {version}", matched_by="keyword"),
                "matched_by": "keyword",
            })
            for vendor in vendors[:2]:
                term = f"{vendor} {products[0]} {version}"
                plan.append({
                    "mode": "alias_keyword",
                    "term": term,
                    "url": self._build_url(term, matched_by="keyword"),
                    "matched_by": "alias_keyword",
                })
            for product_alias in products[1:2]:
                term = f"{product_alias} {version}"
                plan.append({
                    "mode": "alias_keyword",
                    "term": term,
                    "url": self._build_url(term, matched_by="keyword"),
                    "matched_by": "alias_keyword",
                })
                plan.append({
                    "mode": "cpe_lookup",
                    "term": term,
                    "url": self._build_cpe_url(term),
                    "matched_by": "cpe_lookup",
                })
            cpe_vendors = sorted(vendors, key=lambda item: (item != "ui", item))[:1] or ["*"]
            for vendor in cpe_vendors:
                virtual_matches = []
                cpematch_matches = []
                virtual_products = list(products[2:3])
                virtual_products.extend(products[:1])
                for product_alias in virtual_products:
                    cpe_alias = product_alias.replace(" ", "_")
                    virtual_match = f"cpe:2.3:a:{vendor}:{cpe_alias}:*"
                    virtual_matches.append({
                        "mode": "virtual_cpe",
                        "term": virtual_match,
                        "url": self._build_virtual_match_url(virtual_match),
                        "matched_by": "virtual_cpe",
                    })
                    cpematch_matches.append({
                        "mode": "cpematch_lookup",
                        "term": virtual_match,
                        "url": self._build_cpematch_url(virtual_match),
                        "matched_by": "cpematch_lookup",
                    })
                plan.extend(virtual_matches)
                plan.extend(cpematch_matches)
            plan.append({
                "mode": "cpe_lookup",
                "term": f"{products[0]} {version}",
                "url": self._build_cpe_url(f"{products[0]} {version}"),
                "matched_by": "cpe_lookup",
            })

        deduped = []
        seen = set()
        for item in plan:
            signature = (item["mode"], " ".join(str(item["term"]).split()).lower())
            if not signature[1] or signature in seen:
                continue
            seen.add(signature)
            deduped.append(item)
        return deduped[:12]

    def _extract_description(self, cve: dict[str, Any]) -> str | None:
        for item in cve.get("descriptions", []):
            if item.get("lang") == "en" and item.get("value"):
                return item["value"]
        return None

    def _extract_metric(self, metrics: dict[str, Any]) -> tuple[str | None, float | None]:
        metric_priority = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
        for key in metric_priority:
            metric_list = metrics.get(key) or []
            if not metric_list:
                continue
            data = metric_list[0]
            if key in {"cvssMetricV31", "cvssMetricV30"}:
                cvss_data = data.get("cvssData") or {}
                severity = str(cvss_data.get("baseSeverity") or "").lower() or None
                score = cvss_data.get("baseScore")
            else:
                severity = str(data.get("baseSeverity") or "").lower() or None
                score = (data.get("cvssData") or {}).get("baseScore")
            try:
                normalized_score = float(score) if score is not None else None
            except (TypeError, ValueError):
                normalized_score = None
            return severity, normalized_score
        return None, None

    def _extract_references(self, cve: dict[str, Any]) -> list[str]:
        references = []
        for item in cve.get("references", [])[:5]:
            url = item.get("url")
            if url and url not in references:
                references.append(url)
        return references

    def _extract_affected_hint(self, cve: dict[str, Any]) -> str | None:
        criteria = self._extract_configuration_cpes(cve)
        if not criteria:
            return None
        return "; ".join(criteria[:2])[:240]

    def _extract_configuration_cpes(self, cve: dict[str, Any]) -> list[str]:
        return [item["criteria"] for item in self._extract_configuration_entries(cve) if item.get("criteria")]

    def _parse_cpe_criteria(self, criteria: str) -> dict[str, str | None]:
        parts = str(criteria or "").split(":")
        if len(parts) < 6:
            return {"vendor": None, "product": None, "version": None}
        return {
            "vendor": normalize_vendor_name(parts[3]),
            "product": normalize_product_name(parts[4]),
            "version": normalize_version(parts[5]),
        }

    def _version_key(self, version: str | None) -> list[tuple[int, str | int]]:
        normalized = normalize_version(version)
        if not normalized:
            return []
        parts = []
        for token in [item for item in re.split(r"[.\-+_]", normalized) if item]:
            if token.isdigit():
                parts.append((0, int(token)))
            else:
                parts.append((1, token.lower()))
        return parts

    def _compare_versions(self, left: str | None, right: str | None) -> int | None:
        left_key = self._version_key(left)
        right_key = self._version_key(right)
        if not left_key or not right_key:
            return None
        max_len = max(len(left_key), len(right_key))
        for index in range(max_len):
            left_part = left_key[index] if index < len(left_key) else (0, 0)
            right_part = right_key[index] if index < len(right_key) else (0, 0)
            if left_part == right_part:
                continue
            return -1 if left_part < right_part else 1
        return 0

    def version_in_nvd_range(
        self,
        detected_version: str | None,
        criteria_version: str | None,
        start_including: str | None,
        start_excluding: str | None,
        end_including: str | None,
        end_excluding: str | None,
    ) -> tuple[bool, str]:
        normalized_detected = normalize_version(detected_version)
        normalized_criteria = normalize_version(criteria_version)
        if not normalized_detected:
            return False, "detected version missing"
        if normalized_criteria and normalized_criteria not in {"*", "-"}:
            comparison = self._compare_versions(normalized_detected, normalized_criteria)
            if comparison is None:
                return False, "unsafe exact version comparison"
            return comparison == 0, f"exact criteria version comparison detected={normalized_detected} criteria={normalized_criteria}"

        if start_including:
            comparison = self._compare_versions(normalized_detected, start_including)
            if comparison is None or comparison < 0:
                return False, f"detected={normalized_detected} < versionStartIncluding={start_including}"
        if start_excluding:
            comparison = self._compare_versions(normalized_detected, start_excluding)
            if comparison is None or comparison <= 0:
                return False, f"detected={normalized_detected} <= versionStartExcluding={start_excluding}"
        if end_including:
            comparison = self._compare_versions(normalized_detected, end_including)
            if comparison is None or comparison > 0:
                return False, f"detected={normalized_detected} > versionEndIncluding={end_including}"
        if end_excluding:
            comparison = self._compare_versions(normalized_detected, end_excluding)
            if comparison is None or comparison >= 0:
                return False, f"detected={normalized_detected} >= versionEndExcluding={end_excluding}"
        return True, "version range matched"

    def _extract_configuration_entries(self, cve: dict[str, Any]) -> list[dict[str, Any]]:
        configurations = cve.get("configurations") or []
        entries = []

        def walk_nodes(nodes):
            for node in nodes or []:
                for cpe_match in node.get("cpeMatch", []) or []:
                    entries.append({
                        "criteria": cpe_match.get("criteria"),
                        "versionStartIncluding": cpe_match.get("versionStartIncluding"),
                        "versionStartExcluding": cpe_match.get("versionStartExcluding"),
                        "versionEndIncluding": cpe_match.get("versionEndIncluding"),
                        "versionEndExcluding": cpe_match.get("versionEndExcluding"),
                        "matches": list(cpe_match.get("matches") or []),
                    })
                walk_nodes(node.get("children", []) or [])

        for config in configurations:
            walk_nodes(config.get("nodes", []) or [])
        return entries

    def _configuration_match(
        self, query: VulnerabilityQuery, cve: dict[str, Any]
    ) -> tuple[bool, str | None, str | None, str | None]:
        identity = self._query_identity(query)
        wanted_products = set(identity["products"])
        wanted_vendors = set(identity["vendors"])
        wanted_version = identity["version"]

        for entry in self._extract_configuration_entries(cve):
            criteria = entry.get("criteria")
            parsed = self._parse_cpe_criteria(criteria or "")
            if parsed["product"] not in wanted_products:
                continue
            if wanted_vendors and parsed["vendor"] and parsed["vendor"] not in wanted_vendors:
                continue
            matched, reason = self.version_in_nvd_range(
                wanted_version,
                parsed["version"],
                entry.get("versionStartIncluding"),
                entry.get("versionStartExcluding"),
                entry.get("versionEndIncluding"),
                entry.get("versionEndExcluding"),
            )
            if matched:
                if any(entry.get(key) for key in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding")):
                    return True, criteria, "cpe_range_configuration", f"matched range: product={parsed['product']} {reason}"
                return True, criteria, "cpe_configuration", f"matched exact: product={parsed['product']} {reason}"
            self._debug(f"rejected range: product={parsed['product']} {reason}")
        return False, None, None, "no configuration criteria matched"

    def _extract_cpematch_criteria(self, response: dict[str, Any]) -> list[str]:
        match_strings = response.get("matchStrings")
        if not isinstance(match_strings, list):
            return []
        discovered = []
        for item in match_strings[: self.max_results * 2]:
            match_string = item.get("matchString") or {}
            criteria = match_string.get("criteria")
            if criteria and criteria not in discovered:
                discovered.append(criteria)
        return discovered[: self.max_results]

    def _confidence_for_match(self, query: VulnerabilityQuery, matched_by: str, cve: dict[str, Any], affected_hint: str | None) -> str:
        version = self._normalize_term(query.version)
        if not version:
            return "low"

        haystacks = [self._extract_description(cve) or "", affected_hint or ""]
        if any(version.lower() in item.lower() for item in haystacks if item):
            return "high"
        if matched_by in {"product_version", "service_version", "keyword"}:
            return "medium"
        if matched_by == "alias_keyword":
            return "medium"
        if matched_by in {"cpe", "cpe_configuration", "cpe_range_configuration"}:
            return "high"
        return "low"

    def _parse_matches(self, query: VulnerabilityQuery, matched_by: str, response: dict[str, Any]) -> tuple[list[VulnerabilityMatch], str | None]:
        vulnerabilities = response.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            raise ValueError("invalid response shape")

        matches = []
        rejection_reason = "no matches accepted"
        for item in vulnerabilities[:self.max_results]:
            cve = item.get("cve") or {}
            cve_id = cve.get("id")
            if not cve_id:
                continue
            description = self._extract_description(cve)
            severity, cvss_score = self._extract_metric(cve.get("metrics") or {})
            affected_hint = self._extract_affected_hint(cve)
            config_matched, matched_criteria, config_match_type, config_reason = self._configuration_match(query, cve)
            effective_match = config_match_type if config_matched else matched_by
            if config_reason and config_matched:
                self._debug(config_reason)
            if matched_by in {"cpe", "virtual_cpe"} and not config_matched:
                rejection_reason = "cpe results did not contain matching affected configuration"
                if config_reason:
                    self._debug(config_reason)
                continue
            if matched_by in {"keyword", "alias_keyword"} and not config_matched:
                identity = self._query_identity(query)
                haystack = f"{description or ''} {affected_hint or ''}".lower()
                if not any(product in haystack for product in identity["products"]):
                    rejection_reason = "keyword results did not reference product"
                    continue
                if identity["version"] and identity["version"].lower() not in haystack:
                    rejection_reason = "keyword results did not reference product/version evidence"
                    continue
            matches.append(
                VulnerabilityMatch(
                    provider=self.name,
                    vuln_id=cve_id,
                    title=description,
                    description=description,
                    severity=severity,
                    cvss_score=cvss_score,
                    published=cve.get("published"),
                    last_modified=cve.get("lastModified"),
                    references=self._extract_references(cve),
                    affected_hint=matched_criteria or affected_hint,
                    confidence=self._confidence_for_match(query, effective_match, cve, matched_criteria or affected_hint),
                    matched_by=effective_match,
                    raw={"cve_id": cve_id},
                )
            )
        return matches, rejection_reason

    def _discover_cpe_candidates(self, query: VulnerabilityQuery, response: dict[str, Any]) -> list[str]:
        products = response.get("products")
        if not isinstance(products, list):
            return []
        identity = self._query_identity(query)
        candidates = []
        for item in products[: self.max_results * 2]:
            cpe = (item.get("cpe") or {})
            criteria = cpe.get("cpeName") or cpe.get("criteria")
            if not criteria:
                continue
            parsed = self._parse_cpe_criteria(criteria)
            if parsed["product"] not in set(identity["products"]):
                continue
            if identity["version"] and parsed["version"] not in {identity["version"], "*", "-"}:
                continue
            if criteria not in candidates:
                candidates.append(criteria)
        return candidates[:3]

    def search(self, query: VulnerabilityQuery) -> VulnerabilityProviderResult:
        started_at = self.time_func()
        skip_reason = self._generic_or_weak_reason(query)
        search_plan = self.build_search_plan(query)
        self._debug(
            f"query product={json.dumps(query.product)} version={json.dumps(query.version)} cpe={json.dumps(query.cpe)}"
        )
        if not search_plan:
            return VulnerabilityProviderResult(
                provider=self.name,
                query=query,
                status="skipped",
                error=skip_reason or "no suitable NVD query could be built",
                elapsed_seconds=self.time_func() - started_at,
            )

        all_matches = []
        seen_ids = set()
        last_error = None
        raw_count = 0
        had_successful_response = False
        successful_empty_response = False

        for step in search_plan:
            self._apply_rate_limit_delay()
            url = step["url"]
            matched_by = step["matched_by"]
            self._debug(f"mode={step['mode']} url={url}")
            try:
                response = self.client.get_json(url, headers=self._headers(), timeout=self.timeout)
                self._last_request_at = self.time_func()
                had_successful_response = True
                http_status = 200
            except TimeoutError:
                if had_successful_response:
                    last_error = "request timed out"
                    break
                return VulnerabilityProviderResult(
                    provider=self.name,
                    query=query,
                    status="timeout",
                    error="request timed out",
                    elapsed_seconds=self.time_func() - started_at,
                )
            except NVDHTTPError as exc:
                status = "failed"
                if exc.status_code == 429:
                    status = "rate_limited"
                elif exc.status_code in {403, 404} or exc.status_code >= 500:
                    status = "failed"
                self._debug(f"mode={step['mode']} http_status={exc.status_code}")
                if had_successful_response:
                    last_error = f"http {exc.status_code}"
                    break
                return VulnerabilityProviderResult(
                    provider=self.name,
                    query=query,
                    status=status,
                    error=f"http {exc.status_code}",
                    elapsed_seconds=self.time_func() - started_at,
                )
            except OSError as exc:
                self._debug(f"mode={step['mode']} error={' '.join(str(exc).split())[:200]}")
                if had_successful_response:
                    last_error = " ".join(str(exc).split())[:200]
                    break
                return VulnerabilityProviderResult(
                    provider=self.name,
                    query=query,
                    status="failed",
                    error=" ".join(str(exc).split())[:200],
                    elapsed_seconds=self.time_func() - started_at,
                )
            except ValueError as exc:
                self._debug(f"mode={step['mode']} error={str(exc)}")
                if had_successful_response:
                    last_error = str(exc)
                    break
                return VulnerabilityProviderResult(
                    provider=self.name,
                    query=query,
                    status="failed",
                    error=str(exc),
                    elapsed_seconds=self.time_func() - started_at,
                )

            total_results = response.get("totalResults")
            self._debug(f"mode={step['mode']} http_status={http_status} totalResults={total_results}")

            if step["mode"] == "cpematch_lookup":
                discovered_criteria = self._extract_cpematch_criteria(response)
                self._debug(f"mode={step['mode']} discovered_match_criteria={json.dumps(discovered_criteria)}")
                if not discovered_criteria:
                    self._debug(f"mode={step['mode']} no_matches_reason=no match criteria discovered")
                continue

            if step["mode"] == "cpe_lookup":
                try:
                    cpe_candidates = self._discover_cpe_candidates(query, response)
                except ValueError as exc:
                    last_error = str(exc)
                    break
                self._debug(f"mode={step['mode']} discovered_cpes={len(cpe_candidates)}")
                if not cpe_candidates:
                    self._debug(f"mode={step['mode']} no_matches_reason=no cpe candidates discovered")
                    continue
                for cpe_candidate in cpe_candidates:
                    cpe_url = self._build_url(cpe_candidate, matched_by="cpe")
                    self._debug(f"mode=cpe url={cpe_url}")
                    self._apply_rate_limit_delay()
                    try:
                        cpe_response = self.client.get_json(cpe_url, headers=self._headers(), timeout=self.timeout)
                        self._last_request_at = self.time_func()
                        cpe_total_results = cpe_response.get("totalResults")
                        self._debug(f"mode=cpe http_status=200 totalResults={cpe_total_results}")
                    except TimeoutError:
                        if had_successful_response:
                            last_error = "request timed out"
                            break
                        return VulnerabilityProviderResult(
                            provider=self.name,
                            query=query,
                            status="timeout",
                            error="request timed out",
                            elapsed_seconds=self.time_func() - started_at,
                        )
                    except NVDHTTPError as exc:
                        status = "rate_limited" if exc.status_code == 429 else "failed"
                        if had_successful_response:
                            last_error = f"http {exc.status_code}"
                            break
                        return VulnerabilityProviderResult(
                            provider=self.name,
                            query=query,
                            status=status,
                            error=f"http {exc.status_code}",
                            elapsed_seconds=self.time_func() - started_at,
                        )
                    except OSError as exc:
                        if had_successful_response:
                            last_error = " ".join(str(exc).split())[:200]
                            break
                        return VulnerabilityProviderResult(
                            provider=self.name,
                            query=query,
                            status="failed",
                            error=" ".join(str(exc).split())[:200],
                            elapsed_seconds=self.time_func() - started_at,
                        )
                    except ValueError as exc:
                        if had_successful_response:
                            last_error = str(exc)
                            break
                        return VulnerabilityProviderResult(
                            provider=self.name,
                            query=query,
                            status="failed",
                            error=str(exc),
                            elapsed_seconds=self.time_func() - started_at,
                        )
                    vulnerabilities = cpe_response.get("vulnerabilities")
                    if isinstance(vulnerabilities, list):
                        raw_count += len(vulnerabilities)
                        if not vulnerabilities:
                            successful_empty_response = True
                    parsed_matches, rejection_reason = self._parse_matches(query, "cpe", cpe_response)
                    self._debug(f"mode=cpe parsed_vulnerabilities={len(parsed_matches)}")
                    if not parsed_matches:
                        self._debug(f"mode=cpe no_matches_reason={rejection_reason}")
                    for match in parsed_matches:
                        if match.vuln_id in seen_ids:
                            continue
                        seen_ids.add(match.vuln_id)
                        all_matches.append(match)
                    if last_error:
                        break
                if last_error:
                    break
                continue

            vulnerabilities = response.get("vulnerabilities")
            if isinstance(vulnerabilities, list):
                raw_count += len(vulnerabilities)
                if not vulnerabilities:
                    successful_empty_response = True

            try:
                parsed_matches, rejection_reason = self._parse_matches(query, matched_by, response)
            except ValueError as exc:
                last_error = str(exc)
                break
            self._debug(f"mode={step['mode']} parsed_vulnerabilities={len(parsed_matches)}")
            if not parsed_matches:
                self._debug(f"mode={step['mode']} no_matches_reason={rejection_reason}")

            for match in parsed_matches:
                if match.vuln_id in seen_ids:
                    continue
                seen_ids.add(match.vuln_id)
                all_matches.append(match)

        status = "completed" if all_matches else "empty"
        if last_error and had_successful_response:
            status = "partial" if all_matches or successful_empty_response else "failed"
        elif last_error:
            status = "failed"

        return VulnerabilityProviderResult(
            provider=self.name,
            query=query,
            status=status,
            matches=all_matches,
            error=last_error,
            raw_count=raw_count,
            elapsed_seconds=self.time_func() - started_at,
        )
