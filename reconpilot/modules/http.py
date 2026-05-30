from __future__ import annotations

import html
import importlib
import json
import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse

from reconpilot.engine.executor import check_tool_available, normalize_command_output
from reconpilot.modules.common import (
    add_fingerprint,
    append_service_artifact,
    build_module_result,
    extract_http_title,
    finalize_result,
    merge_inventory_observation,
    publish_service_inventory,
    run_batch_step,
    summarize_text,
)
from reconpilot.session_store import ARTIFACTS_DIR
from reconpilot.state import add_finding, add_web_target, upsert_inventory_entry


INTERESTING_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/security.txt",
    "/.well-known/security.txt",
    "/server-status",
    "/.git/HEAD",
    "/.env",
    "/admin",
    "/login",
    "/api",
    "/api/v1",
    "/api/v2",
    "/swagger",
    "/swagger-ui",
    "/api-docs",
    "/openapi.json",
    "/graphql",
    "/phpinfo.php",
]
SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]
JS_KEYWORD_PATTERN = re.compile(r"(/(?:api|auth|login|logout|users|admin|graphql|swagger|openapi(?:\.json)?)[A-Za-z0-9_./-]*)", re.IGNORECASE)
MAX_JS_FETCHES = 8
MAX_JS_BYTES = 65536
MAX_TEXT_FINGERPRINT_BYTES = 32768
MAX_VISIBLE_TEXT_CHUNKS = 24
MAX_CONFIG_ENDPOINTS = 10
MAX_DEBUG_ARTIFACT_BYTES = 24000
MAX_RENDER_TEXT_BYTES = 32768
GENERIC_PRODUCT_VERSION_PATTERNS = [
    re.compile(r"\b([A-Z][A-Za-z0-9.+-]*(?:\s+[A-Z][A-Za-z0-9.+-]*){0,3})\s+v?(\d+\.\d+(?:\.\d+){0,3}(?:[A-Za-z0-9._-]+)?)\b"),
    re.compile(r"\b([A-Za-z][A-Za-z0-9.+-]*(?:\s+[A-Za-z][A-Za-z0-9.+-]*){0,2})/(\d+\.\d+(?:\.\d+){0,3}(?:[A-Za-z0-9._-]+)?)\b"),
]
SEMVER_PATTERN = re.compile(r"\b(?:v(?:ersion)?\s*)?([0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9._-]+)?)\b", re.IGNORECASE)
VERSION_CUE_PATTERN = re.compile(r"\b(version|build|release|appversion|productversion|app_version|product_version)\b", re.IGNORECASE)
JS_PRODUCT_KEY_PATTERN = re.compile(r'(?:"|\')?(appName|productName|displayName|title|brand|application)(?:"|\')?\s*[:=]\s*(?:"|\')([^"\']{2,80})(?:"|\')', re.IGNORECASE)
JS_VERSION_KEY_PATTERN = re.compile(r'(?:"|\')?(version|appVersion|productVersion|buildVersion|releaseVersion|build)(?:"|\')?\s*[:=]\s*(?:"|\')?([0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9._-]+)?)(?:"|\')?', re.IGNORECASE)
CONFIG_ENDPOINT_PATHS = [
    "/status",
    "/api/status",
    "/api/self",
    "/api/info",
    "/api/version",
    "/api/config",
    "/api/bootstrap",
    "/manage/api/status",
    "/manage/api/version",
    "/manage/api/bootstrap",
]
PRODUCT_STOPWORDS = {
    "access",
    "account",
    "admin",
    "api",
    "application",
    "build",
    "dashboard",
    "error",
    "language",
    "login",
    "logout",
    "manage",
    "release",
    "sign",
    "status",
    "swagger",
    "user",
    "username",
    "version",
    "welcome",
    "portal",
    "password",
    "forgot",
    "continue",
    "submit",
    "email",
}
PRODUCT_NORMALIZATION = {
    "apache": "Apache httpd",
    "apache http server": "Apache httpd",
    "apache httpd": "Apache httpd",
    "apache tomcat": "Apache Tomcat",
    "django": "Django",
    "express": "Express",
    "flask": "Flask",
    "grafana": "Grafana",
    "jenkins": "Jenkins",
    "laravel": "Laravel",
    "nginx": "nginx",
    "openresty": "OpenResty",
    "php": "PHP",
    "prestashop": "PrestaShop",
    "sonarqube": "SonarQube",
    "wordpress": "WordPress",
}
TITLE_HINT_SUFFIXES = [
    "login",
    "sign in",
    "dashboard",
    "portal",
]


class _DocumentParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.script_src = []
        self.stylesheets = []
        self.links = []
        self.meta_generator = None
        self.visible_text_chunks = []
        self._hidden_tag_depth = 0

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        lowered_tag = tag.lower()
        if lowered_tag in {"script", "style", "noscript", "title", "head"}:
            self._hidden_tag_depth += 1
        if lowered_tag == "form":
            self.forms.append({
                "action": attributes.get("action"),
                "method": (attributes.get("method") or "get").lower(),
            })
        elif lowered_tag == "script" and attributes.get("src"):
            self.script_src.append(attributes["src"])
        elif lowered_tag == "link":
            href = attributes.get("href")
            rel = " ".join(attributes.get("rel", []) if isinstance(attributes.get("rel"), list) else [attributes.get("rel", "")]).lower()
            if href:
                self.links.append(href)
                if "stylesheet" in rel:
                    self.stylesheets.append(href)
        elif lowered_tag == "a" and attributes.get("href"):
            self.links.append(attributes["href"])
        elif lowered_tag == "meta" and (attributes.get("name") or "").lower() == "generator":
            self.meta_generator = attributes.get("content")

    def handle_endtag(self, tag):
        if tag.lower() in {"script", "style", "noscript", "title", "head"} and self._hidden_tag_depth > 0:
            self._hidden_tag_depth -= 1

    def handle_data(self, data):
        if self._hidden_tag_depth > 0:
            return
        cleaned = " ".join(str(data or "").split()).strip()
        if not cleaned:
            return
        if len(self.visible_text_chunks) >= MAX_VISIBLE_TEXT_CHUNKS:
            return
        self.visible_text_chunks.append(cleaned[:160])


def _normalize_product_name(product):
    cleaned = " ".join(str(product or "").split()).strip()
    aliases = {
        "apache": "Apache httpd",
        "apache http server": "Apache httpd",
        "apache httpd": "Apache httpd",
    }
    return aliases.get(cleaned.lower(), cleaned or None)


def _split_headers_and_body(stdout):
    normalized = normalize_command_output(stdout)
    if "\r\n\r\n" in normalized:
        chunks = normalized.split("\r\n\r\n")
    else:
        chunks = normalized.split("\n\n")
    responses = []
    while len(chunks) >= 2:
        header_block = chunks.pop(0)
        body = ""
        if not chunks:
            responses.append((header_block, body))
            break
        if chunks[0].startswith("HTTP/"):
            responses.append((header_block, body))
            continue
        body = chunks.pop(0)
        responses.append((header_block, body))
    if not responses and normalized:
        return {"response_chain": [], "final_headers": "", "final_body": normalized}
    if responses:
        final_headers, final_body = responses[-1]
        return {"response_chain": responses, "final_headers": final_headers, "final_body": final_body}
    return {"response_chain": [], "final_headers": "", "final_body": ""}


def _header_map(headers_text):
    headers = {}
    current_name = None
    for line in headers_text.splitlines():
        if line.startswith("HTTP/"):
            continue
        if not line.strip():
            continue
        if line.startswith((" ", "\t")) and current_name:
            headers[current_name][-1] = f"{headers[current_name][-1]} {line.strip()}"
            continue
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        current_name = name.strip().lower()
        headers.setdefault(current_name, []).append(value.strip())
    return headers


def _extract_status_code(headers_text):
    for line in headers_text.splitlines():
        line = line.strip()
        if line.startswith("HTTP/"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1])
    return None


def _extract_server_header_observation(server_header):
    if not server_header:
        return None
    patterns = [
        re.compile(r"^\s*(nginx)(?:/([0-9][A-Za-z0-9.\-]*))?\b", re.IGNORECASE),
        re.compile(r"^\s*(Apache)(?:/([0-9][A-Za-z0-9.\-]*))?\b", re.IGNORECASE),
        re.compile(r"^\s*(Microsoft-IIS)(?:/([0-9][A-Za-z0-9.\-]*))?\b", re.IGNORECASE),
        re.compile(r"^\s*(Caddy)(?:/([0-9][A-Za-z0-9.\-]*))?\b", re.IGNORECASE),
        re.compile(r"^\s*(Apache Tomcat)(?:/([0-9][A-Za-z0-9.\-]*))?\b", re.IGNORECASE),
        re.compile(r"^\s*(Werkzeug)(?:/([0-9][A-Za-z0-9.\-]*))?\b", re.IGNORECASE),
        re.compile(r"^\s*(gunicorn)(?:/([0-9][A-Za-z0-9.\-]*))?\b", re.IGNORECASE),
    ]
    for pattern in patterns:
        match = pattern.search(server_header)
        if not match:
            continue
        product = _normalize_product_name(match.group(1))
        version = match.group(2) or None
        return {
            "product": product,
            "version": version,
            "extra_info": None,
            "source": "header:server",
            "confidence": "high" if version else "medium",
            "raw_evidence": f"Server: {server_header}",
        }
    return None


def _extract_x_powered_by_observation(value):
    if not value:
        return None
    patterns = [
        re.compile(r"^\s*(PHP)(?:/([0-9][A-Za-z0-9.\-]*))?\b", re.IGNORECASE),
        re.compile(r"^\s*(ASP\.NET)(?:\s+([0-9][A-Za-z0-9.\-]*))?\b", re.IGNORECASE),
        re.compile(r"^\s*(Express)\b", re.IGNORECASE),
        re.compile(r"^\s*(Next\.js)(?:\s+([0-9][A-Za-z0-9.\-]*))?\b", re.IGNORECASE),
    ]
    for pattern in patterns:
        match = pattern.search(value)
        if match:
            version = match.group(2) if match.lastindex and match.lastindex >= 2 else None
            return {
                "product": match.group(1),
                "version": version or None,
                "extra_info": None,
                "source": "header:x-powered-by",
                "confidence": "high" if version else "medium",
                "raw_evidence": f"X-Powered-By: {value}",
            }
    return None


def _extract_meta_generator_observation(body_text):
    if not body_text:
        return None
    match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', body_text, re.IGNORECASE)
    if not match:
        return None
    generator = " ".join(match.group(1).split()).strip()
    version_match = re.search(r"^(.*?)(?:\s+([0-9][A-Za-z0-9.\-]*))?$", generator)
    product = _normalize_product_name(version_match.group(1)) if version_match else generator
    version = version_match.group(2) if version_match and version_match.lastindex else None
    return {
        "product": product,
        "version": version,
        "extra_info": None,
        "source": "meta:generator",
        "confidence": "high" if version else "medium",
        "raw_evidence": f"meta generator: {generator}",
    }


def _parse_whatweb_observations(stdout):
    observations = []
    normalized_stdout = normalize_command_output(stdout)
    if not normalized_stdout:
        return observations
    patterns = [
        ("WordPress", re.compile(r"\bWordPress(?:\[(.*?)\])?", re.IGNORECASE)),
        ("PrestaShop", re.compile(r"\bPrestaShop(?:\[(.*?)\])?", re.IGNORECASE)),
        ("Apache httpd", re.compile(r"\bApache(?:\[(.*?)\])?", re.IGNORECASE)),
        ("nginx", re.compile(r"\bnginx(?:\[(.*?)\])?", re.IGNORECASE)),
        ("PHP", re.compile(r"\bPHP(?:\[(.*?)\])?", re.IGNORECASE)),
        ("Jenkins", re.compile(r"\bJenkins(?:\[(.*?)\])?", re.IGNORECASE)),
    ]
    for product, pattern in patterns:
        match = pattern.search(normalized_stdout)
        if not match:
            continue
        detail = match.group(1) or ""
        version_match = re.search(r"([0-9][A-Za-z0-9.\-]*)", detail)
        observations.append({
            "product": product,
            "version": version_match.group(1) if version_match else None,
            "extra_info": None,
            "source": "whatweb",
            "confidence": "high" if version_match else "medium",
            "raw_evidence": summarize_text(normalized_stdout, limit=200),
        })
    return observations


def _build_base_url(service_target):
    if service_target.get("url"):
        return service_target["url"]
    service_name = (service_target.get("service") or "").lower()
    scheme = "https" if service_target.get("port") in {443, 8443} or "https" in service_name else "http"
    return f"{scheme}://{service_target['target']}:{service_target['port']}"


def _base_origin_url(url):
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _record_http_artifact(state, result, service_target, artifact_type, source, content, retrieved=True):
    append_service_artifact(state, result, {
        "service": service_target["service"],
        "port": service_target["port"],
        "type": artifact_type,
        "source": source,
        "retrieved": retrieved,
        "content": content,
    })


def _debug_enabled(state):
    return bool(state.get("debug_web"))


def _debug_log(state, message):
    if _debug_enabled(state):
        print(f"[WEB][DEBUG] {message}")


def _debug_artifact_dir(state):
    started_at = str(state.get("started_at", "debug")).replace(":", "-")
    return ARTIFACTS_DIR / "debug-web" / started_at


def _persist_debug_artifact(state, result, service_target, filename, content, *, artifact_type):
    if not _debug_enabled(state):
        return None
    debug_dir = _debug_artifact_dir(state)
    debug_dir.mkdir(parents=True, exist_ok=True)
    path = debug_dir / filename
    normalized_content = normalize_command_output(content)[:MAX_DEBUG_ARTIFACT_BYTES]
    path.write_text(normalized_content, encoding="utf-8")
    _record_http_artifact(state, result, service_target, artifact_type, str(path), f"saved debug artifact {filename}")
    return path


def _make_safe_filename(label):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", str(label or "debug")).strip("_") or "debug"


def _fetch_url(state, url, *, headers=None, method=None, timeout_seconds=None):
    effective_timeout = int(min(state.get("timeout", 120), timeout_seconds or 10))
    command = ["curl", "-k", "-sS", "-L", "-D", "-", "--max-time", str(effective_timeout)]
    for name, value in (headers or {}).items():
        command.extend(["-H", f"{name}: {value}"])
    if method:
        command.extend(["-X", method])
    command.append(url)
    return run_batch_step(state, module_name="http", command=command, timeout=min(int(state.get("timeout", 120)), effective_timeout + 5))


def _head_url(state, url):
    return run_batch_step(
        state,
        module_name="http",
        command=["curl", "-k", "-sS", "-I", "--max-time", str(int(min(state.get("timeout", 120), 10))), url],
        timeout=min(int(state.get("timeout", 120)), 15),
    )


def _run_whatweb_probe(state, base_url):
    if not check_tool_available("whatweb"):
        return None
    return run_batch_step(state, module_name="http", command=["whatweb", "--no-errors", "--color=never", base_url], timeout=12)


def _apply_http_observation(state, result, observation, *, url=None, entry_type="technology", tags=None, update_inventory=True):
    if not observation:
        return
    add_fingerprint(result, **observation)
    if update_inventory:
        merge_inventory_observation(result, **observation)
    upsert_inventory_entry(state, {
        "type": entry_type,
        "host": result.get("host"),
        "url": url or result.get("url"),
        "port": result.get("port"),
        "protocol": result.get("protocol"),
        "service_name": result.get("service"),
        "product": observation.get("product"),
        "version": observation.get("version"),
        "source": observation.get("source"),
        "confidence": observation.get("confidence"),
        "raw_evidence": observation.get("raw_evidence"),
        "tags": list(tags or []),
    })


def _parse_document(body_text):
    parser = _DocumentParser()
    try:
        parser.feed(body_text or "")
    except Exception:
        pass
    return parser


def _same_origin(base_url, candidate):
    parsed_base = urlparse(base_url)
    resolved = urljoin(base_url, candidate)
    parsed = urlparse(resolved)
    return (parsed.scheme, parsed.netloc) == (parsed_base.scheme, parsed_base.netloc)


def _extract_js_candidates(base_url, script_src):
    same_origin = []
    for value in script_src:
        if _same_origin(base_url, value):
            resolved = urljoin(base_url, value)
            if resolved not in same_origin:
                same_origin.append(resolved)
    return same_origin[:MAX_JS_FETCHES]


def _config_probe_urls(base_url):
    root_url = _base_origin_url(base_url)
    urls = []
    for path in CONFIG_ENDPOINT_PATHS:
        resolved = f"{root_url.rstrip('/')}{path}"
        if resolved not in urls:
            urls.append(resolved)
    return urls[:MAX_CONFIG_ENDPOINTS]


def _soft_404_key(body, headers):
    text = summarize_text(f"{headers}\n{body}", limit=200)
    text = re.sub(r"[A-Fa-f0-9]{8,}", "", text)
    return text


def _normalize_generic_product(product):
    cleaned = " ".join(str(product or "").split()).strip(" -:_/").strip()
    if not cleaned:
        return None
    lowered = cleaned.lower()
    if lowered in PRODUCT_STOPWORDS:
        return None
    return PRODUCT_NORMALIZATION.get(lowered, cleaned)


def _looks_like_version(value):
    cleaned = str(value or "").strip().lstrip("vV")
    if not cleaned:
        return False
    if cleaned.count(".") < 1:
        return False
    if re.fullmatch(r"(?:\d+\.){3}\d+", cleaned):
        octets = [int(item) for item in cleaned.split(".")]
        if all(0 <= octet <= 255 for octet in octets):
            return False
    return True


def _reject_version_candidate(version, prefix_text="", suffix_text="", cue_matched=False):
    cleaned = str(version or "").strip().lstrip("vV")
    if not _looks_like_version(cleaned):
        return True
    if re.fullmatch(r"(?:\d+\.){3}\d+", cleaned):
        octets = [int(item) for item in cleaned.split(".")]
        if all(0 <= octet <= 255 for octet in octets) and not cue_matched:
            return True
    parts = cleaned.split(".")
    if len(parts) == 3 and all(part.isdigit() for part in parts):
        year, month, day = [int(part) for part in parts]
        if 1900 <= year <= 2100 and 1 <= month <= 12 and 1 <= day <= 31:
            return True
    lowered_prefix = str(prefix_text or "").lower()
    lowered_suffix = str(suffix_text or "").lower()
    if lowered_prefix.endswith("http/") or lowered_prefix.endswith("tls/") or lowered_prefix.endswith("tlsv") or lowered_prefix.endswith("ssh-"):
        return True
    if re.search(r"(?:width|height|padding|margin|font|line-height|viewport|opacity|z-index|x|y)\s*[:=]?\s*$", lowered_prefix):
        return True
    if lowered_suffix.startswith(("px", "rem", "em", "%", "vh", "vw")):
        return True
    return False


def _version_source_strength(source):
    normalized_source = str(source or "").strip().lower()
    if normalized_source == "meta:generator":
        return 5
    if normalized_source == "whatweb":
        return 4
    if normalized_source.startswith("js_asset"):
        return 4
    if normalized_source in {"html_visible_text", "html:title", "nmap:http-title"}:
        return 3
    if normalized_source.startswith("nmap:ssl-cert"):
        return 2
    return 2


def _record_debug_candidate(debug_context, kind, payload):
    if debug_context is None:
        return
    debug_context.setdefault(kind, []).append(payload)


def _record_debug_rejection(debug_context, kind, reason, snippet, source):
    if debug_context is None:
        return
    debug_context.setdefault("rejections", []).append({
        "kind": kind,
        "source": source,
        "reason": reason,
        "snippet": summarize_text(snippet, limit=180),
    })


def _product_source_strength(source):
    normalized_source = str(source or "").strip().lower()
    if normalized_source in {"meta:generator", "whatweb", "html:title", "nmap:http-title"}:
        return 5
    if normalized_source.startswith("nmap:ssl-cert"):
        return 4
    if normalized_source == "html_visible_text":
        return 3
    return 2


def extract_version_candidates_from_text(text, source, *, context_key=None, confidence="medium", limit=180, debug_context=None):
    haystack = normalize_command_output(text)[:MAX_TEXT_FINGERPRINT_BYTES]
    if not haystack:
        return []
    candidates = []
    seen = set()
    for match in SEMVER_PATTERN.finditer(haystack):
        version = str(match.group(1) or "").strip().lstrip("vV")
        prefix_text = haystack[max(0, match.start() - 40):match.start()]
        suffix_text = haystack[match.end():min(len(haystack), match.end() + 40)]
        cue_matched = bool(VERSION_CUE_PATTERN.search(f"{prefix_text} {suffix_text}"))
        snippet = summarize_text(f"{prefix_text}{match.group(0)}{suffix_text}", limit=limit)
        if _reject_version_candidate(version, prefix_text=prefix_text, suffix_text=suffix_text, cue_matched=cue_matched):
            _record_debug_rejection(debug_context, "version", "filter_rejected", snippet or version, source)
            continue
        signature = version.lower()
        if signature in seen:
            _record_debug_rejection(debug_context, "version", "duplicate", snippet or version, source)
            continue
        seen.add(signature)
        cue_bonus = 2 if cue_matched else 0
        candidate = {
            "version": version,
            "source": source,
            "confidence": confidence,
            "context_key": context_key or source,
            "raw_evidence": snippet or version,
            "score": _version_source_strength(source) + cue_bonus,
        }
        candidates.append(candidate)
        _record_debug_candidate(debug_context, "version_candidates", candidate)
        if len(candidates) >= 8:
            break
    return candidates


def extract_software_observations_from_text(text, source, *, confidence="medium", limit=220):
    haystack = normalize_command_output(text)[:MAX_TEXT_FINGERPRINT_BYTES]
    if not haystack:
        return []
    observations = []
    seen = set()
    for pattern in GENERIC_PRODUCT_VERSION_PATTERNS:
        for match in pattern.finditer(haystack):
            product = _normalize_generic_product(match.group(1))
            version = str(match.group(2) or "").strip().lstrip("vV")
            if not product or not _looks_like_version(version):
                continue
            signature = (product.lower(), version.lower())
            if signature in seen:
                continue
            seen.add(signature)
            observations.append({
                "product": product,
                "version": version,
                "extra_info": None,
                "source": source,
                "confidence": confidence,
                "raw_evidence": summarize_text(match.group(0), limit=limit),
            })
            if len(observations) >= 4:
                return observations
    return observations


def _clean_product_hint_text(text):
    cleaned = " ".join(str(text or "").split()).strip(" -|:/")
    if not cleaned:
        return None
    for separator in (" | ", " - ", " :: ", " : "):
        if separator in cleaned:
            cleaned = cleaned.split(separator, 1)[0].strip()
    lowered = cleaned.lower()
    for suffix in TITLE_HINT_SUFFIXES:
        if lowered.endswith(f" {suffix}"):
            cleaned = cleaned[: -len(suffix)].strip(" -|:/")
            lowered = cleaned.lower()
    return cleaned or None


def extract_product_hints_from_text(text, source, *, confidence="low", limit=180, debug_context=None):
    cleaned = _clean_product_hint_text(normalize_command_output(text))
    if not cleaned:
        return []
    if len(cleaned) > 60 or len(cleaned.split()) > 4:
        _record_debug_rejection(debug_context, "product", "too_long", cleaned, source)
        return []
    if re.search(r"\d+\.\d+", cleaned):
        _record_debug_rejection(debug_context, "product", "contains_version", cleaned, source)
        return []
    if not re.search(r"[A-Za-z]", cleaned):
        _record_debug_rejection(debug_context, "product", "no_letters", cleaned, source)
        return []
    product = _normalize_generic_product(cleaned)
    if not product:
        _record_debug_rejection(debug_context, "product", "generic_stopword", cleaned, source)
        return []
    if product.lower() in PRODUCT_STOPWORDS:
        _record_debug_rejection(debug_context, "product", "generic_stopword", cleaned, source)
        return []
    candidate = {
        "product": product,
        "version": None,
        "extra_info": None,
        "source": source,
        "confidence": confidence,
        "raw_evidence": summarize_text(cleaned, limit=limit),
    }
    _record_debug_candidate(debug_context, "product_candidates", {
        "product": candidate["product"],
        "source": candidate["source"],
        "raw_evidence": candidate["raw_evidence"],
    })
    return [candidate]


def _add_candidate(candidate_list, observation, *, context_key, debug_context=None):
    if not observation or not observation.get("product"):
        return
    candidate = {
        "product": observation.get("product"),
        "source": observation.get("source"),
        "confidence": observation.get("confidence", "medium"),
        "raw_evidence": observation.get("raw_evidence"),
        "context_key": context_key,
        "score": _product_source_strength(observation.get("source")),
    }
    candidate_list.append(candidate)
    _record_debug_candidate(debug_context, "product_candidates", candidate)


def _best_product_version_match(product_candidates, version_candidates):
    best_match = None
    for version_candidate in version_candidates:
        compatible_products = [
            candidate
            for candidate in product_candidates
            if candidate.get("context_key") == version_candidate.get("context_key")
        ]
        if not compatible_products:
            continue
        best_product = max(
            compatible_products,
            key=lambda item: (item.get("score", 0), 1 if item.get("confidence") == "high" else 0, len(item.get("product", ""))),
        )
        combined_score = best_product.get("score", 0) + version_candidate.get("score", 0)
        if best_match is None or combined_score > best_match["score"]:
            best_match = {"product": best_product, "version": version_candidate, "score": combined_score}
    return best_match


def _extract_js_key_candidates(text, source, *, context_key, debug_context=None):
    normalized_text = normalize_command_output(text)[:MAX_TEXT_FINGERPRINT_BYTES]
    product_candidates = []
    version_candidates = []
    for match in JS_PRODUCT_KEY_PATTERN.finditer(normalized_text):
        product = _normalize_generic_product(match.group(2))
        if not product:
            _record_debug_rejection(debug_context, "product", "js_key_generic_stopword", match.group(0), source)
            continue
        candidate = {
            "product": product,
            "source": source,
            "confidence": "medium",
            "raw_evidence": summarize_text(match.group(0), limit=180),
            "context_key": context_key,
            "score": _product_source_strength(source) + 1,
        }
        product_candidates.append(candidate)
        _record_debug_candidate(debug_context, "product_candidates", candidate)
    for match in JS_VERSION_KEY_PATTERN.finditer(normalized_text):
        version = str(match.group(2) or "").strip().lstrip("vV")
        if _reject_version_candidate(version, prefix_text=match.group(1), suffix_text="", cue_matched=True):
            _record_debug_rejection(debug_context, "version", "js_key_filter_rejected", match.group(0), source)
            continue
        candidate = {
            "version": version,
            "source": source,
            "confidence": "medium",
            "context_key": context_key,
            "raw_evidence": summarize_text(match.group(0), limit=180),
            "score": _version_source_strength(source) + 2,
        }
        version_candidates.append(candidate)
        _record_debug_candidate(debug_context, "version_candidates", candidate)
    return product_candidates, version_candidates


def _extract_product_version_from_mapping(data, source, *, context_key, debug_context=None):
    if not isinstance(data, dict):
        return [], []
    product_candidates = []
    version_candidates = []
    product_keys = {"appname", "productname", "displayname", "title", "brand", "application", "name"}
    version_keys = {"version", "appversion", "productversion", "buildversion", "releaseversion", "build"}
    for key, value in data.items():
        lowered_key = str(key).strip().lower()
        if lowered_key in product_keys:
            product = _normalize_generic_product(value)
            if product:
                candidate = {
                    "product": product,
                    "source": source,
                    "confidence": "medium",
                    "raw_evidence": summarize_text(f"{key}: {value}", limit=180),
                    "context_key": context_key,
                    "score": _product_source_strength(source) + 1,
                }
                product_candidates.append(candidate)
                _record_debug_candidate(debug_context, "product_candidates", candidate)
        elif lowered_key in version_keys:
            version_candidates.extend(
                extract_version_candidates_from_text(
                    f"{key}: {value}",
                    source,
                    context_key=context_key,
                    confidence="medium",
                    debug_context=debug_context,
                )
            )
        if isinstance(value, dict):
            nested_products, nested_versions = _extract_product_version_from_mapping(
                value,
                source,
                context_key=context_key,
                debug_context=debug_context,
            )
            product_candidates.extend(nested_products)
            version_candidates.extend(nested_versions)
    return product_candidates, version_candidates


def _extract_config_response_candidates(text, source, *, context_key, debug_context=None):
    normalized_text = normalize_command_output(text)
    product_candidates = []
    version_candidates = []
    try:
        parsed = json.loads(normalized_text)
    except Exception:
        parsed = None
    if isinstance(parsed, dict):
        nested_products, nested_versions = _extract_product_version_from_mapping(
            parsed,
            source,
            context_key=context_key,
            debug_context=debug_context,
        )
        product_candidates.extend(nested_products)
        version_candidates.extend(nested_versions)
    js_products, js_versions = _extract_js_key_candidates(normalized_text, source, context_key=context_key, debug_context=debug_context)
    product_candidates.extend(js_products)
    version_candidates.extend(js_versions)
    version_candidates.extend(
        extract_version_candidates_from_text(
            normalized_text,
            source,
            context_key=context_key,
            confidence="medium",
            debug_context=debug_context,
        )
    )
    return product_candidates, version_candidates


def _render_web_text(url, timeout_seconds):
    try:
        playwright_module = importlib.import_module("playwright.sync_api")
    except Exception:
        return {"success": False, "error": "playwright unavailable", "text": ""}

    try:
        with playwright_module.sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page(ignore_https_errors=True)
            page.goto(url, wait_until="domcontentloaded", timeout=int(timeout_seconds * 1000))
            text = page.evaluate("document.body ? document.body.innerText : ''") or ""
            browser.close()
            return {"success": True, "error": None, "text": normalize_command_output(text)[:MAX_RENDER_TEXT_BYTES]}
    except Exception as exc:
        return {"success": False, "error": str(exc), "text": ""}


def _classify_interesting_path(path, status_code, body_text):
    lowered_path = path.lower()
    if status_code is None or status_code >= 400:
        return None
    if lowered_path == "/.env":
        return ("Exposed .env file", "high")
    if lowered_path == "/.git/head":
        return ("Exposed Git metadata", "medium")
    if lowered_path == "/phpinfo.php":
        return ("phpinfo exposed", "high")
    if lowered_path == "/server-status":
        return ("Apache server-status exposed", "medium")
    if lowered_path in {"/swagger", "/swagger-ui", "/api-docs", "/openapi.json"}:
        return ("Public API documentation exposed", "low")
    if lowered_path == "/graphql":
        return ("GraphQL endpoint exposed", "info")
    if lowered_path in {"/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt"}:
        return None
    if lowered_path in {"/admin", "/login", "/api", "/api/v1", "/api/v2"}:
        return ("Interesting application endpoint exposed", "info")
    if "db_" in (body_text or "").lower():
        return ("Sensitive file content exposed", "high")
    return None


def _record_finding(state, result, *, title, severity, affected, evidence, recommendation, source, finding_type=None):
    finding = {
        "type": finding_type,
        "title": title,
        "severity": severity,
        "affected": affected,
        "evidence": evidence,
        "recommendation": recommendation,
        "source": source,
    }
    result["findings"].append(finding)
    add_finding(state, finding)


def _extract_cert_name(evidence_value, field_name):
    match = re.search(rf"{field_name}=([^/]+)", str(evidence_value or ""), re.IGNORECASE)
    if not match:
        return None
    return " ".join(match.group(1).split()).strip()


def _emit_debug_candidates(state, debug_context):
    if not _debug_enabled(state):
        return
    _debug_log(state, f"html_bytes={debug_context.get('html_bytes', 0)}")
    _debug_log(state, f"script_src={debug_context.get('script_src', [])}")
    _debug_log(state, f"fetched_js_urls={debug_context.get('fetched_js_urls', [])}")
    for candidate in debug_context.get("product_candidates", [])[:16]:
        _debug_log(
            state,
            f"product_candidate source={candidate.get('source')} product={candidate.get('product')} snippet={summarize_text(candidate.get('raw_evidence'), limit=120)}",
        )
    for candidate in debug_context.get("version_candidates", [])[:16]:
        _debug_log(
            state,
            f"version_candidate source={candidate.get('source')} version={candidate.get('version')} snippet={summarize_text(candidate.get('raw_evidence'), limit=120)}",
        )
    for rejection in debug_context.get("rejections", [])[:24]:
        _debug_log(
            state,
            f"rejected_{rejection.get('kind')} source={rejection.get('source')} reason={rejection.get('reason')} snippet={summarize_text(rejection.get('snippet'), limit=120)}",
        )


def run_http_module(state, service_target):
    result = build_module_result(service_target)
    base_url = _build_base_url(service_target)
    root_url = _base_origin_url(base_url)
    result["url"] = base_url
    fetched_js_count = 0
    whatweb_status = "skipped"
    whatweb_excerpt = None
    script_evidence = dict(service_target.get("script_evidence") or {})
    page_context_key = base_url
    product_candidates = []
    version_candidates = []
    debug_context = {"product_candidates": [], "version_candidates": [], "rejections": [], "script_src": [], "fetched_js_urls": []}

    if not check_tool_available("curl"):
        result["status"] = "failed"
        result["errors"].append("curl not found in PATH")
        publish_service_inventory(state, result, entry_type="service", tags=["network", "web"], url=base_url)
        return finalize_result(result)

    main_page = _fetch_url(state, base_url)
    split = _split_headers_and_body(main_page.get("stdout", ""))
    headers_text = split["final_headers"]
    body_text = split["final_body"]
    debug_context["html_bytes"] = len(body_text.encode("utf-8", errors="ignore"))
    header_values = _header_map(headers_text)
    status_code = _extract_status_code(headers_text)
    response_chain = []
    for header_block, _body in split["response_chain"]:
        code = _extract_status_code(header_block)
        location_values = _header_map(header_block).get("location", [])
        response_chain.append({"status_code": code, "location": location_values[0] if location_values else None})

    final_url = base_url
    if response_chain:
        for item in response_chain:
            if item["location"]:
                final_url = urljoin(final_url, item["location"])
    result["url"] = final_url or base_url
    page_context_key = final_url or base_url

    server_header = (header_values.get("server") or [None])[0]
    x_powered_by = (header_values.get("x-powered-by") or [None])[0]
    title = extract_http_title(body_text)
    content_type = (header_values.get("content-type") or [None])[0]
    set_cookie_headers = header_values.get("set-cookie", [])
    meta_generator = _extract_meta_generator_observation(body_text)
    parser = _parse_document(body_text)
    visible_text_chunks = parser.visible_text_chunks[:12]
    debug_context["script_src"] = list(parser.script_src[:MAX_JS_FETCHES])
    if _debug_enabled(state):
        _persist_debug_artifact(state, result, service_target, f"{_make_safe_filename(service_target['port'])}_final_body.txt", body_text, artifact_type="debug_web_html")

    result["http_summary"] = {
        "status_code": status_code,
        "title": title,
        "content_type": content_type,
        "redirect_chain": response_chain,
        "forms": parser.forms[:10],
        "script_src": parser.script_src[:10],
        "stylesheets": parser.stylesheets[:10],
        "links": parser.links[:10],
    }

    _apply_http_observation(state, result, _extract_server_header_observation(server_header), url=base_url, entry_type="service", tags=["web", "http"])
    if script_evidence.get("http_server_header"):
        script_server_observation = _extract_server_header_observation(script_evidence.get("http_server_header"))
        if script_server_observation:
            script_server_observation["source"] = "nmap:http-server-header"
            _apply_http_observation(state, result, script_server_observation, url=final_url or base_url, entry_type="service", tags=["web", "nmap"], update_inventory=True)
    _apply_http_observation(state, result, _extract_x_powered_by_observation(x_powered_by), url=base_url, entry_type="technology", tags=["web", "powered-by"], update_inventory=not result["inventory"].get("product"))
    if meta_generator:
        _apply_http_observation(state, result, meta_generator, url=base_url, entry_type="web_component", tags=["web", "cms"], update_inventory=not result["inventory"].get("product"))
        _add_candidate(product_candidates, meta_generator, context_key=page_context_key, debug_context=debug_context)
        version_candidates.extend(extract_version_candidates_from_text(meta_generator.get("raw_evidence"), "meta:generator", context_key=page_context_key, confidence="high", debug_context=debug_context))
    for observation in extract_product_hints_from_text(title, "html:title", confidence="medium", debug_context=debug_context):
        _apply_http_observation(state, result, observation, url=final_url or base_url, entry_type="web_component", tags=["web", "title_hint"], update_inventory=False)
        _add_candidate(product_candidates, observation, context_key=page_context_key, debug_context=debug_context)
    for source_name, source_text, source_confidence in (
        ("web_html:title", title, "medium"),
        ("web_html:body", body_text, "medium"),
        ("web_html:meta_generator", parser.meta_generator, "high"),
    ):
        for observation in extract_software_observations_from_text(source_text, source_name, confidence=source_confidence):
            _apply_http_observation(state, result, observation, url=final_url or base_url, entry_type="web_component", tags=["web", "text_fingerprint"], update_inventory=True)
    version_candidates.extend(extract_version_candidates_from_text(title, "html:title", context_key=page_context_key, confidence="medium", debug_context=debug_context))
    version_candidates.extend(extract_version_candidates_from_text(parser.meta_generator, "meta:generator", context_key=page_context_key, confidence="high", debug_context=debug_context))
    for chunk in visible_text_chunks:
        for observation in extract_product_hints_from_text(chunk, "html_visible_text", confidence="low", debug_context=debug_context):
            _add_candidate(product_candidates, observation, context_key=page_context_key, debug_context=debug_context)
        version_candidates.extend(extract_version_candidates_from_text(chunk, "html_visible_text", context_key=page_context_key, confidence="medium", debug_context=debug_context))
    if script_evidence.get("http_title"):
        for observation in extract_product_hints_from_text(script_evidence.get("http_title"), "nmap:http-title", confidence="medium", debug_context=debug_context):
            _apply_http_observation(state, result, observation, url=final_url or base_url, entry_type="web_component", tags=["web", "nmap"], update_inventory=False)
            _add_candidate(product_candidates, observation, context_key=page_context_key, debug_context=debug_context)
        for observation in extract_software_observations_from_text(script_evidence.get("http_title"), "nmap:http-title", confidence="medium"):
            _apply_http_observation(state, result, observation, url=final_url or base_url, entry_type="web_component", tags=["web", "nmap"], update_inventory=True)
        version_candidates.extend(extract_version_candidates_from_text(script_evidence.get("http_title"), "nmap:http-title", context_key=page_context_key, confidence="medium", debug_context=debug_context))
    for cert_value in (script_evidence.get("ssl_cert_subject"), script_evidence.get("ssl_cert_issuer"), script_evidence.get("ssl_cert_san")):
        cert_name = _extract_cert_name(cert_value, "commonName") or _extract_cert_name(cert_value, "DNS")
        for observation in extract_product_hints_from_text(cert_name, "nmap:ssl-cert", confidence="low", debug_context=debug_context):
            _apply_http_observation(state, result, observation, url=final_url or base_url, entry_type="web_component", tags=["web", "ssl_cert"], update_inventory=False)
            _add_candidate(product_candidates, observation, context_key=page_context_key, debug_context=debug_context)
        version_candidates.extend(extract_version_candidates_from_text(cert_name, "nmap:ssl-cert", context_key=page_context_key, confidence="low", debug_context=debug_context))

    publish_service_inventory(state, result, entry_type="service", tags=["network", "web"], url=final_url or base_url)

    missing_headers = [header for header in SECURITY_HEADERS if header not in header_values]
    for header in missing_headers:
        _record_finding(
            state,
            result,
            title=f"Missing {header} header",
            severity="low" if header in {"content-security-policy", "strict-transport-security", "x-frame-options"} else "info",
            affected=base_url,
            evidence=f"{header} header was not present",
            recommendation="Review HTTP response hardening headers.",
            source="web:security_headers",
            finding_type="missing_security_header",
        )

    for cookie in set_cookie_headers:
        lowered = cookie.lower()
        if "secure" not in lowered:
            _record_finding(state, result, title="Cookie missing Secure", severity="low", affected=base_url, evidence=cookie, recommendation="Mark cookies Secure over HTTPS.", source="web:cookies", finding_type="cookie_attribute")
        if "httponly" not in lowered:
            _record_finding(state, result, title="Cookie missing HttpOnly", severity="low", affected=base_url, evidence=cookie, recommendation="Mark session cookies HttpOnly.", source="web:cookies", finding_type="cookie_attribute")
        same_site_match = re.search(r"samesite=([^;]+)", cookie, re.IGNORECASE)
        if not same_site_match:
            _record_finding(state, result, title="Cookie missing SameSite", severity="info", affected=base_url, evidence=cookie, recommendation="Set an explicit SameSite attribute.", source="web:cookies", finding_type="cookie_attribute")
        elif same_site_match.group(1).strip().lower() == "none" and "secure" not in lowered:
            _record_finding(state, result, title="SameSite=None cookie without Secure", severity="medium", affected=base_url, evidence=cookie, recommendation="Cookies with SameSite=None must also be Secure.", source="web:cookies", finding_type="cookie_attribute")

    cors_result = _fetch_url(state, base_url, headers={"Origin": "https://reconpilot.invalid"})
    cors_split = _split_headers_and_body(cors_result.get("stdout", ""))
    cors_headers = _header_map(cors_split["final_headers"])
    acao = (cors_headers.get("access-control-allow-origin") or [None])[0]
    acac = (cors_headers.get("access-control-allow-credentials") or [None])[0]
    if acao:
        result["findings"].append({"type": "cors", "value": {"allow_origin": acao, "allow_credentials": acac}})
        reflected = acao == "https://reconpilot.invalid"
        credentials = str(acac or "").lower() == "true"
        if reflected and credentials:
            _record_finding(state, result, title="CORS reflects arbitrary Origin with credentials", severity="high", affected=base_url, evidence={"allow_origin": acao, "allow_credentials": acac}, recommendation="Restrict allowed origins and disable credentialed reflection.", source="web:cors", finding_type="cors")
        elif reflected:
            _record_finding(state, result, title="CORS reflects arbitrary Origin", severity="medium", affected=base_url, evidence={"allow_origin": acao, "allow_credentials": acac}, recommendation="Restrict Access-Control-Allow-Origin to trusted origins.", source="web:cors", finding_type="cors")

    options_result = _fetch_url(state, base_url, method="OPTIONS")
    options_headers = _header_map(_split_headers_and_body(options_result.get("stdout", ""))["final_headers"])
    allow_header = (options_headers.get("allow") or [None])[0]
    if allow_header:
        result["findings"].append({"type": "http_methods", "value": allow_header})

    random_path = "/reconpilot-nonexistent-404-check"
    random_url = f"{root_url.rstrip('/')}{random_path}"
    random_result = _fetch_url(state, random_url)
    random_split = _split_headers_and_body(random_result.get("stdout", ""))
    random_status = _extract_status_code(random_split["final_headers"])
    soft_404_signature = _soft_404_key(random_split["final_body"], random_split["final_headers"])
    if re.search(r"(traceback|stack trace|exception in thread|debug)", random_split["final_body"], re.IGNORECASE):
        _record_finding(state, result, title="Debug or stack trace exposed on error response", severity="medium", affected=random_url, evidence=summarize_text(random_split["final_body"], limit=220), recommendation="Disable verbose error pages in production.", source="web:error_page", finding_type="error_page")

    if headers_text:
        _record_http_artifact(state, result, service_target, "http_headers", base_url, summarize_text(headers_text, limit=500))
    if body_text:
        _record_http_artifact(state, result, service_target, "http_body_excerpt", base_url, summarize_text(body_text, limit=500))

    for path in INTERESTING_PATHS:
        endpoint_url = f"{root_url.rstrip('/')}{path}"
        endpoint_result = _fetch_url(state, endpoint_url)
        endpoint_split = _split_headers_and_body(endpoint_result.get("stdout", ""))
        endpoint_status = _extract_status_code(endpoint_split["final_headers"])
        endpoint_key = _soft_404_key(endpoint_split["final_body"], endpoint_split["final_headers"])
        if endpoint_status is None or endpoint_status >= 400:
            continue
        if random_status and endpoint_status == random_status and endpoint_key == soft_404_signature:
            continue
        result["findings"].append({"type": "interesting_endpoint", "value": path, "status": endpoint_status})
        _record_http_artifact(state, result, service_target, "http_endpoint_excerpt", endpoint_url, summarize_text(endpoint_split["final_body"] or endpoint_split["final_headers"], limit=400))
        finding_shape = _classify_interesting_path(path, endpoint_status, endpoint_split["final_body"])
        if finding_shape:
            title, severity = finding_shape
            _record_finding(state, result, title=title, severity=severity, affected=endpoint_url, evidence={"status": endpoint_status, "path": path}, recommendation="Review and restrict unintended public exposure.", source="web:interesting_paths", finding_type="interesting_path")

    endpoint_hints = []
    for source in list(parser.links) + list(parser.script_src):
        decoded = html.unescape(source or "")
        if JS_KEYWORD_PATTERN.search(decoded):
            endpoint_hints.append(decoded)
    for js_url in _extract_js_candidates(base_url, parser.script_src):
        js_result = _fetch_url(state, js_url)
        js_body = _split_headers_and_body(js_result.get("stdout", ""))["final_body"][:MAX_JS_BYTES]
        fetched_js_count += 1
        debug_context["fetched_js_urls"].append(js_url)
        for match in JS_KEYWORD_PATTERN.findall(js_body or ""):
            endpoint_hints.append(match)
        js_observations = extract_software_observations_from_text(js_body, "js_asset", confidence="medium")
        for observation in js_observations:
            _apply_http_observation(state, result, observation, url=final_url or base_url, entry_type="web_component", tags=["web", "js_asset", "text_fingerprint"], update_inventory=True)
        js_product_candidates, js_version_key_candidates = _extract_js_key_candidates(js_body, "js_asset", context_key=page_context_key, debug_context=debug_context)
        product_candidates.extend(js_product_candidates)
        version_candidates.extend(js_version_key_candidates)
        version_candidates.extend(extract_version_candidates_from_text(js_body, "js_asset", context_key=page_context_key, confidence="medium", debug_context=debug_context))
        if js_observations or js_product_candidates or js_version_key_candidates:
            _record_http_artifact(state, result, service_target, "js_asset_excerpt", js_url, summarize_text(js_body, limit=300))
        if _debug_enabled(state):
            _persist_debug_artifact(state, result, service_target, f"js_{_make_safe_filename(js_url)}.txt", js_body, artifact_type="debug_web_js")
    deduped_hints = []
    for hint in endpoint_hints:
        resolved = urljoin(base_url, hint)
        if resolved not in deduped_hints:
            deduped_hints.append(resolved)
    if deduped_hints:
        result["findings"].append({"type": "endpoint_hints", "value": deduped_hints[:12]})
        _record_finding(state, result, title="Discovered likely application endpoints", severity="info", affected=base_url, evidence=deduped_hints[:12], recommendation="Review exposed application routes for authorization and data exposure.", source="web:html_js", finding_type="endpoint_hints")

    whatweb_result = _run_whatweb_probe(state, base_url)
    if whatweb_result and whatweb_result.get("stdout"):
        whatweb_status = "completed"
        whatweb_excerpt = summarize_text(whatweb_result["stdout"], limit=200)
        _record_http_artifact(state, result, service_target, "whatweb_output", base_url, summarize_text(whatweb_result["stdout"], limit=400))
        for observation in _parse_whatweb_observations(whatweb_result["stdout"]):
            _apply_http_observation(state, result, observation, url=base_url, entry_type="web_component", tags=["web", "whatweb"])
            _add_candidate(product_candidates, observation, context_key=page_context_key, debug_context=debug_context)
        for observation in extract_product_hints_from_text(whatweb_result["stdout"], "whatweb", confidence="medium", debug_context=debug_context):
            _apply_http_observation(state, result, observation, url=base_url, entry_type="web_component", tags=["web", "whatweb"], update_inventory=False)
            _add_candidate(product_candidates, observation, context_key=page_context_key, debug_context=debug_context)
        for observation in extract_software_observations_from_text(whatweb_result["stdout"], "whatweb", confidence="high"):
            _apply_http_observation(state, result, observation, url=base_url, entry_type="web_component", tags=["web", "whatweb"], update_inventory=True)
        version_candidates.extend(extract_version_candidates_from_text(whatweb_result["stdout"], "whatweb", context_key=page_context_key, confidence="high", debug_context=debug_context))
    elif whatweb_result and whatweb_result.get("stderr"):
        whatweb_status = "failed"
        whatweb_excerpt = summarize_text(whatweb_result["stderr"], limit=200)
        result["errors"].append(summarize_text(whatweb_result["stderr"]))
    else:
        whatweb_status = "unavailable"

    combined_match = _best_product_version_match(product_candidates, version_candidates)

    if product_candidates and combined_match is None:
        for config_url in _config_probe_urls(final_url or base_url):
            config_result = _fetch_url(state, config_url, timeout_seconds=5)
            config_body = _split_headers_and_body(config_result.get("stdout", ""))["final_body"]
            config_products, config_versions = _extract_config_response_candidates(
                config_body,
                "config_endpoint",
                context_key=page_context_key,
                debug_context=debug_context,
            )
            product_candidates.extend(config_products)
            version_candidates.extend(config_versions)
            if _debug_enabled(state) and config_body.strip():
                _persist_debug_artifact(state, result, service_target, f"config_{_make_safe_filename(config_url)}.txt", config_body, artifact_type="debug_web_config")
            if config_products or config_versions:
                _record_http_artifact(state, result, service_target, "config_endpoint_excerpt", config_url, summarize_text(config_body, limit=300))
        combined_match = _best_product_version_match(product_candidates, version_candidates)

    if state.get("render_web"):
        rendered = _render_web_text(final_url or base_url, min(float(state.get("timeout", 120)), 10))
        if rendered.get("success"):
            rendered_text = rendered.get("text", "")
            if _debug_enabled(state):
                _persist_debug_artifact(state, result, service_target, f"rendered_{_make_safe_filename(service_target['port'])}.txt", rendered_text, artifact_type="debug_web_rendered")
            for observation in extract_product_hints_from_text(rendered_text, "rendered_dom", confidence="medium", debug_context=debug_context):
                _add_candidate(product_candidates, observation, context_key=page_context_key, debug_context=debug_context)
            version_candidates.extend(extract_version_candidates_from_text(rendered_text, "rendered_dom", context_key=page_context_key, confidence="medium", debug_context=debug_context))
            combined_match = _best_product_version_match(product_candidates, version_candidates)
        else:
            _debug_log(state, f"render_web_unavailable reason={rendered.get('error')}")
    if combined_match and combined_match["score"] >= 6:
        best_product = combined_match["product"]
        best_version = combined_match["version"]
        combined_source = (
            best_product["source"]
            if best_product["source"] == best_version["source"]
            else f"{best_product['source']} + {best_version['source']}"
        )
        combined_confidence = "high" if combined_match["score"] >= 9 else "medium"
        combined_evidence = {
            "product_snippet": best_product.get("raw_evidence"),
            "product_source": best_product.get("source"),
            "version_snippet": best_version.get("raw_evidence"),
            "version_source": best_version.get("source"),
            "context_url": final_url or base_url,
        }
        add_fingerprint(
            result,
            best_product["product"],
            best_version["version"],
            None,
            combined_source,
            combined_confidence,
            combined_evidence,
        )
        merge_inventory_observation(
            result,
            best_product["product"],
            best_version["version"],
            None,
            best_product["source"],
            combined_confidence,
            combined_evidence,
        )
        for source_name in {best_product["source"], best_version["source"]}:
            upsert_inventory_entry(state, {
                "type": "web_component",
                "host": result.get("host"),
                "url": final_url or base_url,
                "port": result.get("port"),
                "protocol": result.get("protocol"),
                "service_name": result.get("service"),
                "product": best_product["product"],
                "version": best_version["version"],
                "source": source_name,
                "confidence": combined_confidence,
                "raw_evidence": combined_evidence,
                "tags": ["web", "http", "text_fingerprint"],
            })
    else:
        _debug_log(state, "no_product_version_match")

    technology_hints = []
    for fingerprint in result.get("fingerprints", []):
        label = " ".join(part for part in [fingerprint.get("product"), fingerprint.get("version")] if part).strip()
        source_label = fingerprint.get("source")
        combined = f"{label} [{source_label}]" if label and source_label else label
        if combined and combined not in technology_hints:
            technology_hints.append(combined)

    add_web_target(state, {
        "url": base_url,
        "source": service_target.get("service"),
        "reachable": bool(status_code),
        "status_code": status_code,
        "final_url": final_url,
        "title": title or script_evidence.get("http_title"),
        "server": server_header or script_evidence.get("http_server_header"),
        "x_powered_by": x_powered_by,
        "content_type": content_type,
        "script_src_count": len(parser.script_src),
        "fetched_js_count": fetched_js_count,
        "whatweb_status": whatweb_status,
        "whatweb_excerpt": whatweb_excerpt,
        "technology_hints": technology_hints,
        "nmap_evidence": script_evidence,
    })

    _emit_debug_candidates(state, debug_context)

    if state.get("debug_web"):
        print(
            f"[WEB][DEBUG] url={base_url} final={final_url} status={status_code} "
            f"title={title or script_evidence.get('http_title') or 'none'} "
            f"scripts={len(parser.script_src)} fetched_js={fetched_js_count} whatweb={whatweb_status}"
        )
        if technology_hints:
            print(f"[WEB][DEBUG] technologies={'; '.join(technology_hints[:6])}")
        if script_evidence:
            print(f"[WEB][DEBUG] nmap_evidence={script_evidence}")
        if whatweb_excerpt:
            print(f"[WEB][DEBUG] whatweb_excerpt={whatweb_excerpt}")

    if result["inventory"].get("product") or result["inventory"].get("version"):
        upsert_inventory_entry(state, {
            "type": "web_component",
            "host": result.get("host"),
            "url": final_url or base_url,
            "port": result.get("port"),
            "protocol": result.get("protocol"),
            "service_name": result.get("service"),
            "product": result["inventory"].get("product"),
            "version": result["inventory"].get("version"),
            "source": result["inventory"].get("detection_source"),
            "confidence": result["inventory"].get("confidence"),
            "raw_evidence": {
                "status_code": status_code,
                "server": server_header,
                "x_powered_by": x_powered_by,
                "title": title,
                "content_type": content_type,
                "meta_generator": meta_generator,
            },
            "tags": ["web", "http"],
        })

    if not main_page["success"] and not result["findings"] and not result["artifacts"]:
        result["status"] = "failed"
        if main_page.get("stderr"):
            result["errors"].append(summarize_text(main_page["stderr"]))
        elif not result["errors"]:
            result["errors"].append("no useful HTTP data retrieved")
    return finalize_result(result)
