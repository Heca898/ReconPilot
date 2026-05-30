from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


def detect_target_type(target):
    cleaned = str(target or "").strip()
    if not cleaned:
        return "unknown"
    parsed = urlparse(cleaned)
    if parsed.scheme and parsed.netloc:
        return "url"
    try:
        ipaddress.ip_address(cleaned)
        return "ip"
    except ValueError:
        return "domain"


def normalize_url_target(target):
    parsed = urlparse(str(target).strip())
    hostname = parsed.hostname
    scheme = parsed.scheme.lower() if parsed.scheme else "http"
    port = parsed.port
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    normalized = f"{scheme}://{hostname}"
    if port:
        normalized = f"{normalized}:{port}"
    if path and path != "/":
        normalized = f"{normalized}{path}"
    return {
        "input": str(target).strip(),
        "target_type": "url",
        "hostname": hostname,
        "normalized_target": normalized,
        "scheme": scheme,
        "port": port,
        "path": path,
    }


def resolve_target(target):
    target_type = detect_target_type(target)
    base = {
        "input": target,
        "target_type": target_type,
        "hostname": None,
        "normalized_target": None,
        "resolved_ip": None,
        "scheme": None,
        "port": None,
        "path": None,
        "dns_resolution_success": False,
        "error": None,
    }

    if target_type == "url":
        base.update(normalize_url_target(target))
        if not base["hostname"]:
            base["error"] = "URL is missing a hostname"
            return base
        try:
            base["resolved_ip"] = socket.gethostbyname(base["hostname"])
            base["dns_resolution_success"] = True
            return base
        except socket.gaierror as exc:
            base["error"] = str(exc)
            return base

    if target_type == "ip":
        base.update({
            "target_type": "ip",
            "hostname": str(target).strip(),
            "normalized_target": str(target).strip(),
            "resolved_ip": str(target).strip(),
            "dns_resolution_success": True,
        })
        return base

    if target_type == "domain":
        hostname = str(target).strip().lower()
        base.update({
            "hostname": hostname,
            "normalized_target": hostname,
        })
        try:
            base["resolved_ip"] = socket.gethostbyname(hostname)
            base["dns_resolution_success"] = True
            return base
        except socket.gaierror as exc:
            base["error"] = str(exc)
            return base

    base["error"] = "unsupported target"
    return base
