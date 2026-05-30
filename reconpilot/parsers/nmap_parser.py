import re


def _coerce_output_text(output):
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode("utf-8", errors="replace")
    if isinstance(output, str):
        return output
    return str(output)


def _parse_service_tail(tail):
    normalized_tail = (tail or "").strip()
    if not normalized_tail:
        return {
            "product": None,
            "version": None,
            "extra_info": None,
            "detection_source": "nmap_port_label",
            "confidence": "medium",
        }

    versioned_match = re.match(r"^(?P<product>.+?)\s+(?P<version>\d[^\s]*)\s*(?P<extra>.*)$", normalized_tail)
    if versioned_match:
        return {
            "product": versioned_match.group("product").strip() or None,
            "version": versioned_match.group("version").strip() or None,
            "extra_info": versioned_match.group("extra").strip() or None,
            "detection_source": "nmap_service_probe",
            "confidence": "high",
        }

    return {
        "product": normalized_tail,
        "version": None,
        "extra_info": None,
        "detection_source": "nmap_service_probe",
        "confidence": "medium",
    }


def _get_script_evidence(entry):
    return entry.setdefault("script_evidence", {})


def _parse_nmap_script_line(entry, normalized):
    evidence = _get_script_evidence(entry)
    cleaned = normalized.lstrip("|_ ").strip()
    lowered = cleaned.lower()

    if lowered.startswith("http-title:"):
        value = cleaned.split(":", 1)[1].strip()
        if value:
            evidence["http_title"] = value
        return
    if lowered.startswith("ssl-cert:"):
        cleaned = cleaned.split(":", 1)[1].strip()
        lowered = cleaned.lower()
    if lowered.startswith("requested resource was"):
        parts = cleaned.split("was", 1)
        if len(parts) == 2:
            evidence["requested_resource"] = parts[1].strip()
        return
    if lowered.startswith("http-server-header:"):
        value = cleaned.split(":", 1)[1].strip()
        if value:
            evidence["http_server_header"] = value
        return
    if lowered.startswith("supported methods:"):
        value = cleaned.split(":", 1)[1].strip()
        if value:
            evidence["http_methods"] = [item for item in value.split() if item]
        return
    if lowered.startswith("subject alternative name:"):
        value = cleaned.split(":", 1)[1].strip()
        if value:
            evidence["ssl_cert_san"] = value
        return
    if lowered.startswith("subject:"):
        value = cleaned.split(":", 1)[1].strip()
        if value:
            evidence["ssl_cert_subject"] = value
        return
    if lowered.startswith("issuer:"):
        value = cleaned.split(":", 1)[1].strip()
        if value:
            evidence["ssl_cert_issuer"] = value
        return


def parse_nmap_output(output):
    output = _coerce_output_text(output)
    host_up = False
    open_ports = []
    port_pattern = re.compile(r"^(\d+)\/(tcp|udp)\s+(open|closed|filtered)\s+([^\s]+)(?:\s+(.*))?$", re.IGNORECASE)
    cpe_pattern = re.compile(r"cpe:\s*(cpe:[^\s,]+)", re.IGNORECASE)
    last_open_index = None

    for line in output.splitlines():
        raw_line = line.rstrip()
        normalized = raw_line.strip()
        if "Host is up" in normalized:
            host_up = True

        match = port_pattern.match(normalized)
        if match:
            port = int(match.group(1))
            protocol = match.group(2).lower()
            state = match.group(3).lower()
            service = match.group(4).lower()
            service_details = _parse_service_tail(match.group(5))
            if state == "open":
                open_ports.append({
                    "port": port,
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                    "product": service_details["product"],
                    "version": service_details["version"],
                    "extra_info": service_details["extra_info"],
                    "raw_evidence": raw_line,
                    "detection_source": service_details["detection_source"],
                    "confidence": service_details["confidence"],
                })
                last_open_index = len(open_ports) - 1
            continue

        if raw_line.lstrip().startswith("|") and last_open_index is not None:
            _parse_nmap_script_line(open_ports[last_open_index], normalized)
            cpe_match = cpe_pattern.search(normalized)
            if cpe_match and not open_ports[last_open_index].get("cpe"):
                open_ports[last_open_index]["cpe"] = cpe_match.group(1)

    return {
        "host_up": host_up,
        "open_ports": open_ports,
        "scan_summary": {"total_open_ports": len(open_ports)},
    }
