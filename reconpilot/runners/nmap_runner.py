import shutil
import subprocess
import time

from reconpilot.engine.executor import normalize_command_output


DEFAULT_NMAP_TIMEOUT = 120


def _build_discovery_flags(mode, ports):
    if mode == "web-basic":
        return ["-p", "80,443,8000,8080,8443"], "web_focused_tcp"
    normalized_ports = str(ports or "top-1000").strip().lower()
    if normalized_ports == "all":
        return ["-p-"], "full_tcp"
    if normalized_ports == "top-1000":
        return ["--top-ports", "1000"], "basic_tcp"
    return ["-p", str(ports)], "custom_tcp"


def build_nmap_command(target, mode="recon", icmp_reachable=None, open_ports=None, version_detection=False, ports="top-1000", scripts=None):
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        return None

    flags = ["-T4"]
    if icmp_reachable is False:
        flags.append("-Pn")

    if scripts and open_ports:
        flags.extend(["-sV", "-p", ",".join(str(port) for port in open_ports), "--script", ",".join(scripts)])
        scan_type = "web_evidence"
    elif version_detection:
        if not open_ports:
            return None
        flags.extend(["-sV", "-p", ",".join(str(port) for port in open_ports)])
        scan_type = "version_detection_followup"
    else:
        discovery_flags, scan_type = _build_discovery_flags(mode, ports)
        flags.extend(discovery_flags)

    command = [nmap_path] + flags + [target]
    scan_context = {
        "tool": "nmap",
        "command": command,
        "target": target,
        "scan_type": scan_type,
        "flags": flags,
        "version_detection": "-sV" in flags,
        "udp_scan": "-sU" in flags,
        "os_detection": "-O" in flags,
        "used_ping_based_discovery": icmp_reachable is True,
        "used_skip_host_discovery": "-Pn" in flags,
        "open_ports": list(open_ports or []),
        "ports": ports,
        "scripts": list(scripts or []),
    }
    return command, scan_context


def run_nmap_scan(target, mode="recon", icmp_reachable=None, timeout=DEFAULT_NMAP_TIMEOUT, open_ports=None, version_detection=False, ports="top-1000", scripts=None):
    built = build_nmap_command(
        target,
        mode=mode,
        icmp_reachable=icmp_reachable,
        open_ports=open_ports,
        version_detection=version_detection,
        ports=ports,
        scripts=scripts,
    )
    if not built:
        return {
            "success": False,
            "stdout": "",
            "stderr": "nmap is not installed or not found in PATH",
            "returncode": None,
            "command": None,
            "scan_context": None,
            "duration_seconds": None,
            "timeout_seconds": timeout,
            "timed_out": False,
        }

    command, scan_context = built
    started_at = time.perf_counter()
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        duration_seconds = time.perf_counter() - started_at
        return {
            "success": result.returncode == 0,
            "stdout": normalize_command_output(result.stdout),
            "stderr": normalize_command_output(result.stderr),
            "returncode": result.returncode,
            "command": command,
            "scan_context": scan_context,
            "duration_seconds": duration_seconds,
            "timeout_seconds": timeout,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        duration_seconds = time.perf_counter() - started_at
        return {
            "success": False,
            "stdout": normalize_command_output(exc.stdout),
            "stderr": f"nmap scan timed out after {timeout} seconds",
            "returncode": None,
            "command": command,
            "scan_context": scan_context,
            "duration_seconds": duration_seconds,
            "timeout_seconds": timeout,
            "timed_out": True,
        }
    except Exception as exc:
        duration_seconds = time.perf_counter() - started_at
        return {
            "success": False,
            "stdout": "",
            "stderr": f"unexpected error: {exc}",
            "returncode": None,
            "command": command,
            "scan_context": scan_context,
            "duration_seconds": duration_seconds,
            "timeout_seconds": timeout,
            "timed_out": False,
        }
