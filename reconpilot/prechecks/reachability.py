import platform
import shutil
import subprocess

from reconpilot.engine.executor import normalize_command_output


def ping_target(target):
    ping_path = shutil.which("ping")

    if not ping_path:
        return {
            "ping_available": False,
            "icmp_reachable": None,
            "command": [],
            "returncode": -1,
            "stdout": "",
            "stderr": "",
            "success": False,
            "error": "ping is not installed or not found in PATH",
        }

    system_name = platform.system().lower()

    if system_name == "windows":
        command = [ping_path, "-n", "1", "-w", "1000", target]
    else:
        command = [ping_path, "-c", "1", "-W", "1", target]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5
        )

        return {
            "ping_available": True,
            "icmp_reachable": result.returncode == 0,
            "command": command,
            "returncode": result.returncode,
            "stdout": normalize_command_output(result.stdout),
            "stderr": normalize_command_output(result.stderr),
            "success": result.returncode == 0,
            "error": None if result.returncode == 0 else "target did not respond to ICMP ping",
        }

    except subprocess.TimeoutExpired as exc:
        return {
            "ping_available": True,
            "icmp_reachable": False,
            "command": command,
            "returncode": 124,
            "stdout": normalize_command_output(exc.stdout),
            "stderr": normalize_command_output(exc.stderr) or "ping request timed out",
            "success": False,
            "error": "ping request timed out",
        }
    except Exception as exc:
        return {
            "ping_available": True,
            "icmp_reachable": None,
            "command": command,
            "returncode": -1,
            "stdout": "",
            "stderr": str(exc),
            "success": False,
            "error": f"unexpected error: {exc}",
        }
