import shutil
import subprocess


def normalize_command_output(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value
    return str(value)


def _looks_like_usage_output(text):
    lowered = (text or "").strip().lower()
    if not lowered:
        return False

    markers = [
        "usage:",
        "options:",
        "show this help",
        "display help",
    ]
    return any(marker in lowered for marker in markers)


def check_tool_available(tool_name):
    return shutil.which(tool_name) is not None


def execute_command(command, timeout=None):
    execution_result = {
        "command": list(command),
        "returncode": -1,
        "stdout": "",
        "stderr": "",
        "success": False,
    }

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
        execution_result["returncode"] = result.returncode
        execution_result["stdout"] = normalize_command_output(result.stdout)
        execution_result["stderr"] = normalize_command_output(result.stderr)
        execution_result["success"] = result.returncode == 0
        return execution_result
    except subprocess.TimeoutExpired as exc:
        execution_result["returncode"] = 124
        execution_result["stdout"] = normalize_command_output(exc.stdout)
        timeout_message = f"command timed out after {timeout} seconds"
        normalized_stderr = normalize_command_output(exc.stderr)
        if normalized_stderr:
            execution_result["stderr"] = f"{normalized_stderr}\n{timeout_message}".strip()
        else:
            execution_result["stderr"] = timeout_message
        return execution_result
    except OSError as exc:
        execution_result["stderr"] = str(exc)
        return execution_result


def evaluate_command_result(command, returncode, stdout, stderr):
    normalized_stdout = normalize_command_output(stdout)
    normalized_stderr = normalize_command_output(stderr)
    output_text = (normalized_stdout.strip() + "\n" + normalized_stderr.strip()).strip()
    timed_out = returncode == 124 and "timed out" in normalized_stderr.lower()

    if timed_out:
        return {
            "success": False,
            "timed_out": True,
            "useful_output": False,
            "reason": "timeout",
        }

    if returncode != 0:
        return {
            "success": False,
            "timed_out": False,
            "useful_output": False,
            "reason": "non_zero_exit",
        }

    if not output_text:
        return {
            "success": True,
            "timed_out": False,
            "useful_output": False,
            "reason": "empty_output",
        }

    if _looks_like_usage_output(output_text):
        return {
            "success": True,
            "timed_out": False,
            "useful_output": False,
            "reason": "help_or_usage_output",
        }

    return {
        "success": True,
        "timed_out": False,
        "useful_output": True,
        "reason": "useful_output",
    }
