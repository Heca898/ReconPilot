from reconpilot.modules.dns import run_dns_module
from reconpilot.modules.ftp import run_ftp_module
from reconpilot.modules.generic import run_generic_service_module
from reconpilot.modules.http import run_http_module
from reconpilot.modules.smb import run_smb_module
from reconpilot.modules.smtp import run_smtp_module
from reconpilot.modules.ssh import run_ssh_module


WEB_SERVICES = {"http", "https", "ssl/http", "http-proxy", "https-alt"}


def is_web_service(service_name, port=None):
    normalized = (service_name or "").lower()
    return normalized in WEB_SERVICES or int(port or 0) in {80, 81, 443, 591, 8000, 8008, 8080, 8081, 8443, 8888}


def select_module_for_service(service_name, port=None):
    normalized = (service_name or "").lower()
    if is_web_service(normalized, port):
        return "http"
    if normalized in {"microsoft-ds", "netbios-ssn", "smb"}:
        return "smb"
    if normalized == "ftp":
        return "ftp"
    if normalized == "ssh":
        return "ssh"
    if normalized in {"domain", "domain?"} or int(port or 0) == 53:
        return "dns"
    if normalized == "smtp" or int(port or 0) in {25, 465, 587, 2525}:
        return "smtp"
    return "generic"


def run_service_module(state, service_target):
    module_name = service_target.get("module")
    if module_name == "http":
        return run_http_module(state, service_target)
    if module_name == "ftp":
        return run_ftp_module(state, service_target)
    if module_name == "smb":
        return run_smb_module(state, service_target)
    if module_name == "ssh":
        return run_ssh_module(state, service_target)
    if module_name == "dns":
        return run_dns_module(state, service_target)
    if module_name == "smtp":
        return run_smtp_module(state, service_target)
    return run_generic_service_module(state, service_target)
