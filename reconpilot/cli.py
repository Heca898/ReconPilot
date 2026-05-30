import argparse


def parse_args():
    parser = argparse.ArgumentParser(
        description="ReconPilot 1.0: deterministic reconnaissance CLI for target profiling, service inventory, web checks, and vulnerability enrichment."
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="Optional batch-mode target URL, domain, or IP address"
    )

    parser.add_argument(
        "--mode",
        choices=["recon", "web-basic", "version-detect"],
        default="recon",
        help="Deterministic scan profile to run"
    )

    parser.add_argument(
        "--vuln-provider",
        choices=["local", "none", "nvd"],
        default="local",
        help="Offline vulnerability matching provider: local=deterministic test rules, none=disable heuristic matching, nvd=legacy alias"
    )

    parser.add_argument(
        "--vuln-api",
        action="store_true",
        help="Enable external vulnerability API enrichment for discovered services"
    )

    parser.add_argument(
        "--vuln-api-provider",
        choices=["nvd"],
        default="nvd",
        help="External vulnerability API provider to use when --vuln-api is enabled"
    )

    parser.add_argument(
        "--debug-vulns",
        action="store_true",
        help="Print vulnerability provider debug information"
    )

    parser.add_argument(
        "--output",
        help="Write the final readable report to the provided path"
    )

    parser.add_argument(
        "--ports",
        default="top-1000",
        help="Port selection for TCP discovery: top-1000 (default), all, or an explicit comma-separated list such as 22,80,443"
    )

    parser.add_argument(
        "--save-session",
        action="store_true",
        help="Persist a JSON session snapshot for this run"
    )

    parser.add_argument(
        "--session-output",
        help="Write the JSON session snapshot to the provided path when --save-session is enabled"
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=120,
        help="Overall per-command timeout in seconds for bounded recon steps"
    )

    parser.add_argument(
        "--debug-web",
        action="store_true",
        help="Print bounded web-analysis evidence details during runtime"
    )

    parser.add_argument(
        "--render-web",
        action="store_true",
        help="Optionally use a headless browser for rendered DOM text extraction when Playwright is available"
    )

    return parser.parse_args()
