import sys
from types import SimpleNamespace

from reconpilot.orchestrator import run_pipeline
from reconpilot.reporting import build_recon_report, print_recon_report, print_runtime_summary, save_recon_report, write_output_report
from reconpilot.session_store import display_output_path, prune_empty_output_dirs, save_state_snapshot
from reconpilot.state import create_session_state


def _build_run_args(
    target,
    mode,
    vuln_provider="local",
    vuln_api=False,
    vuln_api_provider="nvd",
    debug_vulns=False,
    output=None,
    timeout=120,
    ports="top-1000",
    save_session=False,
    session_output=None,
    debug_web=False,
    render_web=False,
):
    return SimpleNamespace(
        target=target,
        mode=mode,
        vuln_provider=vuln_provider,
        vuln_api=vuln_api,
        vuln_api_provider=vuln_api_provider,
        debug_vulns=debug_vulns,
        output=output,
        timeout=timeout,
        ports=ports,
        save_session=save_session,
        session_output=session_output,
        debug_web=debug_web,
        render_web=render_web,
    )


def _run_recon(
    target,
    mode,
    vuln_provider="local",
    vuln_api=False,
    vuln_api_provider="nvd",
    debug_vulns=False,
    output=None,
    timeout=120,
    ports="top-1000",
    save_session=False,
    session_output=None,
    debug_web=False,
    render_web=False,
):
    state = create_session_state(
        _build_run_args(
            target,
            mode,
            vuln_provider=vuln_provider,
            vuln_api=vuln_api,
            vuln_api_provider=vuln_api_provider,
            debug_vulns=debug_vulns,
            output=output,
            timeout=timeout,
            ports=ports,
            save_session=save_session,
            session_output=session_output,
            debug_web=debug_web,
            render_web=render_web,
        )
    )
    state, session_path = run_pipeline(state)
    print_runtime_summary(state, session_path=session_path)
    if output:
        report = build_recon_report(state)
        path, error = write_output_report(report, output)
        if path:
            print(f"[SUMMARY] output: {path}")
        else:
            print(f"[REPORT] output write failed: {error}")
    prune_empty_output_dirs()
    return state, session_path


def _print_menu():
    print()
    print("ReconPilot")
    print("1. Run recon")
    print("2. Show last summary")
    print("3. Generate report")
    print("4. Exit")


def _prompt_target():
    while True:
        target = input("Target: ").strip()
        if target:
            return target
        print("Enter a target IP or domain.")


def _show_last_summary(last_state, last_session_path):
    if last_state is None:
        print("[SUMMARY] no completed recon is available")
        return
    print_runtime_summary(last_state, session_path=last_session_path)


def _generate_report(last_state, last_session_path):
    if last_state is None:
        print("[REPORT] no completed recon is available")
        return None

    report = build_recon_report(last_state)
    report_paths = save_recon_report(last_state, report)
    session_path = save_state_snapshot(last_state)
    print_recon_report(report, report_paths)
    print(f"[SUMMARY] session: {display_output_path(session_path)}")
    return report_paths


def run_interactive_session(
    mode,
    vuln_provider="local",
    vuln_api=False,
    vuln_api_provider="nvd",
    debug_vulns=False,
    output=None,
    timeout=120,
    ports="top-1000",
    save_session=False,
    session_output=None,
    debug_web=False,
    render_web=False,
):
    last_state = None
    last_session_path = None

    while True:
        _print_menu()
        choice = input("Choose [1/2/3/4]: ").strip()

        if choice == "1":
            print()
            target = _prompt_target()
            print()
            last_state, last_session_path = _run_recon(
                target,
                mode,
                vuln_provider=vuln_provider,
                vuln_api=vuln_api,
                vuln_api_provider=vuln_api_provider,
                debug_vulns=debug_vulns,
                output=output,
                timeout=timeout,
                ports=ports,
                save_session=save_session,
                session_output=session_output,
                debug_web=debug_web,
                render_web=render_web,
            )
            continue

        if choice == "2":
            print()
            _show_last_summary(last_state, last_session_path)
            continue

        if choice == "3":
            print()
            _generate_report(last_state, last_session_path)
            continue

        if choice == "4":
            print("[EXIT] clean termination")
            return last_state

        print("Choose 1, 2, 3, or 4.")


def run_batch_session(args):
    kwargs = {
        "vuln_provider": getattr(args, "vuln_provider", "local"),
        "vuln_api": bool(getattr(args, "vuln_api", False)),
        "vuln_api_provider": getattr(args, "vuln_api_provider", "nvd"),
        "debug_vulns": bool(getattr(args, "debug_vulns", False)),
    }
    if hasattr(args, "output"):
        kwargs["output"] = getattr(args, "output")
    if hasattr(args, "timeout"):
        kwargs["timeout"] = getattr(args, "timeout")
    if hasattr(args, "ports"):
        kwargs["ports"] = getattr(args, "ports")
    if hasattr(args, "save_session"):
        kwargs["save_session"] = bool(getattr(args, "save_session"))
    if hasattr(args, "session_output"):
        kwargs["session_output"] = getattr(args, "session_output")
    if hasattr(args, "debug_web"):
        kwargs["debug_web"] = bool(getattr(args, "debug_web"))
    if hasattr(args, "render_web"):
        kwargs["render_web"] = bool(getattr(args, "render_web"))
    state, session_path = _run_recon(args.target, args.mode, **kwargs)
    print("[EXIT] clean termination")
    return state, session_path


def run_session(args):
    if args.target:
        state, _ = run_batch_session(args)
        return state
    if not sys.stdin.isatty():
        print("[INFO] no target supplied. Provide TARGET for batch mode, or run in a TTY for interactive mode.")
        return None
    print("[INFO] no target supplied; starting interactive mode. Provide TARGET for batch mode.")
    return run_interactive_session(
        args.mode,
        vuln_provider=getattr(args, "vuln_provider", "local"),
        vuln_api=bool(getattr(args, "vuln_api", False)),
        vuln_api_provider=getattr(args, "vuln_api_provider", "nvd"),
        debug_vulns=bool(getattr(args, "debug_vulns", False)),
        output=getattr(args, "output", None),
        timeout=getattr(args, "timeout", 120),
        ports=getattr(args, "ports", "top-1000"),
        save_session=bool(getattr(args, "save_session", False)),
        session_output=getattr(args, "session_output", None),
        debug_web=bool(getattr(args, "debug_web", False)),
        render_web=bool(getattr(args, "render_web", False)),
    )
