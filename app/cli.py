"""
Linux Security Auditor — command line interface.

Usage:
    lsa run                       Start the dashboard and open it in your browser
    lsa run --port 8080           Start on a specific port
    lsa run --no-browser          Don't auto-open the browser
    lsa scan                      Run a full audit in the terminal
    lsa scan --json               Output the raw JSON report
    lsa scan --save report.json   Save the JSON report to a file
    lsa --version                 Show version
"""

import argparse
import json
import socket
import sys
import threading
import time
import webbrowser
from datetime import datetime

__version__ = "1.0.0"

# ANSI colors (disabled automatically when output is piped)
USE_COLOR = sys.stdout.isatty()


def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else str(text)


def _bold(t):    return _c("1", t)
def _dim(t):     return _c("2", t)
def _green(t):   return _c("32", t)
def _yellow(t):  return _c("33", t)
def _red(t):     return _c("31", t)
def _blue(t):    return _c("34", t)
def _magenta(t): return _c("35", t)
def _cyan(t):    return _c("36", t)


# ------------------------------------------------------------------ run ----

def cmd_run(args):
    """Start the dashboard server and open the default browser."""
    from app import create_app

    host = "127.0.0.1"
    url = f"http://{host}:{args.port}"

    print()
    print(f"  {_bold('🛡️  Linux Security Auditor')} {_dim(f'v{__version__}')}")
    print(f"  {_cyan('Dashboard:')} {_bold(url)}")
    print(f"  {_dim('Press Ctrl+C to stop.')}")
    print()

    app = create_app()
    app.config["DEBUG"] = False

    # Open the browser shortly after the server starts listening
    if not args.no_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()

    # werkzeug is Flask's built-in server
    from werkzeug.serving import run_simple
    try:
        run_simple(host, args.port, app, use_reloader=False, use_debugger=False)
    except KeyboardInterrupt:
        print(f"\n  {_dim('Dashboard stopped.')}")
    except OSError as e:
        if "Address already in use" in str(e) or errno_like(e):
            print(f"  {_red(f'Port {args.port} is already in use.')} "
                  f"Try: {_bold(f'lsa run --port {args.port + 1}')}")
            sys.exit(1)
        raise


def errno_like(e):
    return getattr(e, "errno", None) == 98  # EADDRINUSE on Linux


# ----------------------------------------------------------------- scan ----

STATUS_STYLE = {
    "PASS":     (_green,  "✓"),
    "WARNING":  (_yellow, "▲"),
    "FAIL":     (_red,    "✗"),
    "CRITICAL": (_red,    "✗"),
    "INFO":     (_blue,   "ℹ"),
    "UNKNOWN":  (_dim,    "•"),
}


def _collect_all_checks():
    """System overview + every security check, using the shared runner."""
    from app.scanner import get_system_scanner, run_all_checks
    checks = [get_system_scanner()()]
    checks += run_all_checks()
    return checks


def cmd_scan(args):
    """Run a full audit in the terminal."""
    from app.scanner import calculate_security_score

    if args.json or args.save:
        checks = _collect_all_checks()
        summary = calculate_security_score(checks)
        payload = {
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "hostname": socket.gethostname(),
            "summary": summary,
            "checks": checks,
        }
        text = json.dumps(payload, indent=2, default=str)
        if args.save:
            with open(args.save, "w", encoding="utf-8") as f:
                f.write(text)
            print(f"{_green('Report saved to')} {_bold(args.save)}")
        if args.json:
            print(text)
        return

    print()
    print(f"  {_bold('🛡️  Linux Security Auditor')} {_dim('— full audit')}")
    print(f"  {_dim('Host:')} {socket.gethostname()}   {_dim('Date:')} {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print()

    checks = _collect_all_checks()

    worst = []
    for chk in checks:
        status = chk.get("status", "UNKNOWN")
        color, icon = STATUS_STYLE.get(status, (_dim, "•"))
        score = chk.get("score", 0)
        max_score = chk.get("max_score", 10)
        name = chk.get("name", "?")
        summary = (chk.get("summary") or "").strip()

        print(f"  {color(icon)} {color(f'{status:8}')} {_bold(name)} {_dim(f'{score}/{max_score}')}")
        if summary:
            print(f"      {summary}")
        reco = (chk.get("recommendation") or "").strip()
        if status in ("WARNING", "FAIL", "CRITICAL") and reco:
            print(f"      {_cyan('→')} {reco}")
        print()

        if status in ("WARNING", "FAIL", "CRITICAL"):
            order = {"CRITICAL": 0, "FAIL": 0, "WARNING": 1}
            worst.append((order.get(status, 2), score / max(max_score or 10, 1), name))

    result = calculate_security_score(checks)
    score, rating = result["score"], result["rating"]
    counts = result.get("checks", {})
    bar_len = 30
    filled = round(score / 100 * bar_len)
    bar = "█" * filled + "░" * (bar_len - filled)
    score_color = _green if score >= 90 else (_blue if score >= 75 else (_yellow if score >= 50 else _red))

    print(f"  {_bold('═══ Security Score ═══')}")
    print(f"  {score_color(f'{score}/100')}  {_bold(rating)}")
    print(f"  {score_color(bar)}")
    print(f"  {_green('✓ PASS')} {counts.get('pass', 0)}   {_yellow('▲ WARNING')} {counts.get('warning', 0)}   {_red('✗ CRITICAL')} {counts.get('critical', 0)}")
    print()

    if worst:
        worst.sort()
        print(f"  {_bold('Fix these first:')}")
        for _, _, name in worst[:3]:
            print(f"    {_red('→')} {name}")
        print()


# ----------------------------------------------------------------- main ----

def build_parser():
    parser = argparse.ArgumentParser(
        prog="lsa",
        description="Linux Security Auditor — audit your system from the terminal or a web dashboard.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="command")

    p_run = sub.add_parser("run", help="Start the web dashboard and open it in your browser")
    p_run.add_argument("--port", type=int, default=5000, help="Port to listen on (default: 5000)")
    p_run.add_argument("--no-browser", action="store_true", help="Do not auto-open the browser")
    p_run.set_defaults(func=cmd_run)

    p_scan = sub.add_parser("scan", help="Run a full security audit in the terminal")
    p_scan.add_argument("--json", action="store_true", help="Print the raw JSON report")
    p_scan.add_argument("--save", metavar="FILE", help="Save the JSON report to a file")
    p_scan.set_defaults(func=cmd_scan)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not getattr(args, "func", None):
        # No subcommand — default to the dashboard, like `lsa run`
        args.func = cmd_run
        args.port = 5000
        args.no_browser = False

    args.func(args)


if __name__ == "__main__":
    main()
