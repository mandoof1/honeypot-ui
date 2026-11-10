"""Command line: audit one protocol of a decoy against a reference daemon.

    python -m tools.fingerprint_audit --decoy 127.0.0.1:42222 \\
        --reference 127.0.0.1:42022 --protocol ssh --out result.json
"""

from __future__ import annotations

import argparse
import sys

from . import PROTOCOLS
from .audit import run_audit, wait_until_listening, write_json, write_markdown
from .net import parse_target
from .probe import Settings


def build_parser() -> argparse.ArgumentParser:
    defaults = Settings()
    parser = argparse.ArgumentParser(
        prog="python -m tools.fingerprint_audit",
        description=(
            "Send the same probes to a decoy and to the real daemon it imitates, "
            "both on loopback, and record every difference."
        ),
    )
    parser.add_argument("--decoy", required=True, metavar="HOST:PORT", help="the decoy's listener (loopback only)")
    parser.add_argument("--reference", required=True, metavar="HOST:PORT", help="the real daemon's listener (loopback only)")
    parser.add_argument("--protocol", required=True, choices=PROTOCOLS)
    parser.add_argument("--out", required=True, metavar="FILE", help="where to write the JSON result")
    parser.add_argument("--markdown", metavar="FILE", help="also write the result as a Markdown table")
    parser.add_argument(
        "--decoy-description", metavar="TEXT",
        help="what the decoy is (engine commit, profile, identity seed); stored in the result",
    )
    parser.add_argument(
        "--reference-description", metavar="TEXT",
        help="what the reference is: package names and versions as the reference itself reports them",
    )
    parser.add_argument("--timeout", type=float, default=defaults.timeout, help="longest wait for one reply, seconds (default %(default)s)")
    parser.add_argument("--delay", type=float, default=defaults.delay, help="least time between two connections, seconds (default %(default)s)")
    parser.add_argument("--quiet", type=float, default=defaults.quiet, help="silence that ends a read with no defined end, seconds (default %(default)s)")
    parser.add_argument("--idle-cap", type=float, default=defaults.idle_cap, help="how long the silent-client SSH probe holds a connection, seconds (default %(default)s)")
    parser.add_argument("--login-attempts", type=int, default=defaults.login_attempts, help="most wrong logins tried per account (default %(default)s)")
    parser.add_argument("--ftp-user", default=defaults.ftp_user, help="account both FTP targets accept (default %(default)s)")
    parser.add_argument("--ftp-password", default=defaults.ftp_password, help="its password (default %(default)s)")
    parser.add_argument("--wait", type=float, default=0.0, metavar="SECONDS", help="first wait up to this long for both targets to listen")
    parser.add_argument("--raw-dir", metavar="DIR", help="also save each raw capture as a file under DIR/decoy and DIR/reference")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        decoy = parse_target(args.decoy)
        reference = parse_target(args.reference)
    except ValueError as exc:
        parser.error(str(exc))

    settings = Settings(
        timeout=args.timeout,
        delay=args.delay,
        quiet=args.quiet,
        idle_cap=args.idle_cap,
        login_attempts=args.login_attempts,
        ftp_user=args.ftp_user,
        ftp_password=args.ftp_password,
    )
    if not args.reference_description:
        print(
            "note: no --reference-description given; the result will not say "
            "which package and version the reference was",
            file=sys.stderr,
        )
    if args.wait > 0:
        try:
            wait_until_listening([decoy, reference], args.wait)
        except TimeoutError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    result = run_audit(
        args.protocol, decoy, reference, settings,
        decoy_description=args.decoy_description,
        reference_description=args.reference_description,
        raw_dir=args.raw_dir,
        progress=lambda message: print(message, file=sys.stderr),
    )
    write_json(args.out, result)
    if args.markdown:
        write_markdown(args.markdown, result)

    summary = result["summary"]
    print(
        f"{args.protocol}: {summary['matches']} of {summary['checks']} checks match, "
        f"{summary['mismatches']} differ; "
        f"{summary['timing_rows_outside_tolerance']} of "
        f"{summary['informational_timing_rows']} timing rows outside tolerance"
    )
    for side in ("decoy", "reference"):
        for group, error in result[side]["probe_errors"].items():
            print(f"  could not run {group} against the {side}: {error}")
    for row in result["checks"]:
        if not row["match"] and not row["informational"]:
            print(f"  differs  {row['id']}  (similarity {row['similarity']:.2f})")
    print(f"result written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
