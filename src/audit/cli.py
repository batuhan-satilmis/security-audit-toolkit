"""Command-line entry point.

    audit-toolkit run --config audit.yaml --out report.md
    audit-toolkit list-checks
    audit-toolkit show-check <id>
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from audit.checks.aws_iam import CHECKS as AWS_IAM_CHECKS
from audit.checks.base import Check
from audit.checks.m365 import CHECKS as M365_CHECKS
from audit.findings import Finding
from audit.report import render_json, render_markdown

# Module registry. Add a module by adding to this dict.
ALL_MODULES: dict[str, list[Check]] = {
    "m365": M365_CHECKS,
    "aws_iam": AWS_IAM_CHECKS,
    # "supabase": SUPABASE_CHECKS,    # populated when supabase module is enabled
}


def cmd_list_checks(_args: argparse.Namespace) -> int:
    for module_name, checks in ALL_MODULES.items():
        print(f"[{module_name}]")
        for check in checks:
            print(f"  {check.check_id:<40} {check.title}")
    return 0


def cmd_show_check(args: argparse.Namespace) -> int:
    for checks in ALL_MODULES.values():
        for check in checks:
            if check.check_id == args.check_id:
                print(f"{check.check_id}\n{'=' * len(check.check_id)}")
                print(f"\n{check.title}\n")
                print(check.description)
                return 0
    print(f"Check '{args.check_id}' not found.", file=sys.stderr)
    return 1


def cmd_run(args: argparse.Namespace) -> int:
    # In a full implementation we'd parse audit.yaml and pull live config via
    # boto3 / Microsoft Graph / Supabase API. For this scaffold we run against
    # fixtures so the CLI is verifiable end-to-end.
    from audit.fixtures import sample_aws_context, sample_m365_context

    module_contexts = {
        "m365": sample_m365_context(),
        "aws_iam": sample_aws_context(),
    }
    findings: list[Finding] = []
    for module_name, checks in ALL_MODULES.items():
        ctx = module_contexts.get(module_name)
        if ctx is None:
            continue
        for check in checks:
            findings.extend(check.evaluate(ctx))

    if args.format == "json":
        out = render_json(findings)
    else:
        out = render_markdown(findings, include_passing=args.include_passing)

    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"Report written to {args.out}", file=sys.stderr)
    else:
        print(out)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="audit-toolkit")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list-checks", help="List every registered check.")
    p_list.set_defaults(func=cmd_list_checks)

    p_show = sub.add_parser("show-check", help="Show the description of a single check.")
    p_show.add_argument("check_id")
    p_show.set_defaults(func=cmd_show_check)

    p_run = sub.add_parser("run", help="Run all enabled checks and produce a report.")
    p_run.add_argument("--config", default="audit.yaml")
    p_run.add_argument("--out", default=None)
    p_run.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p_run.add_argument("--include-passing", action="store_true")
    p_run.set_defaults(func=cmd_run)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
