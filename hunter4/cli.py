"""hunter4 command-line interface.

    hunter4 hunt example.com
    hunter4 hunt https://example.com --provider openai --model gpt-4o-mini
    hunter4 hunt example.com --scope scope.yaml --exclude legacy.example.com
    hunter4 recon example.com
    hunter4 providers
    hunter4 scope example.com

Scope problem solved: you do NOT need scope.yaml/hacktivity.md/policy.md to
start. hunter4 derives scope from the target, takes one explicit
acknowledgement (``--authorized`` or an interactive yes), and enforces the
boundary per request.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__, providers
from .hunt import run_hunt
from .scope import MODES, Scope, normalize_host


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hunter4",
        description="Scope-aware vulnerability hunter driven by AI providers.",
    )
    p.add_argument("--version", action="version", version=f"hunter4 {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def add_common(sp):
        sp.add_argument("target", help="target URL or host (e.g. example.com)")
        sp.add_argument("--provider", default=None, help="AI provider id (default: verboo)")
        sp.add_argument("--model", default=None, help="model id")
        sp.add_argument("--base-url", default=None, help="override provider base URL")
        sp.add_argument("--api-key", default=None, help="override provider API key")
        sp.add_argument("--scope-mode", choices=MODES, default="auto",
                        help="scope mode (default: auto)")
        sp.add_argument("--scope", dest="scope_file", default=None,
                        help="scope file (.yaml or .txt); implies authorization")
        sp.add_argument("--exclude", action="append", default=[], metavar="HOST",
                        help="out-of-scope host/pattern (repeatable)")
        sp.add_argument("--authorized", "-y", action="store_true",
                        help="confirm you are authorized to test the target")
        sp.add_argument("--out", default=None, help="output directory")
        sp.add_argument("--timeout", type=int, default=15, help="per-request seconds")
        sp.add_argument("--ai-timeout", type=int, default=120, help="AI request seconds")
        sp.add_argument("--max-steps", type=int, default=20, help="max AI turns")
        sp.add_argument("--temperature", type=float, default=0.2)
        sp.add_argument("--allow-shell", action="store_true",
                        help="enable the run_command tool (NOT scope-checked)")
        sp.add_argument("--dry-run", action="store_true", help="no network, no writes to targets")
        sp.add_argument("--no-ai", action="store_true", help="deterministic recon only")
        sp.add_argument("-q", "--quiet", action="store_true")

    add_common(sub.add_parser("hunt", help="recon + AI-driven vulnerability hunting"))
    add_common(sub.add_parser("recon", help="deterministic recon only"))

    sub.add_parser("providers", help="list AI providers and models")
    sp_scope = sub.add_parser("scope", help="show the effective scope for a target")
    sp_scope.add_argument("target")
    sp_scope.add_argument("--scope-mode", choices=MODES, default="auto")
    sp_scope.add_argument("--scope", dest="scope_file", default=None)
    sp_scope.add_argument("--exclude", action="append", default=[])
    return p


def _is_authorized(ns) -> bool:
    if ns.scope_file:
        return True
    if ns.authorized:
        return True
    if os.environ.get("HUNTER4_AUTHORIZED", "").lower() in ("1", "true", "yes", "y"):
        return True
    if sys.stdin.isatty():
        host = normalize_host(ns.target)
        try:
            ans = input(
                f"Do you have written authorization to test {host}? [y/N] "
            ).strip().lower()
        except EOFError:
            return False
        return ans in ("y", "yes")
    return False


def _print_providers() -> None:
    print("AI providers (default: verboo)\n")
    for pid in providers.all_ids():
        prov = providers.resolve(pid)
        star = " *" if pid == providers.DEFAULT_PROVIDER else ""
        print(f"  {pid}{star}  — {prov.display_name}  [{prov.kind}]")
        print(f"      base : {prov.resolved_base_url()}")
        print(f"      models: {', '.join(m for m in prov.models if m) or '(set --model)'}")
        key = prov.key()
        state = "set" if key else ("not required" if not prov.requires_key else "MISSING")
        print(f"      key  : {prov.api_key_env} ({state})")
    print("\n  * = default")


def _cmd_scope(ns) -> int:
    scope = Scope.load(
        ns.target,
        mode=ns.scope_mode,
        scope_file=ns.scope_file,
        excludes=ns.exclude,
    )
    print(scope.describe())
    return 0


def _cmd_providers(_ns) -> int:
    _print_providers()
    return 0


def _default_out(target: str) -> Path:
    host = normalize_host(target) or "target"
    return Path.cwd() / "hunter_out" / host


def _run(ns, *, ai: bool) -> int:
    target = ns.target
    host = normalize_host(target)
    if not host:
        print(f"hunter4: could not parse a host from {target!r}", file=sys.stderr)
        return 2

    if not _is_authorized(ns):
        print(
            "hunter4: authorization not confirmed.\n"
            "  This tool sends real requests. Confirm you are authorized with:\n"
            f"    hunter4 hunt {target} --authorized\n"
            "  or provide a scope file:\n"
            f"    hunter4 hunt {target} --scope scope.yaml\n"
            "  (non-interactive runs require --authorized or HUNTER4_AUTHORIZED=1)",
            file=sys.stderr,
        )
        return 3

    scope = Scope.load(
        target,
        mode=ns.scope_mode,
        scope_file=ns.scope_file,
        excludes=ns.exclude,
    )

    provider = None
    if ai and not ns.no_ai:
        try:
            provider = providers.resolve(
                ns.provider, base_url=ns.base_url, api_key=ns.api_key
            )
        except KeyError:
            print(
                f"hunter4: unknown provider {ns.provider!r} "
                f"(known: {', '.join(providers.all_ids())})",
                file=sys.stderr,
            )
            return 2

    out_dir = Path(ns.out).expanduser().resolve() if ns.out else _default_out(target)

    result = run_hunt(
        target=target,
        scope=scope,
        provider=provider,
        model=ns.model or "",
        out_dir=out_dir,
        max_steps=ns.max_steps,
        temperature=ns.temperature,
        timeout=ns.timeout,
        ai_timeout=ns.ai_timeout,
        allow_shell=ns.allow_shell,
        dry_run=ns.dry_run,
        no_ai=(not ai) or ns.no_ai,
        base_url=ns.base_url,
        verbose=not ns.quiet,
    )

    print("\n=== hunter4 summary ===")
    print(f"target   : {result.target}")
    print(f"scope    : {scope.mode}  in={scope.in_scope}  out={scope.out_of_scope or '-'}")
    print(f"requests : {len(result.requests)} allowed, {len(result.denied)} denied by scope")
    print(f"findings : {len(result.findings)}")
    if result.ai_used:
        print(f"ai       : {result.ai_model}  steps={result.steps}")
        if result.usage:
            print("tokens   : " + ", ".join(f"{k}={v}" for k, v in sorted(result.usage.items())))
    print(f"output   : {out_dir}")
    if result.summary:
        print(f"\nAI summary: {result.summary.strip()[:1500]}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ns = _build_parser().parse_args(argv)
    if ns.command == "providers":
        return _cmd_providers(ns)
    if ns.command == "scope":
        return _cmd_scope(ns)
    if ns.command == "recon":
        return _run(ns, ai=False)
    if ns.command == "hunt":
        return _run(ns, ai=True)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
