"""Hunt orchestration: deterministic recon -> AI tool loop -> reports.

Deterministic recon always runs (no API key needed). The AI loop is layered on
top when a provider is configured, and uses the same scope-enforcing toolbox.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from . import client
from .prompts import build_system_prompt, build_user_prompt
from .providers import Provider
from .scope import Scope, normalize_host
from .tools import FindingsStore, ToolBox

_LINK_RE = re.compile(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_JS_URL_RE = re.compile(r'["\'](/[A-Za-z0-9_\-./?=&%#:]+)["\']')
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

_SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "access-control-allow-origin",
)


@dataclass
class HuntResult:
    target: str
    base_url: str
    recon: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    ai_used: bool = False
    ai_model: str | None = None
    steps: int = 0
    usage: dict = field(default_factory=dict)
    out_dir: Path | None = None
    requests: list = field(default_factory=list)
    denied: list = field(default_factory=list)
    summary: str = ""


def _resolve_base(target: str, toolbox: ToolBox) -> tuple[str, dict, str]:
    """Try https then http; return (base_url, meta, body).

    Preserves an explicit scheme and port from the target, so
    ``127.0.0.1:8765`` works as well as ``https://example.com``.
    """
    raw = (target or "").strip().rstrip("/")
    if not raw:
        raise ValueError(f"could not parse a host from {target!r}")
    if not normalize_host(raw):
        raise ValueError(f"could not parse a host from {target!r}")
    if raw.startswith(("http://", "https://")):
        candidates = [raw]
    else:
        candidates = [f"https://{raw}", f"http://{raw}"]
    for base in candidates:
        meta, body = toolbox.fetch(base)
        if meta.get("status") is not None and not meta.get("scope_denied"):
            return base, meta, body
    return candidates[0], {}, ""


def recon(target: str, scope: Scope, toolbox: ToolBox) -> dict:
    base, meta, body = _resolve_base(target, toolbox)

    headers = {k.lower(): v for k, v in (meta.get("headers") or {}).items()}
    sec = {name: headers.get(name, "MISSING") for name in _SECURITY_HEADERS}

    title = ""
    m = _TITLE_RE.search(body or "")
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]

    endpoints: set[str] = set()
    scripts: set[str] = set()
    forms: list[dict] = []
    for raw in _LINK_RE.findall(body or ""):
        full = urljoin(base + "/", raw.strip())
        if not full.startswith(("http://", "https://")):
            continue
        allowed, _ = scope.allows(full)
        if not allowed:
            continue
        if full.lower().endswith((".js", ".mjs")):
            scripts.add(full)
        else:
            endpoints.add(full)
    for raw in _JS_URL_RE.findall(body or ""):
        full = urljoin(base + "/", raw.strip())
        allowed, _ = scope.allows(full)
        if allowed:
            endpoints.add(full)
    for fm in re.finditer(r"<form[^>]*>", body or "", re.IGNORECASE):
        tag = fm.group(0)
        action = re.search(r'action\s*=\s*["\']([^"\']*)["\']', tag, re.IGNORECASE)
        method = re.search(r'method\s*=\s*["\']([^"\']*)["\']', tag, re.IGNORECASE)
        forms.append(
            {
                "action": urljoin(base + "/", (action.group(1) if action else "")),
                "method": (method.group(1).upper() if method else "GET"),
            }
        )

    params: set[str] = set()
    for url in list(endpoints):
        query = urlsplit(url).query
        for pair in query.split("&"):
            if "=" in pair:
                params.add(pair.split("=", 1)[0])

    tech: list[str] = []
    for h in ("server", "x-powered-by", "x-generator"):
        if headers.get(h):
            tech.append(f"{h}: {headers[h]}")
    if headers.get("set-cookie"):
        tech.append("cookies present")

    return {
        "target": target,
        "base_url": base,
        "status": meta.get("status"),
        "final_url": meta.get("url"),
        "title": title,
        "server": headers.get("server", ""),
        "content_type": headers.get("content-type", ""),
        "security_headers": sec,
        "tech_hints": tech,
        "endpoints": sorted(endpoints)[:200],
        "scripts": sorted(scripts)[:100],
        "forms": forms[:50],
        "parameters": sorted(params)[:100],
        "scope": scope.to_dict(),
    }


def _ai_loop(
    *,
    provider: Provider,
    model: str,
    target: str,
    recon_data: dict,
    scope: Scope,
    toolbox: ToolBox,
    max_steps: int,
    temperature: float,
    timeout: int,
    base_url: str | None,
    verbose: bool,
) -> tuple[int, dict, str]:
    messages: list[dict] = [
        {"role": "system", "content": build_system_prompt(scope)},
        {"role": "user", "content": build_user_prompt(target, recon_data)},
    ]
    tools = toolbox.schemas()
    usage_total: dict = {}
    step = 0
    summary = ""
    for step in range(1, max_steps + 1):
        try:
            res = client.chat(
                provider,
                model,
                messages,
                tools=tools,
                temperature=temperature,
                timeout=timeout,
                base_url=base_url,
            )
        except client.ProviderError as e:
            print(f"[ai] provider error: {e}")
            if e.body:
                print(f"[ai] {e.body[:500]}")
            break
        for k, v in (res.usage or {}).items():
            if isinstance(v, int):
                usage_total[k] = usage_total.get(k, 0) + v
        if res.content and verbose:
            print(f"\n[ai] {res.content.strip()}")

        if not res.tool_calls:
            summary = res.content
            break
        messages.append(
            {"role": "assistant", "content": res.content, "tool_calls": res.tool_calls}
        )
        for call in res.tool_calls:
            name = call["name"]
            args = call.get("arguments") or {}
            out = toolbox.dispatch(name, args)
            if verbose:
                preview = json.dumps(args, ensure_ascii=False)
                if len(preview) > 300:
                    preview = preview[:300] + "..."
                print(f"  -> {name} {preview}")
                shown = out if len(out) <= 1200 else out[:1200] + "...[truncated]"
                print(f"     {shown}")
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call["id"],
                    "name": name,
                    "content": out,
                }
            )
        if toolbox.finished:
            summary = toolbox.summary
            break
    else:
        summary = "(max steps reached)"
    return step, usage_total, summary


def _write_recon(path: Path, target: str, scope: Scope, data: dict, toolbox: ToolBox) -> None:
    lines = [
        f"# RECON — {target}",
        "",
        "## Scope",
        "",
        "```",
        scope.describe(),
        "```",
        "",
        "## Summary",
        "",
        "```json",
        json.dumps(data, indent=2),
        "```",
        "",
        "## Requests",
        "",
    ]
    if toolbox.requests:
        for r in toolbox.requests:
            lines.append(f"- `{r['url']}` — {r['reason']}")
    else:
        lines.append("_none_")
    lines += ["", "## Scope-denied (skipped)", ""]
    if toolbox.denied:
        for r in toolbox.denied:
            lines.append(f"- `{r['url']}` — {r['reason']}")
    else:
        lines.append("_none_")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def run_hunt(
    *,
    target: str,
    scope: Scope,
    provider: Provider | None,
    model: str = "",
    out_dir: Path,
    max_steps: int = 20,
    temperature: float = 0.2,
    timeout: int = 15,
    ai_timeout: int = 120,
    allow_shell: bool = False,
    dry_run: bool = False,
    no_ai: bool = False,
    base_url: str | None = None,
    verbose: bool = True,
) -> HuntResult:
    out_dir.mkdir(parents=True, exist_ok=True)
    findings = FindingsStore(out_dir)
    toolbox = ToolBox(
        scope=scope,
        findings=findings,
        timeout=timeout,
        allow_shell=allow_shell,
        dry_run=dry_run,
    )

    if verbose:
        print(f"[scope] {scope.mode}  in={scope.in_scope}  out={scope.out_of_scope or '-'}")
    recon_data = recon(target, scope, toolbox)
    if verbose:
        print(
            f"[recon] {recon_data.get('status')} {recon_data.get('final_url')} "
            f"| endpoints={len(recon_data['endpoints'])} "
            f"scripts={len(recon_data['scripts'])} params={len(recon_data['parameters'])}"
        )

    result = HuntResult(
        target=target,
        base_url=recon_data.get("base_url", ""),
        recon=recon_data,
        out_dir=out_dir,
    )

    if not no_ai and provider is not None:
        if provider.requires_key and not provider.key():
            if verbose:
                print(
                    f"[ai] skipped: no key for {provider.id} "
                    f"(set {provider.api_key_env}); running recon only"
                )
        else:
            if verbose:
                print(f"[ai] provider={provider.id} model={model or provider.model()}")
            steps, usage, summary = _ai_loop(
                provider=provider,
                model=model or provider.model(),
                target=target,
                recon_data=recon_data,
                scope=scope,
                toolbox=toolbox,
                max_steps=max_steps,
                temperature=temperature,
                timeout=ai_timeout,
                base_url=base_url,
                verbose=verbose,
            )
            result.ai_used = True
            result.ai_model = model or provider.model()
            result.steps = steps
            result.usage = usage
            result.summary = summary

    findings.save()
    _write_recon(out_dir / "RECON.md", target, scope, recon_data, toolbox)

    result.findings = [f.__dict__ for f in findings.items]
    result.requests = toolbox.requests
    result.denied = toolbox.denied
    return result
