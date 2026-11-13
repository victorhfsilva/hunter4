# hunter4

A small, **scope-aware** vulnerability hunter driven by AI providers.
It is a simplified re-implementation of the parent `pentest-agents`
framework, built around one goal: **hunt a target without the framework
dead-ending on scope bookkeeping.**

- ~1,500 lines, **stdlib only** (no `requests`, no `pyyaml`).
- Multiple AI providers: **Verboo** (default), [OI], OpenRouter, Groq,
  Anthropic, Ollama, and any generic [OI]-compatible endpoint.
- Deterministic recon always runs; AI hunting layers on top when configured.
- Writes `RECON.md`, `FINDINGS.md`, and `findings.json`.

---

## The scope-limits problem, and how hunter4 solves it

The parent framework refused to hunt unless four artifacts already existed
(`scope.yaml`, `hacktivity.md`, `policy.md`, brain state). That is safe, but it
dead-ends a legitimate engagement: the operator knows the target is authorized,
yet the run aborts before a single request.

hunter4 changes the model in three ways:

1. **Scope is derived, not required.** With no files at all, scope becomes the
   target host plus its subdomains.
2. **One acknowledgement instead of four artifacts.** `--authorized` (or an
   interactive `y`) is the only gate. A scope file is optional and, when
   supplied, *tightens* the boundary.
3. **Enforcement is per request, not per run.** Every network tool checks scope
   before it fires. A denied request is **skipped and logged**; the hunt
   continues with the in-scope surface instead of aborting.

Result: `hunter4 hunt example.com --authorized` just works, while out-of-scope
hosts are still blocked at the tool boundary.

### Scope modes

| Mode | Meaning |
|------|---------|
| `auto` (default) | target host + all subdomains |
| `strict` | exact target host only (no subdomains) |
| `file` | load `in_scope` / `out_of_scope` from a `.yaml` or `.txt` scope file |
| `off` | no host restriction (prints a warning; use deliberately) |

`--exclude HOST` (repeatable) adds out-of-scope entries. **Out-of-scope always
wins over in-scope.**

```yaml
# scope.yaml
in_scope:
  - example.com
  - "*.api.example.com"
out_of_scope:
  - legacy.example.com
  - status.example.com
```

```bash
hunter4 hunt example.com --authorized                      # auto scope
hunter4 hunt example.com --scope scope.yaml                # file implies authorization
hunter4 hunt example.com --authorized --exclude legacy.example.com
hunter4 scope example.com --scope-mode strict              # inspect effective scope
```

---

## Quick start

```bash
# from the repo root
./bin/hunter4 providers                 # list AI providers

export VERBOO_API_KEY=vbk_...           # or reuse ~/.config/opencode/opencode.json
./bin/hunter4 hunt example.com --authorized

# deterministic recon only (no AI key needed)
./bin/hunter4 recon example.com --authorized

# another provider
./bin/hunter4 hunt example.com --authorized --provider openrouter \
    --model openai/gpt-4o-mini
```

Or install the console script:

```bash
pipx install .
hunter4 hunt example.com --authorized
```

`python -m hunter4 ...` works from the repo without installing.

---

## Providers

| Provider | Id | Wire format | Default model | Key env |
|---|---|---|---|---|
| **Verboo** | `verboo` | [OI] chat | `deepseek-v4.1-flash` | `VERBOO_API_KEY` |
| [OI] | `openai` | [OI] chat | `gpt-4o-mini` | `OPENAI_API_KEY` |
| OpenRouter | `openrouter` | [OI] chat | `openai/gpt-4o-mini` | `OPENROUTER_API_KEY` |
| Groq | `groq` | [OI] chat | `llama-3.3-70b-versatile` | `GROQ_API_KEY` |
| Ollama | `ollama` | [OI] chat | `llama3.1` | (none) |
| Anthropic | `anthropic` | Messages API | `--model` / `ANTHROPIC_MODEL` | `ANTHROPIC_API_KEY` |
| Custom | `custom` | [OI] chat | `--model` | `CUSTOM_API_KEY` |

Resolution order for base URL / key / model (first wins):

1. CLI flags `--base-url`, `--api-key`, `--model`
2. provider env vars, then `HUNTER4_*` / `AI_*`
3. `~/.config/hunter4/config.json`
4. `~/.config/opencode/opencode.json` (Verboo convenience)
5. baked-in defaults

No key is stored in this repo. Verboo reuses your existing OpenCode provider
block if present.

---

## How a hunt works

1. **Scope** is resolved (derived or from file).
2. **Deterministic recon** (always):
   - probes the base URL (https, then http), capturing status, server, headers;
   - extracts links, scripts, forms, and query parameters (same-scope only);
   - checks security headers (HSTS, CSP, X-Frame-Options, …).
3. **AI hunt loop** (when a provider key is available):
   - the model receives the recon summary and a hunter methodology prompt;
   - it calls tools (`probe`, `http_request`, `dns_lookup`, `save_finding`,
     `finish`) to test hypotheses;
   - it saves only findings it can evidence.
4. **Reports** are written to the output directory.

### Tools

| Tool | Scope-checked | Purpose |
|---|---|---|
| `probe` | yes | quick status/title/server on a URL |
| `http_request` | yes | crafted requests (method, headers, body) |
| `dns_lookup` | yes | resolve an in-scope host |
| `save_finding` | n/a | persist a proven finding |
| `list_findings` | n/a | list findings so far |
| `run_command` | **no** | local shell; disabled unless `--allow-shell` |
| `finish` | n/a | stop and summarize |

`run_command` is off by default because a shell cannot be scope-enforced. When
enabled, it still blocks obvious destructive commands.

---

## CLI

```
hunter4 hunt    <target> [options]   recon + AI hunting
hunter4 recon   <target> [options]   deterministic recon only
hunter4 scope   <target> [options]   print the effective scope
hunter4 providers                    list providers/models/key state
```

Common options:

| Flag | Meaning |
|---|---|
| `--provider <id>` | provider (default `verboo`) |
| `--model <id>` | model override |
| `--base-url` / `--api-key` | endpoint overrides |
| `--scope-mode auto\|strict\|file\|off` | scope derivation |
| `--scope <file>` | load scope file (implies authorization) |
| `--exclude <host>` | out-of-scope host (repeatable) |
| `--authorized` / `-y` | confirm authorization |
| `--max-steps N` | max AI turns (default 20) |
| `--timeout N` / `--ai-timeout N` | request / AI timeouts |
| `--allow-shell` | enable `run_command` |
| `--dry-run` | no network; tools print intent |
| `--no-ai` | deterministic recon only |
| `--out DIR` | output directory (default `hunter_out/<host>`) |
| `-q` / `--quiet` | less output |

Non-interactive runs require `--authorized` or `HUNTER4_AUTHORIZED=1`.

---

## Output

```
hunter_out/<host>/
├── RECON.md      # scope, recon summary (JSON), allowed + denied requests
├── FINDINGS.md   # human-readable findings with evidence
└── findings.json # machine-readable findings
```

---

## Safety

- Requests go only to in-scope hosts; denials are logged in `RECON.md`.
- No destructive actions; the shell tool is opt-in.
- The AI is instructed to save only evidenced findings — treat any unproven
  claim as a lead, not a finding.
- Use only against targets you are authorized to test.

---

## Development

```bash
PYTHONPATH=. python3 -m pytest tests -q
```

Coverage: scope derivation/matching, provider registry + resolution, the
[OI] and Anthropic wire adapters, per-request scope enforcement, dry-run,
findings persistence, and recon extraction.

## License

MIT. For authorized security testing only.
