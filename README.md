# dsh-egress-guard

[![npm](https://img.shields.io/npm/v/dsh-egress-guard?color=4D6BFE)](https://www.npmjs.com/package/dsh-egress-guard)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

English | [中文](README.zh.md)

A **runtime** security gate for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) tool calls.

Existing security plugins in the ecosystem scan configuration files *before* an agent runs. This one sits in the tool-execution pipeline and acts on the calls themselves:

| Rule | Extension point | What it does |
|---|---|---|
| **Egress allowlist** | `tools/pre-execute` | Denies (or asks about) a call that names a network destination outside your allowlist — `curl` to a paste site, `git push` to an unknown remote, a fetch to an exfiltration endpoint. |
| **Secret redaction** | `tools/post-execute` | Rewrites credentials out of a tool result *before* the model, the durable session log, or a Code Mode program can read them. |
| **Audit log** | both waterfalls | Appends every decision — including the ones `monitor` mode only *would* have made — to a JSONL file. |

No fork, no patched loop: three listeners on documented extension points, disposed cleanly on unload.

## Install

```sh
dsh plugin --profile <name> add dsh-egress-guard
```

The bundle ships `mode: monitor`, so **installing it cannot break a working setup**: every rule is evaluated and audited, nothing is blocked or rewritten. Read the audit log for a day, then turn on enforcement in your profile's `cordis.patch.yml`:

```yaml
- id: egress-guard
  config:
    mode: enforce
    egress:
      enabled: true
      allowHosts: ['*.github.com', '*.npmjs.org', 'api.deepseek.com']
      denyHosts: []
      allowLoopback: true
      onViolation: deny
    redact:
      enabled: true
      builtins: true
      extraPatterns: []
      placeholder: '[redacted:{name}]'
    audit:
      enabled: true
      path: ''
      logAllowed: false
```

A patch replaces a row's **whole** `config`, so restate every key you want to keep.

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `mode` | `monitor` | `off` registers nothing. `monitor` evaluates and audits without acting. `enforce` denies and redacts. |
| `egress.allowHosts` | `[]` in schema, a starter list in the bundle | Permitted hosts. `*.example.com` covers the apex **and** every subdomain. An empty list means denylist-only. |
| `egress.denyHosts` | `[]` | Always denied. Beats `allowHosts` and `allowLoopback`. |
| `egress.allowLoopback` | `true` | Exempts `localhost`, `127.0.0.0/8`, `::1`, `*.localhost`. |
| `egress.onViolation` | `deny` | `ask` routes to `ctx.approval` instead — and **degrades to deny** when no approval service is mounted. |
| `redact.builtins` | `true` | Private keys, vendor API keys, JWTs, bearer headers, `KEY=value` assignments. |
| `redact.extraPatterns` | `[]` | Extra regex sources, compiled with the global flag. |
| `redact.placeholder` | `[redacted:{name}]` | `{name}` is the pattern that matched. |
| `audit.path` | `$DSH_HOME/egress-guard.jsonl` | JSONL, one decision per line. |
| `audit.logAllowed` | `false` | Also record calls that named a host and passed — this is how you build an allowlist out of real traffic. |

### Building an allowlist from real traffic

```sh
# 1. Install (monitor mode) and work normally for a while, with logAllowed: true.
# 2. See which hosts your agent actually reaches:
jq -r '.hosts[]?' ~/.dsh/egress-guard.jsonl | sort | uniq -c | sort -rn
# 3. Put the legitimate ones in allowHosts, then flip mode to enforce.
```

## Design notes

**Redaction happens at the canonical value, not the rendered content.** The registry's contract is explicit that content replacement is *not* a confidentiality boundary — a Code Mode program receives the canonical `value` directly. So a successful result is redacted by replacing its value, and the content is re-rendered from the redacted value. Failed results carry no value (the registry rejects a value replacement on them), so their message is redacted as content.

**The guard runs last in the post-execute waterfall.** It delegates with `next()` first, then redacts whatever projection the composed decision actually carries, so a listener deeper in the waterfall cannot reinstate the original text. When another plugin replaced the content but the underlying value holds a secret, the guard replaces the **value** — losing that plugin's presentation, but not leaking to programmatic consumers. That precedence is deliberate.

**Denials tell the model not to route around them.** A bare "denied" invites a retry with a different tool; the reason string names the hosts and says to ask the user instead.

## Limitations — read this before trusting it

This is a **guard rail, not a containment boundary**. It raises the cost of an accident or a careless prompt injection; it does not stop a determined adversary running code on your machine.

- **Detection is textual.** Destinations are found by scanning argument strings for URLs and `user@host` remotes. A command that assembles its destination at runtime (`curl "$ENDPOINT"`, base64, string concatenation, an IP in decimal form) is **invisible** to the gate. Real containment is the sandbox seam's job (`dsh-bash-sandbox`, network namespaces, a proxy), not a string matcher's.
- **A tool that opens its own socket bypasses the gate entirely** unless the destination appears in its arguments.
- **Redaction is pattern-based**, so it misses credential shapes it does not know, and it can rewrite text that merely looks like a secret. Add `extraPatterns` for your own formats; check the audit log for false positives before enforcing.
- **Binary content is not scanned** — image blocks and other non-text blocks pass through untouched.
- **The audit log is local and unsigned.** Anything that can write to your filesystem can edit it.

## Compatibility

Built against the `@deepseek-ai/dsh-tools` `0.1.0-rc` pipeline contract. The test suite runs against `0.1.0-rc.6` from npm, and the bundle was installed into a live `dsh 0.1.0-rc.5` profile four ways — from npm, from a local path, from a packed tarball, and from git — reaching `fiberPhase: active` in all four.

Note that npm's `latest` tag for the `@deepseek-ai/*` packages still points at an old `0.0.1-rc.1` line; the current releases are on the `next` tag. If you install harness packages by hand, ask for the version explicitly.

The harness is in developer preview and states that compatibility-breaking changes will happen. If a pipeline contract shifts, this plugin's tests are designed to fail loudly — they execute real calls through a real registry rather than mocking the waterfalls.

## Development

```sh
npm install
npm test          # 61 tests: pure unit tests + end-to-end through a real ToolRuntime
npm run typecheck
npm run build
```

To try it against a live harness without publishing:

```sh
dsh plugin --profile <name> add /path/to/dsh-egress-guard
dsh --profile <name> --dump-config   # shows the "# == dsh-egress-guard" layer
```

## License

[MIT](LICENSE)
