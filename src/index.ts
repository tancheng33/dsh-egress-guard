/**
 * dsh-egress-guard — a runtime security gate for DeepSeek Harness tool calls.
 *
 * Three independent rules, all on documented extension points, none of which
 * modify the agent loop:
 *
 * - `tools/pre-execute` — deny (or ask about) a call that names a network
 *   destination outside the configured allowlist.
 * - `tools/post-execute` — rewrite credentials out of a tool result before the
 *   model, the durable session log, or a Code Mode program can read them.
 * - `tools/result` observation is deliberately NOT used for enforcement; the
 *   audit log is written from the two waterfalls, where the decision is known.
 *
 * The shipped default is `mode: 'monitor'`: every rule is evaluated and
 * audited, nothing is blocked or rewritten. A security plugin that breaks a
 * working agent on install gets uninstalled, so enforcement is opt-in.
 *
 * @module dsh-egress-guard
 */

import { homedir } from 'node:os'
import { join } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import Schema from '@deepseek-ai/schemastery'
import type { JsonValue } from '@deepseek-ai/dsh-session'
import type { PostToolDecision, PreToolDecision, ToolExecution, ToolExecutionResult } from '@deepseek-ai/dsh-tools'
import { createFileSink, NULL_SINK, type AuditRecord, type AuditSink } from './audit.js'
import { evaluateEgress } from './egress.js'
import { BUILTIN_PATTERNS, compilePatterns, redactContent, redactJson, type SecretPattern } from './redact.js'

export { evaluateEgress, extractTargets, isLoopback, matchHost } from './egress.js'
export { BUILTIN_PATTERNS, redactContent, redactJson, redactText } from './redact.js'
export type { AuditRecord, AuditSink } from './audit.js'
export type { EgressTarget, EgressVerdict } from './egress.js'
export type { SecretPattern } from './redact.js'

/** Cordis plugin name used by loader diagnostics and the plugin inventory. */
export const name = 'egress-guard'

/**
 * The tool registry owns the waterfalls this plugin listens on. Static
 * injection holds the plugin PENDING until the registry exists, so a
 * composition that forgets `@deepseek-ai/dsh-tools` fails loudly instead of
 * silently enforcing nothing.
 */
export const inject = ['tools']

/** Egress rule configuration. */
export interface EgressConfig {
  enabled: boolean
  allowHosts: string[]
  denyHosts: string[]
  allowLoopback: boolean
  onViolation: 'deny' | 'ask'
}

/** Redaction rule configuration. */
export interface RedactConfig {
  enabled: boolean
  builtins: boolean
  extraPatterns: string[]
  placeholder: string
}

/** Audit sink configuration. */
export interface AuditConfig {
  enabled: boolean
  path: string
  logAllowed: boolean
}

/** Plugin configuration. */
export interface Config {
  mode: 'off' | 'monitor' | 'enforce'
  egress: EgressConfig
  redact: RedactConfig
  audit: AuditConfig
}

/** Schemastery schema; Cordis validates `config` against it and fills defaults. */
export const Config: Schema<Config> = Schema.object({
  mode: Schema.union(['off', 'monitor', 'enforce'] as const)
    .default('monitor')
    .description('off: unload the rules entirely. monitor: evaluate and audit, never act. enforce: deny and redact.'),
  egress: Schema.object({
    enabled: Schema.boolean().default(true)
      .description('Evaluate the destination allowlist on every tool call.'),
    allowHosts: Schema.array(String).default([])
      .description('Permitted hosts. `*.example.com` covers the apex and every subdomain. An empty list permits every host that is not explicitly denied.'),
    denyHosts: Schema.array(String).default([])
      .description('Always-denied hosts; takes precedence over allowHosts and over allowLoopback.'),
    allowLoopback: Schema.boolean().default(true)
      .description('Exempt localhost, 127.0.0.0/8, ::1, and *.localhost from the allowlist.'),
    onViolation: Schema.union(['deny', 'ask'] as const).default('deny')
      .description('deny: fail the call. ask: route it to the approval service (which degrades to deny when no approval service is mounted).'),
  }).default({} as EgressConfig),
  redact: Schema.object({
    enabled: Schema.boolean().default(true)
      .description('Scan tool results for credentials.'),
    builtins: Schema.boolean().default(true)
      .description('Use the built-in credential patterns (private keys, vendor API keys, JWTs, key=value assignments).'),
    extraPatterns: Schema.array(String).default([])
      .description('Additional JavaScript regular-expression sources, compiled with the global flag.'),
    placeholder: Schema.string().default('[redacted:{name}]')
      .description('Replacement text. `{name}` is substituted with the pattern that matched.'),
  }).default({} as RedactConfig),
  audit: Schema.object({
    enabled: Schema.boolean().default(true)
      .description('Append every decision to a JSONL log.'),
    path: Schema.string().default('')
      .description('Log path. Empty resolves to $DSH_HOME/egress-guard.jsonl (default ~/.dsh/egress-guard.jsonl).'),
    logAllowed: Schema.boolean().default(false)
      .description('Also record calls that named a destination and passed. Verbose, but it is how you build an allowlist from real traffic.'),
  }).default({} as AuditConfig),
})

/**
 * Resolve the audit log path, mirroring the harness's own `$DSH_HOME`
 * precedence: an explicit configured path wins, then the environment
 * variable, then `~/.dsh`.
 *
 * @param configured - the `audit.path` field.
 * @param env - environment mapping, injectable for tests.
 * @returns an absolute-or-cwd-relative log path.
 */
export function resolveAuditPath(configured: string, env: Record<string, string | undefined> = process.env): string {
  const explicit = configured.trim()
  if (explicit.length > 0) return explicit
  const home = env['DSH_HOME']?.trim()
  return join(home !== undefined && home.length > 0 ? home : join(homedir(), '.dsh'), 'egress-guard.jsonl')
}

/**
 * Assemble the active pattern set from configuration.
 *
 * @param config - the redaction configuration.
 * @returns built-in patterns (when enabled) followed by compiled custom ones.
 */
export function activePatterns(config: RedactConfig): SecretPattern[] {
  return [
    ...(config.builtins ? BUILTIN_PATTERNS : []),
    ...compilePatterns(config.extraPatterns),
  ]
}

/**
 * Build the model-facing denial text.
 *
 * It names the offending hosts and tells the model NOT to work around the
 * block, because a bare "denied" invites a retry with a different tool.
 *
 * @param violations - the hosts that failed the policy.
 * @returns the reason string attached to the deny/ask decision.
 */
function denialReason(violations: readonly string[]): string {
  const hosts = violations.join(', ')
  return `Blocked by dsh-egress-guard: ${hosts} ${violations.length === 1 ? 'is' : 'are'} not on the configured egress allowlist. `
    + 'Do not retry this call or route around it with another tool. '
    + `If the request is legitimate, ask the user to add the host to the guard's \`egress.allowHosts\`.`
}

/** Install the guard's listeners. */
export function apply(ctx: Context, config: Config): void {
  if (config.mode === 'off') return

  const enforcing = config.mode === 'enforce'
  const warn = (message: string): void => {
    const logger = (ctx as { logger?: { warn?: (text: string) => void } }).logger
    if (typeof logger?.warn === 'function') logger.warn(`egress-guard: ${message}`)
    else console.warn(`[egress-guard] ${message}`)
  }

  const sink: AuditSink = config.audit.enabled
    ? createFileSink(resolveAuditPath(config.audit.path), warn)
    : NULL_SINK
  const patterns = activePatterns(config.redact)

  const audit = (record: Omit<AuditRecord, 'ts'>): void => {
    sink.write({ ts: new Date().toISOString(), ...record })
  }

  ctx.on('tools/pre-execute', async (exec: ToolExecution, next): Promise<PreToolDecision> => {
    if (!config.egress.enabled) return next()

    const verdict = evaluateEgress(exec.arguments, config.egress)
    if (verdict.violations.length === 0) {
      if (config.audit.logAllowed && verdict.targets.length > 0) {
        audit({
          kind: 'egress',
          tool: exec.name,
          callId: String(exec.callId),
          decision: 'allow',
          hosts: verdict.targets.map(target => target.host),
        })
      }
      return next()
    }

    const decision = !enforcing ? 'would-deny' : config.egress.onViolation === 'ask' ? 'ask' : 'deny'
    audit({
      kind: 'egress',
      tool: exec.name,
      callId: String(exec.callId),
      decision,
      hosts: verdict.targets.map(target => target.host),
      violations: [...verdict.violations],
      sample: verdict.targets.find(target => verdict.violations.includes(target.host))?.source,
    })

    if (!enforcing) return next()
    const reason = denialReason(verdict.violations)
    return config.egress.onViolation === 'ask' ? { kind: 'ask', reason } : { kind: 'deny', reason }
  })

  ctx.on('tools/post-execute', async (
    exec: ToolExecution,
    result: Readonly<ToolExecutionResult>,
    next,
  ): Promise<PostToolDecision> => {
    if (!config.redact.enabled || patterns.length === 0) return next()

    // Run the rest of the waterfall first, then redact whatever projection the
    // composed decision actually carries. Redacting before delegating would let
    // a later listener reinstate the original text.
    const decision = await next()
    const record = (projection: NonNullable<AuditRecord['projection']>, hits: readonly string[]): void => {
      audit({
        kind: 'redact',
        tool: exec.name,
        callId: String(exec.callId),
        decision: enforcing ? 'redact' : 'would-redact',
        patterns: [...hits],
        projection,
      })
    }

    if (decision.kind === 'block') {
      const redacted = redactContent(decision.feedback, patterns, config.redact.placeholder)
      if (redacted.hits.length === 0) return decision
      record('feedback', redacted.hits)
      if (!enforcing) return decision
      return { ...decision, feedback: redacted.value }
    }

    // A downstream listener already replaced the canonical value: redact that
    // replacement, since it — not the original — is what the pipeline commits.
    if (decision.value !== undefined) {
      const redacted = redactJson(decision.value as JsonValue, patterns, config.redact.placeholder)
      if (redacted.hits.length === 0) return decision
      record('value', redacted.hits)
      if (!enforcing) return decision
      return { kind: 'accept', value: redacted.value, additionalContexts: decision.additionalContexts }
    }

    // Successful results are redacted at the VALUE, not at the rendered
    // content: content replacement is explicitly not a confidentiality
    // boundary in the registry contract, and a Code Mode program receives the
    // value directly. Replacing the value re-renders the content from it.
    if (!result.isError) {
      const redacted = redactJson(result.value, patterns, config.redact.placeholder)
      if (redacted.hits.length > 0) {
        record('value', redacted.hits)
        if (!enforcing) return decision
        // This deliberately supersedes a downstream content-only replacement:
        // leaking the value to a programmatic consumer is the worse outcome.
        return { kind: 'accept', value: redacted.value, additionalContexts: decision.additionalContexts }
      }
    }

    // Failures carry no canonical value — the registry rejects a value
    // replacement on them — so their message is redacted as content.
    const source = decision.content ?? result.content
    const redacted = redactContent(source, patterns, config.redact.placeholder)
    if (redacted.hits.length === 0) return decision
    record('content', redacted.hits)
    if (!enforcing) return decision
    return { kind: 'accept', content: redacted.value, additionalContexts: decision.additionalContexts }
  })

  // Flush queued audit lines when the plugin unloads (HMR, profile reload).
  // The disposer RETURNS the flush promise rather than firing it and forgetting:
  // audit writes are queued, so a disposer that does not hand the promise back
  // can drop the last records of a session.
  ctx.effect(() => () => sink.flush())
}
