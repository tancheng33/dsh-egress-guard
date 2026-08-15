/**
 * Secret detection and redaction for tool results.
 *
 * Pure string/JSON transforms only. The caller decides WHICH projection of a
 * result gets redacted (canonical value, rendered content, or block feedback),
 * because that choice is a pipeline contract rather than a pattern-matching
 * concern.
 *
 * @module dsh-egress-guard/redact
 */

/** One named secret shape and how its match is rewritten. */
export interface SecretPattern {
  /** Stable identifier; it names the hit in the audit log and the placeholder. */
  readonly name: string
  /** Global regular expression. A fresh instance is compiled per pass, so `lastIndex` never leaks between calls. */
  readonly regex: RegExp
  /**
   * Optional rewrite for a pattern that must preserve part of its match — the
   * key of a `key = value` assignment, for instance. Receives the resolved
   * placeholder followed by the ordinary `String.replace` arguments.
   */
  readonly replacer?: (placeholder: string, ...args: string[]) => string
}

/** Depth cap for the value walk, matching the argument walk in `egress.ts`. */
const MAX_DEPTH = 12

/**
 * Shapes that are credentials wherever they appear. Each entry is deliberately
 * anchored on a vendor prefix or an explicit key name: a generic "40 random
 * characters" rule would redact hashes, UUIDs, and base64 payloads that tools
 * legitimately return, and a guard that corrupts ordinary output gets disabled.
 */
export const BUILTIN_PATTERNS: readonly SecretPattern[] = [
  {
    name: 'private-key',
    regex: /-----BEGIN[^-]{0,40}PRIVATE KEY-----[\s\S]*?-----END[^-]{0,40}PRIVATE KEY-----/g,
  },
  { name: 'openai-key', regex: /\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}/g },
  { name: 'github-token', regex: /\bgh[pousr]_[A-Za-z0-9]{30,}/g },
  { name: 'aws-access-key', regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { name: 'google-api-key', regex: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: 'slack-token', regex: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g },
  { name: 'jwt', regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
  { name: 'bearer-token', regex: /\bBearer\s+[A-Za-z0-9._~+/-]{20,}={0,2}/gi },
  {
    name: 'credential-assignment',
    // Keeps the key and the separator so the model still sees WHICH variable
    // was set — it only never sees the value.
    regex: /\b([A-Za-z0-9_-]*(?:api[_-]?key|secret|token|password|passwd|access[_-]?key)[A-Za-z0-9_-]*)(\s*[:=]\s*)(["']?)([^\s"',;]{8,})\3/gi,
    replacer: (placeholder, _match, key, separator, quote) => `${key}${separator}${quote}${placeholder}${quote}`,
  },
]

/**
 * Compile user-supplied regular expressions into named patterns.
 *
 * @param sources - raw expression bodies from configuration.
 * @returns one pattern per source, named `custom-<index>`.
 * @throws SyntaxError when a source is not a valid regular expression — the
 *   plugin surfaces it at load time rather than silently ignoring the rule.
 */
export function compilePatterns(sources: readonly string[]): SecretPattern[] {
  return sources.map((source, index) => ({
    name: `custom-${index + 1}`,
    regex: new RegExp(source, 'g'),
  }))
}

/**
 * Resolve the configured placeholder template for one pattern.
 *
 * @param template - the configured template, where `{name}` is substituted.
 * @param name - the matched pattern's name.
 * @returns the replacement text.
 */
export function formatPlaceholder(template: string, name: string): string {
  return template.replaceAll('{name}', name)
}

/** The result of one redaction pass. */
export interface RedactionResult<T> {
  /** The rewritten payload; strictly equal to the input when nothing matched. */
  readonly value: T
  /** Distinct pattern names that matched, in first-hit order. */
  readonly hits: readonly string[]
}

/**
 * Redact every configured secret shape in one string.
 *
 * @param text - the text to scan.
 * @param patterns - the active patterns.
 * @param placeholder - the placeholder template.
 * @returns the rewritten text and the patterns that fired.
 */
export function redactText(
  text: string,
  patterns: readonly SecretPattern[],
  placeholder: string,
): RedactionResult<string> {
  let current = text
  const hits: string[] = []
  for (const pattern of patterns) {
    const resolved = formatPlaceholder(placeholder, pattern.name)
    // A fresh RegExp per pass: the configured instances are shared across every
    // tool call, and a stateful `lastIndex` would make results order-dependent.
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags)
    const replacer = pattern.replacer
    current = current.replace(regex, (...args: unknown[]) => {
      if (!hits.includes(pattern.name)) hits.push(pattern.name)
      const stringArgs = args.map(arg => (typeof arg === 'string' ? arg : ''))
      return replacer === undefined ? resolved : replacer(resolved, ...stringArgs)
    })
  }
  return { value: current, hits }
}

/**
 * Redact every string reachable from a JSON-shaped value.
 *
 * Object keys are left untouched: a key names a field, and rewriting it would
 * change the shape the tool's output schema declares.
 *
 * @param value - the canonical tool value.
 * @param patterns - the active patterns.
 * @param placeholder - the placeholder template.
 * @returns the rewritten value (the same reference when nothing matched) and the hits.
 */
export function redactJson<T>(
  value: T,
  patterns: readonly SecretPattern[],
  placeholder: string,
): RedactionResult<T> {
  const hits: string[] = []
  const record = (found: readonly string[]): void => {
    for (const name of found) if (!hits.includes(name)) hits.push(name)
  }

  const visit = (node: unknown, depth: number): unknown => {
    if (depth > MAX_DEPTH) return node
    if (typeof node === 'string') {
      const result = redactText(node, patterns, placeholder)
      record(result.hits)
      return result.value
    }
    if (Array.isArray(node)) {
      let changed = false
      const next = node.map(item => {
        const replaced = visit(item, depth + 1)
        if (replaced !== item) changed = true
        return replaced
      })
      return changed ? next : node
    }
    if (typeof node === 'object' && node !== null) {
      let changed = false
      const next: Record<string, unknown> = {}
      for (const [key, item] of Object.entries(node)) {
        const replaced = visit(item, depth + 1)
        if (replaced !== item) changed = true
        next[key] = replaced
      }
      return changed ? next : node
    }
    return node
  }

  return { value: visit(value, 0) as T, hits }
}

/** The structural shape of a text content block, kept local to avoid a runtime import. */
interface TextBlockLike {
  readonly type: string
  readonly text?: unknown
}

/**
 * Redact the text blocks of a rendered content array.
 *
 * Non-text blocks (images, and any future block type) pass through unchanged:
 * this plugin cannot inspect binary payloads, and dropping them would destroy
 * results it does not understand.
 *
 * @param blocks - the rendered content.
 * @param patterns - the active patterns.
 * @param placeholder - the placeholder template.
 * @returns the rewritten blocks (the same reference when nothing matched) and the hits.
 */
export function redactContent<T extends TextBlockLike>(
  blocks: readonly T[],
  patterns: readonly SecretPattern[],
  placeholder: string,
): RedactionResult<T[]> {
  const hits: string[] = []
  let changed = false
  const next = blocks.map(block => {
    if (block.type !== 'text' || typeof block.text !== 'string') return block
    const result = redactText(block.text, patterns, placeholder)
    for (const name of result.hits) if (!hits.includes(name)) hits.push(name)
    if (result.value === block.text) return block
    changed = true
    return { ...block, text: result.value }
  })
  return { value: changed ? next : [...blocks], hits }
}
