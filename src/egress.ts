/**
 * Destination extraction and allowlist matching for one pending tool call.
 *
 * Everything here is pure and synchronous: it reads the already-frozen
 * arguments of a {@link ToolExecution} and reports which network destinations
 * the call names. The policy decision itself lives in the plugin entry point.
 *
 * @module dsh-egress-guard/egress
 */

/** Absolute http(s) URLs, stopped at whitespace, quotes, and shell redirection. */
const URL_PATTERN = /\bhttps?:\/\/[^\s'"`<>\\|;)]+/gi

/**
 * `user@host` destinations of `ssh`, `scp`, `rsync`, and `git` remotes. The
 * host must carry a dot and a alphabetic TLD so ordinary email-looking text in
 * a diff does not read as an egress target on every call.
 */
const SSH_PATTERN = /\b[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})(?=[:\s/]|$)/g

/** Depth cap for the argument walk; deeper structures are not model-authored. */
const MAX_DEPTH = 12

/** Total strings inspected per call, so a huge argument payload cannot stall the gate. */
const MAX_STRINGS = 4096

/** Hostnames that never leave the machine. */
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]', '0.0.0.0'])

/** One destination found in a call's arguments, with the text it came from. */
export interface EgressTarget {
  /** Lowercased hostname with any trailing dot removed. */
  readonly host: string
  /** The matched substring, truncated for the audit log. */
  readonly source: string
}

/** The verdict for one call: everything it names, and the part that is not allowed. */
export interface EgressVerdict {
  readonly targets: readonly EgressTarget[]
  /** Hosts denied outright or absent from a non-empty allowlist. */
  readonly violations: readonly string[]
}

/** Host-matching inputs, mirroring the corresponding {@link Config} fields. */
export interface EgressPolicy {
  readonly allowHosts: readonly string[]
  readonly denyHosts: readonly string[]
  readonly allowLoopback: boolean
}

/**
 * Collect every string reachable from a JSON-shaped argument payload.
 *
 * @param value - the call's parsed arguments (already lossless JSON).
 * @returns the strings, capped at {@link MAX_STRINGS}.
 */
export function collectStrings(value: unknown): string[] {
  const out: string[] = []
  const visit = (node: unknown, depth: number): void => {
    if (out.length >= MAX_STRINGS || depth > MAX_DEPTH) return
    if (typeof node === 'string') {
      out.push(node)
      return
    }
    if (Array.isArray(node)) {
      for (const item of node) visit(item, depth + 1)
      return
    }
    if (typeof node === 'object' && node !== null) {
      for (const item of Object.values(node)) visit(item, depth + 1)
    }
  }
  visit(value, 0)
  return out
}

/** Normalize one hostname for comparison: lowercase, no trailing dot, no brackets. */
function normalizeHost(host: string): string {
  return host.toLowerCase().replace(/\.$/, '')
}

/**
 * Truncate a matched substring so one 4 KB URL cannot bloat every audit record.
 *
 * @param text - the raw match.
 * @returns at most 200 characters, with an ellipsis when cut.
 */
function truncate(text: string): string {
  return text.length <= 200 ? text : `${text.slice(0, 200)}…`
}

/**
 * Extract the network destinations named anywhere in a call's arguments.
 *
 * Detection is deliberately textual: it sees URLs and `user@host` remotes in
 * any argument of any tool, including a shell command string. It does NOT
 * understand shell semantics, so a destination assembled at runtime
 * (`curl "$ENDPOINT"`, base64, string concatenation) is invisible here — see
 * the limitations section of the README.
 *
 * @param args - the call's parsed arguments.
 * @returns one entry per distinct host, keeping the first source text seen.
 */
export function extractTargets(args: unknown): EgressTarget[] {
  const found = new Map<string, EgressTarget>()
  for (const text of collectStrings(args)) {
    for (const match of text.matchAll(URL_PATTERN)) {
      let host: string
      try {
        host = normalizeHost(new URL(match[0]).hostname)
      } catch {
        // A malformed URL names no resolvable destination; the shell would
        // fail on it too. Skip rather than guess at the author's intent.
        continue
      }
      if (host.length > 0 && !found.has(host)) found.set(host, { host, source: truncate(match[0]) })
    }
    for (const match of text.matchAll(SSH_PATTERN)) {
      const host = normalizeHost(match[1] ?? '')
      if (host.length > 0 && !found.has(host)) found.set(host, { host, source: truncate(match[0]) })
    }
  }
  return [...found.values()]
}

/**
 * Test one host against one pattern.
 *
 * A bare pattern (`github.com`) matches that exact host. A wildcard pattern
 * (`*.github.com`) matches the apex domain AND every subdomain — an allowlist
 * entry is an explicit grant, so the apex is included rather than requiring
 * every user to write the domain twice.
 *
 * @param host - a normalized hostname.
 * @param pattern - an allowlist or denylist entry.
 * @returns whether the pattern covers the host.
 */
export function matchHost(host: string, pattern: string): boolean {
  const normalized = normalizeHost(pattern.trim())
  if (normalized.length === 0) return false
  if (normalized === '*') return true
  if (normalized.startsWith('*.')) {
    const apex = normalized.slice(2)
    return host === apex || host.endsWith(`.${apex}`)
  }
  return host === normalized
}

/** Whether a host is a loopback address or a `.localhost` name. */
export function isLoopback(host: string): boolean {
  return LOOPBACK_HOSTS.has(host) || host.endsWith('.localhost') || host.startsWith('127.')
}

/**
 * Evaluate one call's destinations against the configured policy.
 *
 * Precedence: an explicit `denyHosts` match always violates, even when the
 * same host is allowlisted; loopback is exempt only when `allowLoopback` is
 * set and the host is not explicitly denied. An EMPTY `allowHosts` allows
 * every host that is not denied, so a deployment can run denylist-only.
 *
 * @param args - the pending call's arguments.
 * @param policy - the configured hosts.
 * @returns every destination found plus the violating subset.
 */
export function evaluateEgress(args: unknown, policy: EgressPolicy): EgressVerdict {
  const targets = extractTargets(args)
  const violations: string[] = []
  for (const { host } of targets) {
    if (policy.denyHosts.some(pattern => matchHost(host, pattern))) {
      violations.push(host)
      continue
    }
    if (policy.allowLoopback && isLoopback(host)) continue
    if (policy.allowHosts.length === 0) continue
    if (!policy.allowHosts.some(pattern => matchHost(host, pattern))) violations.push(host)
  }
  return { targets, violations }
}
