/**
 * Append-only JSONL audit sink.
 *
 * Every policy evaluation that had something to say lands here, including the
 * ones that only WOULD have acted in `monitor` mode. The sink never throws
 * into the tool pipeline: an unwritable log degrades to a warning, because a
 * failed audit write must not fail a user's tool call.
 *
 * @module dsh-egress-guard/audit
 */

import { appendFile, mkdir } from 'node:fs/promises'
import { dirname } from 'node:path'

/** One audited policy evaluation. */
export interface AuditRecord {
  /** ISO-8601 timestamp assigned when the record is queued. */
  ts: string
  /** Which rule produced the record. */
  kind: 'egress' | 'redact'
  /** The evaluated tool call. */
  tool: string
  /** Provider-issued call id, for correlation with the session log. */
  callId: string
  /**
   * What the guard did. `would-deny` and `would-redact` are the `monitor`-mode
   * counterparts of `deny` and `redact`; `allow` appears only when
   * `audit.logAllowed` is set.
   */
  decision: 'allow' | 'deny' | 'ask' | 'would-deny' | 'redact' | 'would-redact'
  /** Hosts named by the call (egress records). */
  hosts?: string[]
  /** Hosts that violated the policy (egress records). */
  violations?: string[]
  /** Pattern names that matched (redaction records). */
  patterns?: string[]
  /** Which projection was rewritten (redaction records). */
  projection?: 'value' | 'content' | 'feedback'
  /** First matching source text, truncated (egress records). */
  sample?: string
}

/** Sink interface, so the plugin can run with auditing switched off. */
export interface AuditSink {
  /** Queue one record. Never throws and never blocks the caller. */
  write(record: AuditRecord): void
  /** Await the queued writes; used by tests and by disposal. */
  flush(): Promise<void>
}

/** A sink that discards everything, used when `audit.enabled` is false. */
export const NULL_SINK: AuditSink = {
  write() { /* discarded by configuration */ },
  async flush() { /* nothing queued */ },
}

/**
 * Create a JSONL sink at `path`.
 *
 * Writes are serialized through one promise chain so concurrent tool calls
 * cannot interleave partial lines. The directory is created on first write.
 *
 * @param path - absolute or cwd-relative log path.
 * @param onError - reporter for a failed write (the plugin passes `ctx.logger`).
 * @returns the sink.
 */
export function createFileSink(path: string, onError: (message: string) => void): AuditSink {
  let chain: Promise<void> = Promise.resolve()
  let directoryReady = false
  let reportedFailure = false

  return {
    write(record: AuditRecord): void {
      const line = `${JSON.stringify(record)}\n`
      chain = chain.then(async () => {
        if (!directoryReady) {
          await mkdir(dirname(path), { recursive: true })
          directoryReady = true
        }
        await appendFile(path, line, 'utf8')
      }).catch((error: unknown) => {
        // Report once per sink: a permanently unwritable path would otherwise
        // emit one warning per tool call for the rest of the session.
        if (reportedFailure) return
        reportedFailure = true
        onError(`audit log write failed (${path}): ${error instanceof Error ? error.message : String(error)}`)
      })
    },
    async flush(): Promise<void> {
      await chain
    },
  }
}
