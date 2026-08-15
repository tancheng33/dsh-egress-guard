/**
 * The audit log through the real pipeline: a denied call and a redacted call
 * must each leave exactly one record, with the fields an operator greps for.
 * The unit tests in `audit.spec.ts` cover the sink itself; these cover the
 * wiring between a decision and a line on disk.
 */

import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import { CallId } from '@deepseek-ai/dsh-llm'
import SystemPrompt from '@deepseek-ai/dsh-system-prompt'
import ToolRuntime, { defineTool } from '@deepseek-ai/dsh-tools'
import { FAKE_API_KEY } from './fixtures.js'
import * as EgressGuard from '../src/index.js'
import type { AuditRecord, Config } from '../src/index.js'

const signal = new AbortController().signal

const echo = defineTool({
  name: 'echo',
  description: 'echo the text back',
  parameters: { text: { type: 'string', required: true } },
  output: {
    schema: { type: 'string' },
    render: (_args, value) => [{ type: 'text', text: value }],
  },
  async execute(args) {
    return args.text
  },
})

/**
 * Boot a context whose guard audits to a fresh temp file.
 *
 * @param config - guard configuration except the audit path.
 * @returns the context, the log path, and the plugin fork (dispose flushes).
 */
async function setup(config: Record<string, unknown>) {
  const dir = await mkdtemp(join(tmpdir(), 'egress-guard-audit-'))
  const path = join(dir, 'audit.jsonl')
  const ctx = new Context()
  await ctx.plugin(SystemPrompt)
  await ctx.plugin(ToolRuntime)
  const fork = await ctx.plugin(EgressGuard, {
    ...config,
    audit: { enabled: true, path, logAllowed: config['logAllowed'] === true },
  } as unknown as Config)
  ctx.tools.register(echo)
  return { ctx, path, fork }
}

/** Read the log after disposal, which flushes the queued writes. */
async function readRecords(path: string, fork: { dispose(): Promise<unknown> }): Promise<AuditRecord[]> {
  await fork.dispose()
  const text = await readFile(path, 'utf8')
  return text.trim().split('\n').filter(Boolean).map(line => JSON.parse(line) as AuditRecord)
}

function call(ctx: Context, args: Record<string, unknown>) {
  return ctx.tools.execute({ callId: CallId('audit-test'), name: 'echo', arguments: args, signal })
}

describe('audit log through the pipeline', () => {
  it('records a denial with the offending host and a sample', async () => {
    const { ctx, path, fork } = await setup({ mode: 'enforce', egress: { allowHosts: ['*.github.com'] } })
    await call(ctx, { text: 'curl https://paste.example.com/x' })

    const records = await readRecords(path, fork)
    expect(records).toHaveLength(1)
    expect(records[0]).toMatchObject({
      kind: 'egress',
      tool: 'echo',
      callId: 'audit-test',
      decision: 'deny',
      violations: ['paste.example.com'],
    })
    expect(records[0]?.sample).toContain('paste.example.com')
    expect(records[0]?.ts).toMatch(/^\d{4}-\d{2}-\d{2}T/)
  })

  it('records monitor-mode decisions as "would-" variants', async () => {
    const { ctx, path, fork } = await setup({ mode: 'monitor', egress: { allowHosts: ['*.github.com'] } })
    await call(ctx, { text: 'curl https://paste.example.com/x' })
    await call(ctx, { text: FAKE_API_KEY })

    const records = await readRecords(path, fork)
    expect(records.map(record => record.decision)).toEqual(['would-deny', 'would-redact'])
  })

  it('records a redaction with the patterns that fired and the projection used', async () => {
    const { ctx, path, fork } = await setup({ mode: 'enforce' })
    await call(ctx, { text: `key ${FAKE_API_KEY}` })

    const records = await readRecords(path, fork)
    expect(records).toHaveLength(1)
    expect(records[0]).toMatchObject({
      kind: 'redact',
      decision: 'redact',
      patterns: ['openai-key'],
      projection: 'value',
    })
  })

  it('stays silent for a clean call', async () => {
    const { ctx, path, fork } = await setup({ mode: 'enforce', egress: { allowHosts: ['*.github.com'] } })
    await call(ctx, { text: 'ls -la' })
    await call(ctx, { text: 'curl https://api.github.com/user' })

    await fork.dispose()
    await expect(readFile(path, 'utf8')).rejects.toThrow(/ENOENT/)
  })

  it('records passing calls when logAllowed is set', async () => {
    const { ctx, path, fork } = await setup({
      mode: 'enforce',
      egress: { allowHosts: ['*.github.com'] },
      logAllowed: true,
    })
    await call(ctx, { text: 'curl https://api.github.com/user' })

    const records = await readRecords(path, fork)
    expect(records).toHaveLength(1)
    expect(records[0]).toMatchObject({ decision: 'allow', hosts: ['api.github.com'] })
  })

  it('never writes when auditing is disabled', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'egress-guard-audit-'))
    const path = join(dir, 'audit.jsonl')
    const ctx = new Context()
    await ctx.plugin(SystemPrompt)
    await ctx.plugin(ToolRuntime)
    await ctx.plugin(EgressGuard, {
      mode: 'enforce',
      egress: { allowHosts: [] },
      audit: { enabled: false, path, logAllowed: true },
    } as unknown as Config)
    ctx.tools.register(echo)

    await call(ctx, { text: `curl https://paste.example.com/x ${FAKE_API_KEY}` })
    await expect(readFile(path, 'utf8')).rejects.toThrow(/ENOENT/)
  })
})
