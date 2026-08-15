import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { createFileSink, NULL_SINK } from '../src/audit.js'
import { resolveAuditPath } from '../src/index.js'

describe('createFileSink', () => {
  it('appends one JSON object per line, in order', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'egress-guard-'))
    const path = join(dir, 'nested', 'audit.jsonl')
    const sink = createFileSink(path, () => { throw new Error('should not report an error') })

    sink.write({ ts: '2026-08-15T00:00:00.000Z', kind: 'egress', tool: 'bash', callId: 'a', decision: 'deny' })
    sink.write({ ts: '2026-08-15T00:00:01.000Z', kind: 'redact', tool: 'read', callId: 'b', decision: 'redact' })
    await sink.flush()

    const lines = (await readFile(path, 'utf8')).trim().split('\n')
    expect(lines).toHaveLength(2)
    expect(JSON.parse(lines[0] ?? '')).toMatchObject({ tool: 'bash', decision: 'deny' })
    expect(JSON.parse(lines[1] ?? '')).toMatchObject({ tool: 'read', decision: 'redact' })
  })

  it('reports an unwritable path once and never throws at the call site', async () => {
    const messages: string[] = []
    // A path whose parent is an existing FILE, so mkdir cannot create it.
    const dir = await mkdtemp(join(tmpdir(), 'egress-guard-'))
    await writeFile(join(dir, 'blocker'), 'not a directory', 'utf8')
    const sink = createFileSink(join(dir, 'blocker', 'log.jsonl'), message => messages.push(message))

    expect(() => {
      sink.write({ ts: 'x', kind: 'egress', tool: 't', callId: 'c', decision: 'deny' })
      sink.write({ ts: 'y', kind: 'egress', tool: 't', callId: 'd', decision: 'deny' })
    }).not.toThrow()
    await sink.flush()

    expect(messages).toHaveLength(1)
    expect(messages[0]).toContain('audit log write failed')
  })
})

describe('NULL_SINK', () => {
  it('discards writes without error', async () => {
    NULL_SINK.write({ ts: 'x', kind: 'egress', tool: 't', callId: 'c', decision: 'allow' })
    await expect(NULL_SINK.flush()).resolves.toBeUndefined()
  })
})

describe('resolveAuditPath', () => {
  it('prefers an explicit path', () => {
    expect(resolveAuditPath('  /var/log/guard.jsonl ', {})).toBe('/var/log/guard.jsonl')
  })

  it('falls back to $DSH_HOME', () => {
    expect(resolveAuditPath('', { DSH_HOME: '/custom/home' })).toBe('/custom/home/egress-guard.jsonl')
  })

  it('falls back to ~/.dsh when DSH_HOME is unset or blank', () => {
    expect(resolveAuditPath('', { DSH_HOME: '   ' })).toMatch(/[/\\]\.dsh[/\\]egress-guard\.jsonl$/)
    expect(resolveAuditPath('', {})).toMatch(/[/\\]\.dsh[/\\]egress-guard\.jsonl$/)
  })
})
