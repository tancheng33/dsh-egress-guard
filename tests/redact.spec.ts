import { describe, expect, it } from 'vitest'
import { BUILTIN_PATTERNS, compilePatterns, redactContent, redactJson, redactText } from '../src/redact.js'
import {
  FAKE_API_KEY, FAKE_API_KEY_ALT, FAKE_AWS_KEY, FAKE_BEARER,
  FAKE_GITHUB_TOKEN, FAKE_GOOGLE_KEY, FAKE_JWT, FAKE_SLACK_TOKEN,
} from './fixtures.js'

const placeholder = '[redacted:{name}]'

describe('redactText', () => {
  it.each([
    ['openai-key', `export KEY=${FAKE_API_KEY}`],
    ['github-token', `token ${FAKE_GITHUB_TOKEN}`],
    ['aws-access-key', `aws_access_key_id ${FAKE_AWS_KEY}`],
    ['google-api-key', `key=${FAKE_GOOGLE_KEY}`],
    ['slack-token', FAKE_SLACK_TOKEN],
    ['jwt', `auth ${FAKE_JWT}`],
    ['bearer-token', `Authorization: ${FAKE_BEARER}`],
  ])('redacts a %s', (name, sample) => {
    const result = redactText(sample, BUILTIN_PATTERNS, placeholder)
    expect(result.hits).toContain(name)
    expect(result.value).toContain(`[redacted:${name}]`)
  })

  it('redacts a PEM private key block whole', () => {
    const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\nlines\n-----END RSA PRIVATE KEY-----'
    const result = redactText(`before\n${pem}\nafter`, BUILTIN_PATTERNS, placeholder)
    expect(result.value).toBe('before\n[redacted:private-key]\nafter')
  })

  it('keeps the key of a credential assignment and drops only the value', () => {
    const result = redactText('DEEPSEEK_API_KEY="hunter2hunter2hunter2"', BUILTIN_PATTERNS, placeholder)
    expect(result.value).toBe('DEEPSEEK_API_KEY="[redacted:credential-assignment]"')
  })

  it('leaves ordinary text untouched and reports no hits', () => {
    const text = 'commit 8f2a1c9 rewrote the parser; coverage 91.4%; see docs/architecture.md'
    const result = redactText(text, BUILTIN_PATTERNS, placeholder)
    expect(result.value).toBe(text)
    expect(result.hits).toEqual([])
  })

  it('does not redact hashes, uuids, or base64 payloads', () => {
    const text = [
      'sha256:9b74c9897bac770ffc029102a200c5de2b1a1a1e2b1a1a1e2b1a1a1e2b1a1a1e',
      '550e8400-e29b-41d4-a716-446655440000',
      'aGVsbG8gd29ybGQgdGhpcyBpcyBub3QgYSBzZWNyZXQ=',
    ].join('\n')
    expect(redactText(text, BUILTIN_PATTERNS, placeholder).hits).toEqual([])
  })

  it('is not order-dependent across repeated passes', () => {
    const sample = `a ${FAKE_API_KEY} b ${FAKE_API_KEY_ALT}`
    const first = redactText(sample, BUILTIN_PATTERNS, placeholder)
    const second = redactText(sample, BUILTIN_PATTERNS, placeholder)
    expect(first.value).toBe(second.value)
    expect(first.value).not.toContain('sk-')
  })

  it('applies custom patterns compiled from configuration', () => {
    const patterns = compilePatterns(['INTERNAL-[0-9]{4}'])
    const result = redactText('ticket INTERNAL-4211 filed', patterns, placeholder)
    expect(result.value).toBe('ticket [redacted:custom-1] filed')
  })
})

describe('redactJson', () => {
  it('rewrites strings at any depth and leaves keys alone', () => {
    const value = { env: { DEEPSEEK_API_KEY: FAKE_API_KEY }, notes: ['fine'] }
    const result = redactJson(value, BUILTIN_PATTERNS, placeholder)
    expect(result.value).toEqual({ env: { DEEPSEEK_API_KEY: '[redacted:openai-key]' }, notes: ['fine'] })
    expect(result.hits).toEqual(['openai-key'])
  })

  it('returns the identical reference when nothing matched', () => {
    const value = { a: ['b', { c: 1 }] }
    const result = redactJson(value, BUILTIN_PATTERNS, placeholder)
    expect(result.value).toBe(value)
    expect(result.hits).toEqual([])
  })

  it('handles non-string leaves', () => {
    const value = { n: 1, b: true, nil: null }
    expect(redactJson(value, BUILTIN_PATTERNS, placeholder).value).toBe(value)
  })
})

describe('redactContent', () => {
  it('rewrites text blocks and passes other block types through', () => {
    const blocks = [
      { type: 'text', text: `key ${FAKE_AWS_KEY}` },
      { type: 'image', source: 'data:image/png;base64,AAAA' },
    ]
    const result = redactContent(blocks, BUILTIN_PATTERNS, placeholder)
    expect(result.value[0]).toEqual({ type: 'text', text: 'key [redacted:aws-access-key]' })
    expect(result.value[1]).toBe(blocks[1])
    expect(result.hits).toEqual(['aws-access-key'])
  })

  it('reports no hits for clean content', () => {
    expect(redactContent([{ type: 'text', text: 'ok' }], BUILTIN_PATTERNS, placeholder).hits).toEqual([])
  })
})
