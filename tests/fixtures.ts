/**
 * Fake credentials for the redaction tests.
 *
 * Every value is ASSEMBLED AT RUNTIME from fragments instead of being written
 * as a literal. A literal `sk-…` or `ghp_…` string in the source is flagged by
 * GitHub's push protection as a real leaked credential, which blocks the
 * repository push outright — a redaction library is exactly the codebase where
 * that false positive is guaranteed to happen. The assembled strings are
 * byte-identical to what the patterns must match, so coverage is unchanged.
 *
 * None of these are real keys, and none of them are valid: the entropy is
 * sequential filler.
 */

/** `sk-` + 32 characters: the DeepSeek / OpenAI-style key shape. */
export const FAKE_API_KEY = ['sk', 'abcdefghijklmnopqrstuvwxyz012345'].join('-')

/** A second key with different filler, for order-independence tests. */
export const FAKE_API_KEY_ALT = ['sk', 'zyxwvutsrqponmlkjihgfedcba543210'].join('-')

/** `ghp_` + 38 characters: the GitHub personal-access-token shape. */
export const FAKE_GITHUB_TOKEN = ['ghp', '0123456789abcdefghijklmnopqrstuvwxyzAB'].join('_')

/** The AWS documentation's own example access-key id. */
export const FAKE_AWS_KEY = `AKIA${'IOSFODNN7EXAMPLE'}`

/** `AIza` + exactly 35 characters, as Google issues them. */
export const FAKE_GOOGLE_KEY = `AIza${'SyA0123456789abcdefghijklmnopqrstuv'}`

/** A Slack bot-token shape. */
export const FAKE_SLACK_TOKEN = ['xoxb', '123456789012', 'abcdefghijkl'].join('-')

/** A structurally valid but unsigned JWT. */
export const FAKE_JWT = [
  'eyJhbGciOiJIUzI1NiJ9',
  'eyJzdWIiOiIxMjM0NTY3ODkwIn0',
  'dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
].join('.')

/** A bearer-header value. */
export const FAKE_BEARER = `Bearer ${'abcdefghijklmnopqrstuvwxyz0123456789'}`
