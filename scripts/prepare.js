/**
 * Build `lib/` from `src/` after a git install.
 *
 * pnpm runs `prepare` for a git dependency, which is the only way an installed
 * checkout gets compiled output. It must be self-contained: no monorepo, no
 * workspace links, no assumptions about the caller's cwd. When TypeScript is
 * unavailable (an npm tarball install, where `lib/` already ships) it exits
 * successfully rather than failing the install.
 */

import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)))
const require = createRequire(join(packageRoot, 'package.json'))

let compiler
try {
  compiler = require.resolve('typescript/bin/tsc')
} catch {
  if (existsSync(join(packageRoot, 'lib', 'index.js'))) {
    console.log('[dsh-egress-guard] prepare: prebuilt lib/ present, skipping build')
    process.exit(0)
  }
  console.error('[dsh-egress-guard] prepare: typescript is not installed and lib/ is missing; run `npm install` first')
  process.exit(1)
}

const result = spawnSync(process.execPath, [compiler, '-p', join(packageRoot, 'tsconfig.build.json')], {
  cwd: packageRoot,
  stdio: 'inherit',
})
process.exit(result.status ?? 1)
