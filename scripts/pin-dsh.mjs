/**
 * Pin every `@deepseek-ai/dsh-*` package in the tree to one DSH release.
 *
 * The harness packages peer-depend on each other with `^<exact prerelease>`
 * ranges, so asking npm for a handful of them leaves the rest on the line
 * that is already installed and the resolution dies — or, worse, quietly
 * tests a mixed graph. Pinning has to happen through the manifest and a
 * clean resolve: this rewrites the harness devDependencies, adds an override
 * per family package that published the target version, reinstalls, and then
 * puts `package.json` and `package-lock.json` back so the working tree stays
 * clean. The installed `node_modules` is what the run then exercises.
 *
 * Usage: node scripts/pin-dsh.mjs 0.1.6-alpha.2
 */

import { execFileSync } from 'node:child_process'
import { readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'

const version = process.argv[2]
if (!version) {
  console.error('usage: node scripts/pin-dsh.mjs <dsh-version>')
  process.exit(1)
}

const registry = 'https://registry.npmjs.org'
const family = readdirSync('node_modules/@deepseek-ai').filter(name => name.startsWith('dsh-'))

const published = family.filter(name => {
  const out = execFileSync('npm', ['view', `@deepseek-ai/${name}`, 'versions', '--json', `--registry=${registry}`], {
    encoding: 'utf8',
  })
  return JSON.parse(out).includes(version)
})

const skipped = family.filter(name => !published.includes(name))
if (skipped.length > 0) console.log(`no ${version} release, left to resolve freely: ${skipped.join(', ')}`)

const manifest = readFileSync('package.json', 'utf8')
const lock = readFileSync('package-lock.json', 'utf8')
const pkg = JSON.parse(manifest)
for (const name of Object.keys(pkg.devDependencies)) {
  if (published.includes(name.replace('@deepseek-ai/', ''))) pkg.devDependencies[name] = version
}
pkg.overrides = Object.fromEntries(published.map(name => [`@deepseek-ai/${name}`, version]))

try {
  writeFileSync('package.json', `${JSON.stringify(pkg, null, 2)}\n`)
  rmSync('package-lock.json')
  rmSync('node_modules', { recursive: true, force: true })
  execFileSync('npm', ['install', '--no-audit', '--no-fund', `--registry=${registry}`], { stdio: 'inherit' })
} finally {
  writeFileSync('package.json', manifest)
  writeFileSync('package-lock.json', lock)
}

const resolved = JSON.parse(readFileSync('node_modules/@deepseek-ai/dsh-tools/package.json', 'utf8')).version
console.log(`dsh-tools resolved to ${resolved}`)
if (resolved !== version) {
  console.error(`expected ${version}`)
  process.exit(1)
}
