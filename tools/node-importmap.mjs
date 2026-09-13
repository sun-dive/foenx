// Lets Node run the page's modules unchanged: resolves the bare '@noble/hashes/*' specifiers the engine
// imports to the vendored files, exactly as the page's import map does.
//   node --import ./tools/node-importmap.mjs some-script.mjs
import { register } from 'node:module'
import { pathToFileURL } from 'node:url'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
register('data:text/javascript,' + encodeURIComponent(`
  const VENDOR = ${JSON.stringify(pathToFileURL(join(root, 'site/js/vendor/noble-hashes/')).href)}
  export async function resolve(spec, ctx, next) {
    if (spec.startsWith('@noble/hashes/')) return { url: VENDOR + spec.slice('@noble/hashes/'.length), shortCircuit: true }
    return next(spec, ctx)
  }
`), import.meta.url)
