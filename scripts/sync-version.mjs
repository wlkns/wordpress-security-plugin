#!/usr/bin/env node
/**
 * Propagate the version from package.json into the WordPress plugin files.
 *
 * Run automatically by npm's `version` lifecycle (i.e. `npm version patch|minor|major`),
 * after package.json is bumped but before the release commit + git tag are created.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const { version } = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));

if (!/^\d+\.\d+\.\d+$/.test(version)) {
  console.error(`Refusing to sync: "${version}" is not a plain x.y.z version.`);
  process.exit(1);
}

/** Apply a single replacement, erroring if the pattern is missing. */
function patch(contents, file, label, pattern, replacement) {
  if (!pattern.test(contents)) {
    console.error(`Could not find ${label} in ${file} — aborting before any commit.`);
    process.exit(1);
  }
  return contents.replace(pattern, replacement);
}

const edits = [
  {
    file: 'wlkns-security.php',
    apply: (c, f) => {
      c = patch(c, f, 'plugin header "Version:"', /(\*\s*Version:\s*)\d+\.\d+\.\d+/, `$1${version}`);
      c = patch(c, f, 'WLKNS_WWS_VERSION constant', /(define\('WLKNS_WWS_VERSION',\s*')\d+\.\d+\.\d+('\))/, `$1${version}$2`);
      return c;
    },
  },
  {
    file: 'README.md',
    apply: (c, f) => patch(c, f, '"Stable tag" table row', /(\*\*Stable tag\*\*\s*\|\s*)\d+\.\d+\.\d+/, `$1${version}`),
  },
];

for (const { file, apply } of edits) {
  const path = resolve(root, file);
  const updated = apply(readFileSync(path, 'utf8'), file);
  writeFileSync(path, updated);
  console.log(`Synced ${file} -> ${version}`);
}
