import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

/** The repository root, found by walking up from the working directory (tests run from
 *  web/ or mobile/), so contract files are read from the checkout under test. */
export function repoRoot(): string {
  let dir = resolve(process.cwd());
  for (;;) {
    if (existsSync(join(dir, 'contracts', 'action', 'v1', 'action-result.schema.json'))) return dir;
    const up = dirname(dir);
    if (up === dir) throw new Error('repository root not found above ' + process.cwd());
    dir = up;
  }
}

export function readRepo(...parts: string[]): string {
  return readFileSync(join(repoRoot(), ...parts), 'utf8');
}
