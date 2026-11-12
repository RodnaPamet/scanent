/**
 * The exit-code table: the values scripts depend on, and the documentation's
 * copy of it.
 */
import { readFileSync } from 'fs';
import { resolve } from 'path';

import { EXIT, EXIT_CODE_TABLE } from '../src/exit-codes';

describe('the exit codes', () => {
    it('are these values, and the first three are what they have always been', () => {
        expect(EXIT).toEqual({ OK: 0, FAILED: 1, USAGE: 2, INCOMPLETE: 3, CONFIG: 4, CREDENTIAL: 5, NETWORK: 6, SIGINT: 130, SIGTERM: 143 });
        expect(Object.isFrozen(EXIT)).toBe(true);
    });

    it('has one table row per code, each with a meaning', () => {
        expect(EXIT_CODE_TABLE.map((r) => [r.code, r.name])).toEqual(Object.entries(EXIT).map(([name, code]) => [code, name]));
        for (const row of EXIT_CODE_TABLE) expect(row.meaning.length).toBeGreaterThan(5);
    });

    it('docs/scanner.md lists the same codes and names', () => {
        const doc = readFileSync(resolve(__dirname, '..', '..', '..', 'docs', 'scanner.md'), 'utf8');
        const section = doc.slice(doc.indexOf('## Exit codes'));
        const rows = [...section.slice(0, section.indexOf('\n## ', 5) === -1 ? undefined : section.indexOf('\n## ', 5)).matchAll(/^\| (\d+) \| ([A-Z]+) \|/gm)].map((m) => [Number(m[1]), m[2]]);
        expect(rows).toEqual(EXIT_CODE_TABLE.map((r) => [r.code, r.name]));
    });
});
