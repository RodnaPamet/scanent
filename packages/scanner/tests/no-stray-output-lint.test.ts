/**
 * The lint boundary on what prints: under `packages/<name>/src`, only `cli.ts`,
 * `log.ts` and `outputs.ts` may write to the console or to the process's own
 * stdout and stderr.
 *
 * The secret-canary suites watch the sinks a run is handed: its files, its
 * stdout callback, its log, a thrown message. A source that wrote a
 * credential or a response body straight to the process would pass all of
 * them. This runs the real ESLint, as configured, over a probe that does
 * exactly that, at a path in each package, and over the same text at the
 * three paths that are allowed to.
 *
 * The probe is passed on stdin: no file is written into the source tree.
 */
import { execFileSync } from 'node:child_process';
import * as path from 'node:path';

const REPO_ROOT = path.resolve(__dirname, '../../..');
const ESLINT = path.join(REPO_ROOT, 'node_modules', 'eslint', 'bin', 'eslint.js');

const PROBE = `export function leak(headers: Record<string, string>, body: string): void {
    console.error('source refused', JSON.stringify(headers));
    console.log(body);
    console.warn(body);
    console.info(body);
    console.debug(body);
    process.stderr.write(body);
    process.stdout.write(body);
    const out = process.stdout;
    out.write(body);
}
`;

interface LintMessage {
    readonly ruleId: string | null;
    readonly line: number;
}

function lint(filePath: string): LintMessage[] {
    let out: string;
    try {
        out = execFileSync(process.execPath, [ESLINT, '--stdin', '--stdin-filename', filePath, '--format', 'json'], {
            cwd: REPO_ROOT,
            input: PROBE,
            encoding: 'utf8',
            stdio: ['pipe', 'pipe', 'pipe'],
        });
    } catch (err) {
        // ESLint exits 1 when it reports errors, with the report on stdout.
        out = (err as { stdout?: string }).stdout ?? '';
    }
    const [result] = JSON.parse(out) as { messages: LintMessage[] }[];
    return result.messages;
}

const lineOf = (text: string): number => PROBE.split('\n').findIndex((l) => l.includes(text)) + 1;
const PRINTING = ['console.error(', 'console.log(', 'console.warn(', 'console.info(', 'console.debug('] as const;
const STREAMS = ['process.stderr.write(', 'process.stdout.write(', 'const out = process.stdout'] as const;

describe.each([
    ['a source', 'packages/scanner/src/sources/probe.ts'],
    ['the wire', 'packages/scanner/src/http-probe.ts'],
    ['the code reader', 'packages/scanner/src/sources/code/probe.ts'],
    ['the contract', 'packages/contract/src/probe.ts'],
])('in %s (%s)', (_label, file) => {
    const messages = lint(file);
    const at = (text: string) => messages.filter((m) => m.line === lineOf(text)).map((m) => m.ruleId);

    it.each(PRINTING)('%s is refused', (text) => {
        expect(lineOf(text)).toBeGreaterThan(0);
        expect(at(text)).toContain('no-console');
    });

    it.each(STREAMS)('%s is refused', (text) => {
        expect(lineOf(text)).toBeGreaterThan(0);
        expect(at(text)).toContain('no-restricted-properties');
    });
});

describe('in the report package', () => {
    const messages = lint('packages/report/src/results/probe.ts');
    const at = (text: string) => messages.filter((m) => m.line === lineOf(text)).map((m) => m.ruleId);

    it.each(PRINTING)('%s is refused', (text) => {
        expect(at(text)).toContain('no-console');
    });

    it.each(STREAMS)('%s is refused: the package may not name the process at all', (text) => {
        expect(at(text)).toContain('no-restricted-globals');
    });
});

describe.each(['packages/scanner/src/cli.ts', 'packages/scanner/src/log.ts', 'packages/scanner/src/outputs.ts'])('in %s, one of the three files that print', (file) => {
    it('the same text is refused nothing', () => {
        expect(lint(file).map((m) => [m.line, m.ruleId])).toEqual([]);
    });
});
