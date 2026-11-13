/**
 * `docs/operations.md`, held to the code it describes.
 *
 * Every log event the scanner and the egress proxy can write is collected from
 * the source with the TypeScript parser: each `log.info|warn|error('<msg>',
 * { fields })` call. The page must list exactly those events, each at its
 * level and with its fields. A new event, a renamed one or a new field fails
 * here until the page says so; an event the page still lists after the code
 * dropped it fails too.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';

import * as ts from 'typescript';

import { EXIT_CODE_TABLE } from '../src/exit-codes';
import { SUPPORT_SCHEMA } from '../src/support-bundle';

const REPO = path.resolve(__dirname, '../../..');
const SRC = path.join(REPO, 'packages/scanner/src');
const DOC = fs.readFileSync(path.join(REPO, 'docs/operations.md'), 'utf8');

interface LogEvent {
    readonly file: string;
    readonly level: 'info' | 'warn' | 'error';
    readonly msg: string;
    readonly fields: readonly string[];
}

function sourceFiles(dir: string): string[] {
    return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
        const child = path.join(dir, e.name);
        return e.isDirectory() ? sourceFiles(child) : child.endsWith('.ts') ? [child] : [];
    });
}

/** The property names of an object literal, following a spread of, or a reference to, an object literal declared in the same file. */
function fieldsOf(node: ts.Expression | undefined, file: ts.SourceFile): string[] {
    if (node === undefined) return [];
    if (ts.isIdentifier(node)) {
        let found: ts.Expression | undefined;
        const visit = (n: ts.Node): void => {
            if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.name.text === node.text && n.initializer !== undefined) found = n.initializer;
            ts.forEachChild(n, visit);
        };
        visit(file);
        if (found === undefined) throw new Error(`${file.fileName}: the log fields \`${node.text}\` are not declared in this file`);
        return fieldsOf(found, file);
    }
    if (!ts.isObjectLiteralExpression(node)) throw new Error(`${file.fileName}: log fields that are not an object literal: ${node.getText(file)}`);
    return node.properties.flatMap((p) => {
        if (ts.isSpreadAssignment(p)) return fieldsOf(p.expression, file);
        if (p.name === undefined || !(ts.isIdentifier(p.name) || ts.isStringLiteral(p.name))) throw new Error(`${file.fileName}: a log field with a computed name`);
        return [p.name.text];
    });
}

function logEvents(): LogEvent[] {
    const out: LogEvent[] = [];
    for (const file of sourceFiles(SRC)) {
        const source = ts.createSourceFile(file, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true);
        const visit = (node: ts.Node): void => {
            if (
                ts.isCallExpression(node) &&
                ts.isPropertyAccessExpression(node.expression) &&
                ['info', 'warn', 'error'].includes(node.expression.name.text) &&
                /log/i.test(node.expression.expression.getText(source))
            ) {
                const [msg, fields] = node.arguments;
                // A message built from data could carry anything: every event is a fixed text.
                if (msg === undefined || !(ts.isStringLiteral(msg) || ts.isNoSubstitutionTemplateLiteral(msg))) {
                    throw new Error(`${path.relative(REPO, file)}: a log message that is not a string literal: ${node.getText(source).slice(0, 80)}`);
                }
                out.push({
                    file: path.relative(SRC, file),
                    level: node.expression.name.text as LogEvent['level'],
                    msg: msg.text,
                    fields: fieldsOf(fields, source),
                });
            }
            ts.forEachChild(node, visit);
        };
        visit(source);
    }
    return out;
}

/** The event tables of the page: `| \`msg\` | level | fields | when |`. */
function documentedEvents(): { msg: string; level: string; fields: string[] }[] {
    return DOC.split('\n').flatMap((line) => {
        const m = /^\| `([^`]+)` \| (info|warn|error) \| (.*?) \| .* \|$/.exec(line);
        if (m === null) return [];
        return [{ msg: m[1], level: m[2], fields: [...m[3].matchAll(/`([a-zA-Z]+)` \(/g)].map((f) => f[1]) }];
    });
}

const events = logEvents();
const documented = documentedEvents();

describe('docs/operations.md, the log', () => {
    it('reads a real population of events from the source, in the scanner and in the proxy', () => {
        expect(events.length).toBeGreaterThanOrEqual(20);
        expect(new Set(events.map((e) => e.file))).toEqual(new Set(['cli.ts', 'egress-proxy.ts', 'outputs.ts', 'scan.ts', 'schedule.ts']));
        expect(documented.length).toBeGreaterThanOrEqual(15);
    });

    it('lists every event the code can write, at its level', () => {
        const inCode = [...new Set(events.map((e) => `${e.level}: ${e.msg}`))].sort();
        const inDoc = documented.map((e) => `${e.level}: ${e.msg}`).sort();
        expect(inDoc).toEqual(inCode);
    });

    it('lists no event twice', () => {
        const names = documented.map((e) => e.msg);
        expect(new Set(names).size).toBe(names.length);
    });

    it.each([...new Set(events.map((e) => e.msg))].sort())('names every field of "%s", and no other', (msg) => {
        const inCode = [...new Set(events.filter((e) => e.msg === msg).flatMap((e) => e.fields))].sort();
        const row = documented.find((e) => e.msg === msg);
        const line = DOC.split('\n').find((l) => l.startsWith(`| \`${msg}\` |`)) ?? '';
        if (inCode.length === 0) {
            expect(line).toContain('| none |');
            return;
        }
        // `source incomplete` is described as `source read`'s fields plus its own.
        const inherited = /the fields of `([^`]+)`/.exec(line)?.[1];
        const fromOther = inherited === undefined ? [] : (documented.find((e) => e.msg === inherited)?.fields ?? []);
        expect([...new Set([...(row?.fields ?? []), ...fromOther])].sort()).toEqual(inCode);
    });

    it('describes the three members every line has, and no line can carry another name for them', () => {
        for (const member of ['ts', 'level', 'msg']) expect(DOC).toContain(`| \`${member}\` | string |`);
        // An event's own field must not shadow one of the three.
        for (const e of events) for (const f of e.fields) expect(['ts', 'level', 'msg']).not.toContain(f);
    });

    it('names every reason the proxy refuses with', () => {
        const proxy = fs.readFileSync(path.join(SRC, 'egress-proxy.ts'), 'utf8');
        const reasons = [...new Set([...proxy.matchAll(/reason: '([A-Z_]+)'/g)].map((m) => m[1]))].sort();
        expect(reasons.length).toBeGreaterThanOrEqual(6);
        const row = DOC.split('\n').find((l) => l.startsWith('| `egress refused` |')) ?? '';
        expect([...new Set([...row.matchAll(/`([A-Z_]{5,})`/g)].map((m) => m[1]))].sort()).toEqual(reasons);
    });

    it('names both reasons the proxy closes a silent connection with', () => {
        const proxy = fs.readFileSync(path.join(SRC, 'egress-proxy.ts'), 'utf8');
        // The one place a closure is logged chooses between two reasons.
        const chosen = /log\.warn\('egress closed', \{ reason: established \? '([A-Z_]+)' : '([A-Z_]+)'/.exec(proxy);
        expect(chosen).not.toBeNull();
        expect((proxy.match(/'egress closed'/g) ?? []).length).toBe(1);
        const row = DOC.split('\n').find((l) => l.startsWith('| `egress closed` |')) ?? '';
        expect([...new Set([...row.matchAll(/`([A-Z_]{4,})`/g)].map((m) => m[1]))].sort()).toEqual([chosen?.[1], chosen?.[2]].sort());
    });
});

describe('docs/operations.md, the rest', () => {
    it('lists every exit code with its name, as the code defines them', () => {
        const rows = DOC.split('\n').flatMap((line) => {
            const m = /^\| (\d+) \| `([A-Z]+)` \| /.exec(line);
            return m === null ? [] : [{ code: Number(m[1]), name: m[2] }];
        });
        expect(rows).toEqual(EXIT_CODE_TABLE.map(({ code, name }) => ({ code, name })));
    });

    it('names the run\'s files as the scanner writes them', () => {
        for (const name of ['latest.json', 'report.signed.json', 'results.json', 'agents.csv', 'findings.csv', 'summary.html', 'report.pdf', 'manifest.json']) expect(DOC).toContain(name);
    });

    it('describes the support bundle by its schema, its members and its flags', () => {
        expect(DOC).toContain(`\`${SUPPORT_SCHEMA}\``);
        for (const member of ['versions', 'config', 'configProblem', 'environment', 'doctor', 'lastRun']) expect(DOC).toContain(`| \`${member}\` |`);
        for (const flag of ['--out <file>', '--runs <dir>', '--doctor', '--include-identifiers']) expect(DOC).toContain(`| \`${flag}\` |`);
        expect(DOC).toContain('lastRun.notRecorded');
    });
});
