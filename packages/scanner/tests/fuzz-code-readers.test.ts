/**
 * Hostile code: the readers of the `code` source over generated and mutated
 * text. A scanned repository is the estate's, and may be written by somebody
 * who wants the scanner to crash, hang, or read past what it was given.
 *
 *   1. `tokenizePython` and `readPython` return, or throw `PythonReadError`,
 *      and nothing else, on any text.
 *   2. `readJavaScript` returns, or throws `JavaScriptReadError`, and nothing
 *      else; and reading never evaluates what it reads.
 *   3. `recognizeAgents` never throws on facts either reader produced.
 *   4. Depth and size: nesting far past any real program, and a file at the
 *      size cap, each end in a bounded time with a typed outcome.
 *   5. The whole source: a root holding the worst of the above is INCOMPLETE
 *      `UNPARSEABLE`, and what else it read is still reported.
 *
 * Each property takes its seed and count from `helpers/prng.ts`; the cases a
 * property found are pinned by name below it.
 */
import { createSourceWire } from '../src/http';
import type { CodeFs } from '../src/sources/code/files';
import { MAX_FILE_BYTES } from '../src/sources/code/files';
import { callsWithin, type Expr, type FileFacts } from '../src/sources/code/ir';
import { JavaScriptReadError, readJavaScript } from '../src/sources/code/javascript';
import { PythonReadError, readPython, STEPS_PER_TOKEN, tokenizePython, workBudgetFor } from '../src/sources/code/python';
import * as recognize from '../src/sources/code/recognize';
import { recognizeAgents } from '../src/sources/code/recognize';
import { langchainCodeSource } from '../src/sources/langchain';
import {
    AGENT_SDK_PY,
    AGENT_SDK_TS,
    AGENT_SDK_UNRESOLVED,
    LANGCHAIN_JS,
    LANGCHAIN_PYTHON,
    LANGGRAPH,
    NOT_AGENT_SDK,
    NOT_LANGCHAIN,
    UNPARSEABLE,
} from './helpers/agent-harness-code-fixtures';
import { forAll, FUZZ_ITERATIONS, type Rng, TEST_TIMEOUT_MS } from './helpers/prng';

jest.setTimeout(TEST_TIMEOUT_MS);

const ALL = { ...LANGCHAIN_PYTHON, ...LANGCHAIN_JS, ...LANGGRAPH, ...UNPARSEABLE, ...NOT_LANGCHAIN, ...AGENT_SDK_TS, ...AGENT_SDK_PY, ...AGENT_SDK_UNRESOLVED, ...NOT_AGENT_SDK };
const PYTHON = Object.entries(ALL).filter(([name]) => name.endsWith('.py')).map(([, text]) => text);
const SCRIPT = Object.entries(ALL).filter(([name]) => !name.endsWith('.py') && /\.(m?[jt]sx?|c[jt]s)$/.test(name));

const FILE = { label: 'fuzz', path: 'agent.py' };

/** Python-shaped fragments: what a mutation alone seldom makes. */
const PY_FRAGMENTS = [
    'from langchain.agents import AgentExecutor\n', 'import langchain as lc\n', 'agent = AgentExecutor(agent=a, tools=[', '])\n', 'def f(x):\n    return x\n',
    'class T(BaseTool):\n    name = "t"\n', '"""', "'''", 'f"{', '}"', 'rb"\\', '\\\n', '    ', '\t', '@tool\n', 'lambda x: x', '[x for x in y if z]', '{**a, "k": v}',
    'x = (', ')', 'if a else b', 'await ', '0x1f', '1_000', '1e', '...', ':=', '->', '**=', 'match x:\n    case 1:\n        pass\n', '#', '\r\n', '\r', '\f', '\\N{DASH}',
    'os.environ["KEY"]', 'os.getenv("K")', 'tools=tools, llm=ChatOpenAI(model="m", api_key="k")\n',
];
const JS_FRAGMENTS = [
    'import { AgentExecutor } from "langchain/agents";\n', 'const { ChatOpenAI } = require("@langchain/openai");\n', 'export const a = new AgentExecutor({ agent, tools: [',
    '] });\n', 'query({ prompt: "p", options: { allowedTools: ["Read"] } })', '`${', '}`', '/*', '*/', '//', '<T>', 'as any', '!', '?.', '??=', '=>', 'class X extends Tool { name = "x" }',
    'process.env.KEY', 'await ', 'async function* g() { yield* h(); }', '#priv', '@dec', '</div>', '<div a={', '}/>', '/re/gu', '0b1', '1n', '...spread', 'satisfies T',
];

function generated(r: Rng, seeds: readonly string[], fragments: readonly string[]): string {
    const mode = r.int(0, 3);
    if (mode === 0) return r.mutateText(r.pick(seeds));
    if (mode === 1) return Array.from({ length: r.int(1, 40) }, () => r.pick(fragments)).join(r.pick(['', ' ', '\n']));
    if (mode === 2) return r.unicodeString(r.int(0, 400));
    return r.mutateText(r.pick(seeds)) + Array.from({ length: r.int(1, 10) }, () => r.pick(fragments)).join('');
}

/** Every node of an expression is one of the IR's kinds, with a line; and it is a tree a walk can end on. */
function assertWellFormed(facts: FileFacts): void {
    const seen = new Set<Expr>();
    let nodes = 0;
    const visit = (e: Expr, depth: number): void => {
        nodes += 1;
        if (nodes > 5_000_000) throw new Error('the facts hold more nodes than any input could');
        if (depth > 400) throw new Error('an expression nests deeper than the readers allow');
        if (typeof e.line !== 'number' || !Number.isInteger(e.line) || e.line < 0) throw new Error(`a node has line ${String(e.line)}`);
        if (seen.has(e)) return;
        seen.add(e);
        switch (e.k) {
            case 'call':
                visit(e.fn, depth + 1);
                e.args.forEach((a) => visit(a, depth + 1));
                for (const v of e.kwargs.values()) visit(v, depth + 1);
                break;
            case 'attr':
                visit(e.obj, depth + 1);
                break;
            case 'sub':
                visit(e.obj, depth + 1);
                visit(e.key, depth + 1);
                break;
            case 'list':
                e.items.forEach((i) => visit(i, depth + 1));
                break;
            case 'dict':
                e.entries.forEach(([, v]) => visit(v, depth + 1));
                break;
            case 'concat':
                e.parts.forEach((p) => visit(p, depth + 1));
                break;
            default:
                break;
        }
    };
    for (const list of facts.bindings.values()) for (const b of list) visit(b.expr, 0);
    for (const { call } of facts.calls) {
        visit(call, 0);
        callsWithin(call);
    }
}

describe('1. the Python reader', () => {
    it('tokenizes any text, or refuses it with PythonReadError', async () => {
        await forAll(
            'tokenizePython',
            (r) => generated(r, PYTHON, PY_FRAGMENTS),
            (src) => {
                try {
                    const toks = tokenizePython(src);
                    const lines = src.split('\n').length + src.split('\r').length;
                    for (const t of toks) if (t.line < 1 || t.line > lines + 1) throw new Error(`a token is on line ${t.line} of ${lines}`);
                } catch (err) {
                    if (!(err instanceof PythonReadError)) throw err;
                }
            },
        );
    });

    it('reads any text into well-formed facts, or refuses it with PythonReadError, and the recogniser takes whatever it reads', async () => {
        await forAll(
            'readPython',
            (r) => generated(r, PYTHON, PY_FRAGMENTS),
            (src) => {
                let facts: FileFacts;
                try {
                    facts = readPython(src);
                } catch (err) {
                    if (!(err instanceof PythonReadError)) throw err;
                    return;
                }
                assertWellFormed(facts);
                const found = recognizeAgents(facts, FILE);
                for (const agent of found.agents) if (!agent.discoveredId.startsWith('code:fuzz/agent.py#')) throw new Error('an agent is not named by its file');
            },
        );
    });
});

describe('2. the JavaScript and TypeScript reader', () => {
    it('reads any text into well-formed facts, or refuses it with JavaScriptReadError, and the recogniser takes whatever it reads', async () => {
        await forAll(
            'readJavaScript',
            (r) => {
                const [name, text] = r.pick(SCRIPT);
                return { name: r.pick([name, 'a.js', 'a.ts', 'a.tsx', 'a.jsx', 'a.mjs', 'a.cts']), src: generated(r, [text], JS_FRAGMENTS) };
            },
            ({ name, src }) => {
                let facts: FileFacts;
                try {
                    facts = readJavaScript(name, src);
                } catch (err) {
                    if (!(err instanceof JavaScriptReadError)) throw err;
                    return;
                }
                assertWellFormed(facts);
                recognizeAgents(facts, { label: 'fuzz', path: name });
            },
            // TypeScript's parser is the slow one: a fifth of the budget covers as much ground.
            { iterations: Math.max(40, Math.floor(FUZZ_ITERATIONS / 5)) },
        );
    });

    it('never evaluates what it reads: a planted side effect is not observed', () => {
        const marker = '__scanent_fuzz_side_effect__';
        const g = globalThis as Record<string, unknown>;
        delete g[marker];
        const planted = [
            `globalThis.${marker} = true;\nimport { AgentExecutor } from "langchain/agents";\nexport const a = new AgentExecutor({ agent: (globalThis.${marker} = 1), tools: [] });\n`,
            `(function(){ globalThis.${marker} = true; })();\nconst x = require("langchain/agents");\n`,
            `export const a = eval("globalThis.${marker} = true");\nimport "langchain";\n`,
        ];
        for (const src of planted) readJavaScript('agent.ts', src);
        readPython(`import langchain\n__import__("os").environ["${marker}"] = "1"\nexec("x = 1")\n`);
        expect(g[marker]).toBeUndefined();
        expect(process.env[marker]).toBeUndefined();
    });
});

describe('4. depth and size', () => {
    const DEEP = 200_000;
    const within = (ms: number, fn: () => void): number => {
        const t = process.hrtime.bigint();
        fn();
        const took = Number(process.hrtime.bigint() - t) / 1e6;
        expect(took).toBeLessThan(ms);
        return took;
    };
    const outcome = (fn: () => unknown, refusal: new (...args: never[]) => Error): string => {
        try {
            fn();
            return 'read';
        } catch (err) {
            if (err instanceof refusal) return 'refused';
            throw err;
        }
    };

    it.each([
        ['parentheses', `x = ${'('.repeat(DEEP)}1${')'.repeat(DEEP)}\n`],
        ['brackets', `x = ${'['.repeat(DEEP)}${']'.repeat(DEEP)}\n`],
        ['braces', `x = ${'{'.repeat(DEEP)}${'}'.repeat(DEEP)}\n`],
        ['calls', `x = ${'f('.repeat(DEEP)}${')'.repeat(DEEP)}\n`],
        ['attribute chain', `x = a${'.b'.repeat(DEEP)}\n`],
        ['unary minus', `x = ${'-'.repeat(DEEP)}1\n`],
        ['not', `x = ${'not '.repeat(DEEP)}1\n`],
        ['lambda', `x = ${'lambda: '.repeat(20_000)}1\n`],
        ['conditional', `x = 1${' if a else 1'.repeat(20_000)}\n`],
        ['indentation', `${Array.from({ length: 5_000 }, (_, i) => `${' '.repeat(i)}if x:\n`).join('')}${' '.repeat(5_000)}pass\n`],
        ['unclosed brackets', `x = ${'('.repeat(DEEP)}\n`],
        ['unterminated string', `x = "${'a'.repeat(DEEP)}\n`],
        ['one long line of operators', `x = 1${' + 1'.repeat(DEEP)}\n`],
    ])('Python nested %s deep is read or refused, never a stack overflow', (_label, src) => {
        expect(['read', 'refused']).toContain(outcome(() => readPython(`from langchain.agents import AgentExecutor\n${src}`), PythonReadError));
    });

    // Shapes that made the reader re-read the same tokens. Before the reader
    // remembered a conditional that was not one, the first doubled its work at
    // every level (depth 24 took seconds, depth 60 years) and the second took
    // over a minute for one file; neither could be interrupted, because the
    // read is synchronous. The time limit is the assertion.
    it.each([
        ['a conditional inside a lambda inside a conditional, 64 deep', `x = ${'a if lambda: '.repeat(64)}a\n`],
        ['the same, 20,000 deep', `x = ${'a if lambda: '.repeat(20_000)}a\n`],
        ['one line of chained conditionals filling the size cap', `x = a${' if a else a'.repeat(Math.floor((MAX_FILE_BYTES - 64) / 12))}\n`],
        ['a lambda in every bracket, each ending in an abandoned conditional', `x = ${'(lambda: a if '.repeat(60_000)}a${')'.repeat(60_000)}\n`],
        ['an abandoned conditional before every bracket', `x = ${'a if ('.repeat(100_000)}a${')'.repeat(100_000)}\n`],
        ['an abandoned conditional in every list', `x = ${'[a if '.repeat(100_000)}a${']'.repeat(100_000)}\n`],
    ])('Python with %s is read or refused within seconds', (_label, src) => {
        expect(Buffer.byteLength(src)).toBeLessThanOrEqual(MAX_FILE_BYTES);
        within(5_000, () => {
            expect(['read', 'refused']).toContain(outcome(() => readPython(`from langchain.agents import AgentExecutor\n${src}`), PythonReadError));
        });
    });

    it('a file that costs more to read than its size allows is refused, and an ordinary file is nowhere near the budget', () => {
        // Nested brackets inside abandoned conditionals are skipped once per
        // level of nesting: within the depth cap, but far over the budget.
        const costly = `x = ${'a if ('.repeat(100_000)}a${')'.repeat(100_000)}\n`;
        expect(() => readPython(costly)).toThrow(PythonReadError);
        expect(() => readPython(costly)).toThrow(/costs more to read than its size allows/);
        // The same statement many times costs about one step a token.
        const line = 'agent = AgentExecutor(agent=make(llm, tools), tools=[a if b else c for d in e if f], k=lambda: g if h else i)\n';
        const tokens = tokenizePython(line.repeat(2_000)).length;
        expect(tokens * 3).toBeLessThan(workBudgetFor(tokens).left);
        expect(readPython(`from langchain.agents import AgentExecutor\n${line.repeat(2_000)}`).calls.length).toBeGreaterThanOrEqual(2_000);
        expect(STEPS_PER_TOKEN).toBeLessThanOrEqual(64);
    });

    it('a conditional is still read as one whose value is not known, chained or not', () => {
        const value = (src: string) => readPython(src).bindings.get('x')?.[0].expr;
        expect(value('x = "a" if c else "b"\n')?.k).toBe('opaque');
        expect(value('x = "a" if c else "b" if d else "e"\n')?.k).toBe('opaque');
        expect(value('x = f(lambda: "a" if c else "b")\n')?.k).toBe('call');
        // A comprehension's filter is not a conditional: the list is still a comprehension.
        expect(value('x = [a for a in b if c]\n')?.k).toBe('opaque');
        expect(value('x = "a"\n')).toMatchObject({ k: 'str', value: 'a' });
    });

    it.each([
        ['parentheses', `const x = ${'('.repeat(DEEP)}1${')'.repeat(DEEP)};\n`],
        ['arrays', `const x = ${'['.repeat(DEEP)}${']'.repeat(DEEP)};\n`],
        ['objects', `const x = ${'{a:'.repeat(DEEP)}1${'}'.repeat(DEEP)};\n`],
        ['calls', `const x = ${'f('.repeat(DEEP)}${')'.repeat(DEEP)};\n`],
        ['member chain', `const x = a${'.b'.repeat(DEEP)};\n`],
        ['binary plus', `const x = 1${' + 1'.repeat(DEEP)};\n`],
        ['blocks', `${'{'.repeat(DEEP)}${'}'.repeat(DEEP)}\n`],
        ['arrow functions', `const x = ${'() => '.repeat(DEEP)}1;\n`],
        ['template literals', `const x = ${'`${'.repeat(20_000)}1${'}`'.repeat(20_000)};\n`],
        ['generics', `const x: ${'A<'.repeat(DEEP)}B${'>'.repeat(DEEP)} = 1;\n`],
        ['unclosed brackets', `const x = ${'('.repeat(DEEP)}\n`],
    ])('TypeScript nested %s deep is read or refused, never a stack overflow', (_label, src) => {
        expect(['read', 'refused']).toContain(outcome(() => readJavaScript('agent.ts', `import { AgentExecutor } from "langchain/agents";\n${src}`), JavaScriptReadError));
    });

    it('a file at the size cap is read in bounded time, and twice the text takes about twice as long', () => {
        // Linear, not quadratic: the ratio of times for 1x and 4x the input stays far under 16.
        const line = 'agent = AgentExecutor(agent=make(llm, tools), tools=[search, lookup], verbose=True)  # a comment\n';
        const head = 'from langchain.agents import AgentExecutor\n';
        const make = (bytes: number) => head + line.repeat(Math.floor((bytes - head.length) / line.length));
        const quarter = make(MAX_FILE_BYTES / 4);
        const full = make(MAX_FILE_BYTES);
        readPython(quarter); // warm
        const small = within(5_000, () => readPython(quarter));
        const large = within(20_000, () => readPython(full));
        expect(large / Math.max(small, 1)).toBeLessThan(12);

        const jsLine = 'export const agent = new AgentExecutor({ agent: make(llm, tools), tools: [search, lookup] }); // c\n';
        const js = `import { AgentExecutor } from "langchain/agents";\n${jsLine.repeat(Math.floor(MAX_FILE_BYTES / jsLine.length) - 1)}`;
        within(20_000, () => readJavaScript('agent.ts', js));
    });

    it.each([
        ['a megabyte of one token', 'a'.repeat(MAX_FILE_BYTES)],
        ['a megabyte of quotes', '"'.repeat(MAX_FILE_BYTES)],
        ['a megabyte of backslashes', '\\'.repeat(MAX_FILE_BYTES)],
        ['a megabyte of newlines', '\n'.repeat(MAX_FILE_BYTES)],
        ['a megabyte of opening brackets', '('.repeat(MAX_FILE_BYTES)],
        ['a megabyte of hashes and carriage returns', '#\r'.repeat(MAX_FILE_BYTES / 2)],
        ['a megabyte of spaces then a name', `${' '.repeat(MAX_FILE_BYTES - 2)}x\n`],
        ['a megabyte of NULs', '\u0000'.repeat(MAX_FILE_BYTES)],
        ['a megabyte of f-string openers', 'f"{'.repeat(MAX_FILE_BYTES / 3)],
    ])('%s ends in bounded time in both readers', (_label, text) => {
        within(20_000, () => outcome(() => readPython(text), PythonReadError));
        within(20_000, () => outcome(() => readJavaScript('a.ts', text), JavaScriptReadError));
    });
});

describe('5. the whole source over hostile files', () => {
    const NOW = Date.parse('2026-10-19T03:00:00.000Z');
    const noNetwork = async (): Promise<Response> => {
        throw new Error('the code source reaches no network');
    };
    const fsOf = (files: Record<string, string | Buffer>): CodeFs => ({
        async lstat(path) {
            const isRoot = path === '/root';
            const data = files[path.slice('/root/'.length)];
            if (!isRoot && data === undefined) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
            return { isDirectory: () => isRoot, isFile: () => !isRoot, isSymbolicLink: () => false, size: isRoot ? 0 : Buffer.byteLength(data) };
        },
        async readdir() {
            return Object.keys(files);
        },
        async readFile(path) {
            const data = files[path.slice('/root/'.length)];
            return Buffer.isBuffer(data) ? data : Buffer.from(data);
        },
    });
    const read = (files: Record<string, string | Buffer>) =>
        langchainCodeSource({ roots: [{ label: 'hostile', path: '/root' }], fs: fsOf(files) }).read({
            asOf: new Date(NOW),
            deadline: NOW + 60_000,
            now: () => NOW,
            ...createSourceWire({ fetchImpl: noNetwork, deadline: NOW + 60_000, now: () => NOW }),
        });
    const GOOD = LANGCHAIN_PYTHON[Object.keys(LANGCHAIN_PYTHON)[0]];

    it('the fixture agent is found when it is alone', async () => {
        const alone = await read({ 'good.py': GOOD });
        expect(alone.status).toBe('COMPLETE');
        expect(alone.observations.length).toBeGreaterThan(0);
    });

    it.each([
        ['a deeply nested TypeScript file', { 'deep.ts': `import "langchain";\nconst x = ${'['.repeat(200_000)}${']'.repeat(200_000)};\n` }],
        ['a binary file with a source name', { 'blob.py': Buffer.concat([Buffer.from('langchain\n'), Buffer.from(Array.from({ length: 4096 }, (_, i) => (i * 37) % 256))]) }],
        ['invalid UTF-8', { 'bad.py': Buffer.concat([Buffer.from('import langchain\nx = "'), Buffer.from([0xff, 0xfe, 0xc0, 0x80, 0xed, 0xa0, 0x80]), Buffer.from('"\nagent = (\n')]) }],
    ])('%s beside a good file: the source is INCOMPLETE UNPARSEABLE and the good file is still reported', async (_label, hostile) => {
        const alone = await read({ 'good.py': GOOD });
        const result = await read({ ...hostile, 'good.py': GOOD });
        expect(result.status).toBe('INCOMPLETE');
        expect(result.reason).toBe('UNPARSEABLE');
        expect(result.observations.map((o) => o.discoveredId)).toEqual(alone.observations.map((o) => o.discoveredId));
        expect(result.rows).toBe(2);
    });

    // Found by the depth cases above: a line of prefix operators overflowed the
    // stack in the Python reader, the throw ended the source's read, and every
    // agent found in the other files was lost with it (reported UNREACHABLE,
    // zero agents). It is an expression the reader cannot resolve and nothing more.
    it.each([
        ['a hundred thousand unary minuses', `import langchain\nx = ${'-'.repeat(100_000)}1\n`],
        ['a hundred thousand nots', `import langchain\nx = ${'not '.repeat(100_000)}1\n`],
        ['two hundred thousand parentheses', `import langchain\nx = ${'('.repeat(200_000)}1${')'.repeat(200_000)}\n`],
    ])('a Python file holding %s is read, and the good file beside it is still reported', async (_label, text) => {
        const alone = await read({ 'good.py': GOOD });
        const result = await read({ 'deep.py': text, 'good.py': GOOD });
        expect(result.status).toBe('COMPLETE');
        expect(result.observations.map((o) => o.discoveredId)).toEqual(alone.observations.map((o) => o.discoveredId));
    });

    it('a fault in a reader on one file is that file not read, never the end of the source', async () => {
        // No input is known to make the recogniser throw; if one ever does, it must cost that file and no other.
        const real = recognize.recognizeAgents;
        const spy = jest.spyOn(recognize, 'recognizeAgents').mockImplementation((facts, file) => {
            if (file.path === 'odd.py') throw new TypeError('a fault in the recogniser');
            return real(facts, file);
        });
        try {
            const alone = await read({ 'good.py': GOOD });
            const result = await read({ 'good.py': GOOD, 'odd.py': GOOD });
            expect(result).toMatchObject({ status: 'INCOMPLETE', reason: 'UNPARSEABLE', rows: 2 });
            expect(result.observations.map((o) => o.discoveredId)).toEqual(alone.observations.map((o) => o.discoveredId));
        } finally {
            spy.mockRestore();
        }
    });

    it.each([
        ['UTF-16 little-endian with a byte-order mark', Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(GOOD, 'utf16le')])],
        ['UTF-16 big-endian with a byte-order mark', Buffer.concat([Buffer.from([0xfe, 0xff]), Buffer.from(GOOD, 'utf16le').swap16()])],
    ])('a source file in %s is not passed over in silence: it could not be read as text', async (_label, data) => {
        const result = await read({ 'wide.py': data, 'good.py': GOOD });
        expect(result).toMatchObject({ status: 'INCOMPLETE', reason: 'UNPARSEABLE', rows: 2 });
        expect(result.observations.length).toBeGreaterThan(0);
    });

    it('generated files never take the source down: it answers COMPLETE or INCOMPLETE with a contract reason', async () => {
        await forAll(
            'code source over generated files',
            (r) => Object.fromEntries(Array.from({ length: r.int(1, 4) }, (_, i) => [`f${i}.${r.pick(['py', 'ts', 'js', 'tsx'])}`, `langchain\n${generated(r, [...PYTHON, ...SCRIPT.map(([, t]) => t)], [...PY_FRAGMENTS, ...JS_FRAGMENTS])}`])),
            async (files) => {
                const result = await read(files);
                if (result.status === 'INCOMPLETE' && result.reason !== 'UNPARSEABLE') throw new Error(`reason ${String(result.reason)}`);
                if (result.rows !== Object.keys(files).length) throw new Error('a file was not counted');
            },
            { iterations: Math.max(40, Math.floor(FUZZ_ITERATIONS / 5)) },
        );
    });
});
