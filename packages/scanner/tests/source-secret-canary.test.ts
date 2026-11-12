/**
 * NOTHING SECRET-SHAPED FROM A SOURCE REACHES AN OUTPUT.
 *
 * `output-secret-canary.test.ts` plants a canary where a renderer would meet
 * it. This suite plants one where an estate could: in every string of every
 * response every source reads, one string at a time, and in the response
 * headers and error bodies a scan or a preflight can be answered with.
 *
 * For each planted canary, a whole run (`scan` to a directory and to stdout)
 * ends one of two ways, and never a third:
 *
 *   • the string was not kept, and the canary is in no file, not on stdout and
 *     in no log line; or
 *   • the string is one the report carries (an id, a tool's name), and the run
 *     is refused: the refusal names the member, never the value, and nothing
 *     is written.
 *
 * Then the credentials the scanner is given: with each source failing in turn,
 * and with a server that echoes the credential back in its error, none of them
 * is in any output of `scan`, `doctor`, `hosts` or `diff`.
 *
 * The canaries come from `helpers/output-fixtures.ts`, built from parts at run
 * time, so this file holds no secret-shaped literal.
 */
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { parseScannerConfig } from '../src/config';
import { runDiff } from '../src/diff-command';
import { renderDoctorJson, renderDoctorText } from '../src/doctor/render';
import { runDoctor } from '../src/doctor/run';
import { hostsFor, renderHosts } from '../src/hosts';
import type { FetchLike } from '../src/http';
import { scanAndDeliver } from '../src/outputs';
import { ReportRefusedLocally } from '../src/report';
import {
    AZURE_ACCESS_TOKEN_VALUE,
    GRAPH_ACCESS_TOKEN_VALUE,
    langSmithFixture,
    LANGSMITH_US,
    NEVER_REPORTED,
    REGISTER_EXCHANGED_TOKEN,
} from './helpers/agent-harness-source-fakes';
import { GOOGLE_ACCESS_TOKEN_VALUE, WORLD_SECRETS } from './helpers/doctor-world';
import { createEstateWorld, ESTATE_SOURCE_KINDS, ESTATE_SOURCES, estateConfig, estateEnv, PUBLIC_RESOLVER } from './helpers/estate-world';
import { CANARIES, capturedLog, tree } from './helpers/output-fixtures';
import { LONG, TEST_TIMEOUT_MS } from './helpers/prng';

jest.setTimeout(TEST_TIMEOUT_MS);

const NOW = Date.parse('2026-10-19T03:00:00.000Z');
const SOURCES = ESTATE_SOURCE_KINDS.map((kind) => ESTATE_SOURCES[kind]);

let base: string;
let runs = 0;
beforeAll(() => {
    base = mkdtempSync(join(tmpdir(), 'scanent-source-canary-'));
});
afterAll(() => {
    rmSync(base, { recursive: true, force: true });
});

const worldFor = () => createEstateWorld({ fakes: { langsmith: { [LANGSMITH_US]: langSmithFixture() } } });

/** One request's identity across runs: sources are read in parallel, so an index would not be stable. */
function signatureOf(url: string, init: RequestInit, counts: Map<string, number>): string {
    let rpc = '';
    try {
        rpc = String((JSON.parse(String(init.body ?? '')) as { method?: unknown }).method ?? '');
    } catch {
        rpc = '';
    }
    const u = new URL(url);
    const key = `${(init.method ?? 'GET').toUpperCase()} ${u.origin}${u.pathname}${u.search} ${rpc}`;
    const n = (counts.get(key) ?? 0) + 1;
    counts.set(key, n);
    return `${key}#${n}`;
}

type Path = readonly (string | number)[];

function stringPaths(value: unknown, at: Path = []): Path[] {
    if (typeof value === 'string') return [at];
    if (Array.isArray(value)) return value.flatMap((v, i) => stringPaths(v, [...at, i]));
    if (value !== null && typeof value === 'object') return Object.entries(value).flatMap(([k, v]) => stringPaths(v, [...at, k]));
    return [];
}

function setAt(value: unknown, at: Path, replacement: string): unknown {
    if (at.length === 0) return replacement;
    const [head, ...rest] = at;
    if (Array.isArray(value)) return value.map((v, i) => (i === head ? setAt(v, rest, replacement) : v));
    return { ...(value as Record<string, unknown>), [head]: setAt((value as Record<string, unknown>)[head as string], rest, replacement) };
}

/** A JSON body, or the JSON carried in an event stream's `data:` lines; null when the response holds neither. */
function readBody(text: string, contentType: string): { json: unknown; write: (json: unknown) => string } | null {
    if (contentType.includes('text/event-stream')) {
        const m = /^data: ?(.*)$/m.exec(text);
        if (m === null) return null;
        try {
            return { json: JSON.parse(m[1]), write: (json) => text.replace(m[0], `data: ${JSON.stringify(json)}`) };
        } catch {
            return null;
        }
    }
    try {
        return { json: JSON.parse(text), write: (json) => JSON.stringify(json) };
    } catch {
        return null;
    }
}

interface RunOutcome {
    /** Everything the run produced that somebody could read: files, stdout, log lines, and a thrown message. */
    readonly everything: string;
    readonly files: Record<string, string>;
    readonly refused: string | null;
    readonly dir: string;
}

/** One whole run of the full estate: `scan` to a directory and to stdout, over `wire`. */
async function runWhole(wire: FetchLike, sources: readonly unknown[] = SOURCES): Promise<RunOutcome> {
    const dir = join(base, `run-${runs++}`);
    mkdirSync(dir, { mode: 0o700 });
    const config = parseScannerConfig(estateConfig(sources, { outputs: [{ kind: 'file', dir }, { kind: 'stdout' }] }));
    const logged = capturedLog();
    const printed: string[] = [];
    let refused: string | null = null;
    try {
        await scanAndDeliver({
            config,
            env: estateEnv(),
            log: logged.log,
            fetchImpl: wire,
            resolveHost: PUBLIC_RESOLVER,
            now: () => NOW,
            outputs: [{ kind: 'file', dir }, { kind: 'stdout' }],
            stdout: (text) => printed.push(text),
        });
    } catch (err) {
        if (!(err instanceof ReportRefusedLocally)) throw err;
        refused = err.message;
    }
    const files = tree(dir);
    return { everything: [Object.values(files).join('\n'), printed.join(''), logged.text(), refused ?? ''].join('\n'), files, refused, dir };
}

/** Every string leaf of every JSON response a clean scan of the full estate reads. */
async function leavesOfCleanScan(): Promise<{ signature: string; path: Path }[]> {
    const world = worldFor();
    const counts = new Map<string, number>();
    const leaves: { signature: string; path: Path }[] = [];
    const wire: FetchLike = async (url, init) => {
        const signature = signatureOf(url, init, counts);
        const res = await world.fetchImpl(url, init);
        const text = await res.clone().text();
        const body = readBody(text, res.headers.get('content-type') ?? '');
        if (body !== null) for (const path of stringPaths(body.json)) leaves.push({ signature, path });
        return res;
    };
    const clean = await runWhole(wire);
    if (clean.refused !== null || Object.keys(clean.files).length === 0) throw new Error('the clean scan did not write its run');
    return leaves;
}

/** A wire that plants `canary` at one string of one response. */
function plantingWire(target: { signature: string; path: Path }, canary: string): { wire: FetchLike; planted: () => boolean } {
    const world = worldFor();
    const counts = new Map<string, number>();
    let planted = false;
    return {
        planted: () => planted,
        wire: async (url, init) => {
            const signature = signatureOf(url, init, counts);
            const res = await world.fetchImpl(url, init);
            if (signature !== target.signature) return res;
            const text = await res.text();
            const body = readBody(text, res.headers.get('content-type') ?? '');
            if (body === null) return new Response(text, { status: res.status, headers: res.headers });
            planted = true;
            return new Response(body.write(setAt(body.json, target.path, canary)), { status: res.status, headers: res.headers });
        },
    };
}

describe('a canary in every string of every response, one at a time', () => {
    let leaves: { signature: string; path: Path }[];
    beforeAll(async () => {
        leaves = await leavesOfCleanScan();
    });

    it('the clean scan reads responses from every network source', () => {
        const hosts = new Set(leaves.map((l) => new URL(l.signature.split(' ')[1]).hostname));
        for (const host of ['graph.microsoft.com', 'login.microsoftonline.com', 'acme.okta.com', 'acme-agents.vault.azure.net', 'api.github.com', 'iam.googleapis.com', 'oauth2.googleapis.com', 'api.smith.langchain.com', 'mcp.acme.example', 'inflect.example.com']) {
            expect(hosts).toContain(host);
        }
        expect(leaves.length).toBeGreaterThan(200);
    });

    it('is dropped, or refuses the run by the member\'s path: it is never written, printed or logged', async () => {
        // Every leaf under SCANENT_LONG=1 with every shape; otherwise every leaf once, the shape rotating.
        const shapes = LONG ? CANARIES : [null];
        let dropped = 0;
        let refused = 0;
        const refusedMembers = new Set<string>();
        for (const [index, leaf] of leaves.entries()) {
            for (const [s, shape] of shapes.entries()) {
                const [what, canary] = shape ?? CANARIES[index % CANARIES.length];
                const { wire, planted } = plantingWire(leaf, canary);
                const outcome = await runWhole(wire);
                const where = `${what} at ${leaf.signature.replace(/\?.*? /, ' ')} ${leaf.path.join('.')}`;
                if (!planted()) throw new Error(`the canary was not planted: ${where}`);
                if (outcome.everything.includes(canary)) throw new Error(`${where} reached an output`);
                if (outcome.refused !== null) {
                    refused += 1;
                    if (Object.keys(outcome.files).length > 0) throw new Error(`${where}: the run was refused and still wrote`);
                    refusedMembers.add(outcome.refused.replace(/\[\d+\]/g, '[n]'));
                } else {
                    dropped += 1;
                }
                rmSync(outcome.dir, { recursive: true, force: true });
                void s;
            }
        }
        // Both ways out are live: most strings are dropped, and the ones the report carries refuse the run.
        expect(dropped).toBeGreaterThan(100);
        expect(refused).toBeGreaterThan(0);
        for (const message of refusedMembers) expect(message).toMatch(/^the scanner refused to sign its report: /);
    }, 600_000);
});

describe('a canary in what a response is wrapped in', () => {
    const HEADERS = ['www-authenticate', 'location', 'link', 'mcp-session-id', 'x-oauth-scopes', 'retry-after', 'x-request-id', 'set-cookie', 'date', 'etag'];

    it.each(CANARIES)('%s in every response header of every request is in no output of a scan', async (_what, canary) => {
        const world = worldFor();
        const wire: FetchLike = async (url, init) => {
            const res = await world.fetchImpl(url, init);
            const headers = new Headers(res.headers);
            for (const name of HEADERS) {
                try {
                    headers.set(name, name === 'link' ? `<${canary}>; rel="next"` : canary);
                } catch {
                    // A value the platform will not put in a header cannot arrive in one.
                }
            }
            return new Response(res.body, { status: res.status, headers });
        };
        const outcome = await runWhole(wire);
        expect(outcome.everything).not.toContain(canary);
    });

    it.each(CANARIES)('%s in every error body, for each status a source can be refused with, is in no output of a scan or a preflight', async (_what, canary) => {
        for (const status of [400, 401, 403, 404, 429, 500, 503]) {
            const world = worldFor();
            const wire: FetchLike = async () =>
                new Response(JSON.stringify({ error: canary, error_description: canary, message: canary, detail: [canary], errorSummary: canary }), {
                    status,
                    headers: { 'content-type': 'application/json', 'www-authenticate': 'Bearer error="invalid_token"' },
                });
            const outcome = await runWhole(wire);
            expect(outcome.everything).not.toContain(canary);
            // The same answers to the preflight.
            const dir = join(base, `doctor-${runs++}`);
            mkdirSync(join(dir, 'out'), { recursive: true, mode: 0o700 });
            const configPath = join(dir, 'config.json');
            writeFileSync(configPath, JSON.stringify(estateConfig(SOURCES, { outputs: [{ kind: 'file', dir: join(dir, 'out') }] })), { mode: 0o600 });
            chmodSync(configPath, 0o600);
            const report = await runDoctor({ configPath, env: estateEnv(), fetchImpl: wire, resolveHost: PUBLIC_RESOLVER, now: () => NOW, nodeVersion: 'v24.1.0', uid: 1000 });
            expect(renderDoctorText(report)).not.toContain(canary);
            expect(renderDoctorJson(report)).not.toContain(canary);
            void world;
        }
    });

    it.each(CANARIES)('%s as the whole of a body that is not JSON is in no output', async (_what, canary) => {
        const wire: FetchLike = async () => new Response(`<html><body>${canary}</body></html>`, { status: 200, headers: { 'content-type': 'text/html' } });
        expect((await runWhole(wire)).everything).not.toContain(canary);
    });
});

describe('the credentials the scanner is given', () => {
    /** Every credential value, and every token an exchange hands back, of the fake estate. */
    const GIVEN: readonly string[] = [
        ...Object.entries(estateEnv())
            .filter(([name]) => name !== 'SCANNER_SIGNING_KEY' && name !== 'GCP_SCANNER_KEY')
            .map(([, value]) => value),
        AZURE_ACCESS_TOKEN_VALUE,
        GRAPH_ACCESS_TOKEN_VALUE,
        GOOGLE_ACCESS_TOKEN_VALUE,
        REGISTER_EXCHANGED_TOKEN,
        ...WORLD_SECRETS,
        ...NEVER_REPORTED,
    ];
    const assertNone = (text: string, where: string): void => {
        for (const secret of GIVEN) if (text.includes(secret)) throw new Error(`a credential reached ${where}`);
    };

    it('the list is the estate\'s: every variable but the two key files, whose lines are listed apart', () => {
        expect(GIVEN.length).toBeGreaterThan(20);
        expect(GIVEN.every((v) => v.length >= 8)).toBe(true);
    });

    it('a clean scan of every source holds none of them, in any file, on stdout or in the log', async () => {
        const outcome = await runWhole(worldFor().fetchImpl);
        expect(Object.keys(outcome.files).length).toBeGreaterThan(0);
        assertNone(outcome.everything, 'a clean scan');
    });

    const FAILURES: readonly [string, (req: { url: string; init: RequestInit }) => Response | 'throw'][] = [
        ['refused as unauthenticated', () => new Response('{"error":"invalid_token"}', { status: 401, headers: { 'content-type': 'application/json' } })],
        ['unreachable', () => 'throw'],
        ['answering 500', () => new Response('{"error":"internal"}', { status: 500, headers: { 'content-type': 'application/json' } })],
        [
            // A server, or a proxy in front of it, that reflects the request in its error: the credential comes back.
            'echoing the request back in its error',
            ({ init }) => {
                const headers = [...new Headers(init.headers).entries()].map(([k, v]) => `${k}: ${v}`).join('\n');
                return new Response(JSON.stringify({ error: 'bad request', youSent: { headers, body: String(init.body ?? '') } }), {
                    status: 400,
                    headers: { 'content-type': 'application/json', 'x-echo': encodeURIComponent(headers).slice(0, 2_000) },
                });
            },
        ],
        [
            'echoing the request back in a 200 that is not the listing',
            ({ init }) => new Response(JSON.stringify({ debug: [...new Headers(init.headers).values()], body: String(init.body ?? '') }), { status: 200, headers: { 'content-type': 'application/json' } }),
        ],
    ];

    describe.each(ESTATE_SOURCE_KINDS.filter((k) => k !== 'code'))('with %s failing', (kind) => {
        const hostsOfKind = hostsFor(parseScannerConfig(estateConfig([ESTATE_SOURCES[kind]])))
            .filter((h) => h.source === kind)
            .map((h) => h.host);

        it.each(FAILURES)('%s: no credential is in any output of the scan, and the other sources are still read', async (_label, fail) => {
            const world = worldFor();
            const wire: FetchLike = async (url, init) => {
                if (!hostsOfKind.includes(new URL(url).hostname)) return world.fetchImpl(url, init);
                const answer = fail({ url, init });
                if (answer === 'throw') throw new TypeError('fetch failed');
                return answer;
            };
            const outcome = await runWhole(wire);
            assertNone(outcome.everything, `the scan with ${kind} failing`);
            expect(outcome.refused).toBeNull();
            const results = JSON.parse(outcome.files[Object.keys(outcome.files).find((f) => f.endsWith('results.json')) as string]) as { sources: { kind: string; status: string }[] };
            expect(results.sources.find((s) => s.kind === kind)?.status).toBe('INCOMPLETE');
            expect(results.sources.filter((s) => s.status === 'COMPLETE').length).toBeGreaterThanOrEqual(ESTATE_SOURCE_KINDS.length - 3);
        });

        it.each(FAILURES)('%s: no credential is in the preflight, as a table or as JSON', async (_label, fail) => {
            const world = worldFor();
            const wire: FetchLike = async (url, init) => {
                if (!hostsOfKind.includes(new URL(url).hostname)) return world.fetchImpl(url, init);
                const answer = fail({ url, init });
                if (answer === 'throw') throw new TypeError('fetch failed');
                return answer;
            };
            const dir = join(base, `doctor-${runs++}`);
            mkdirSync(join(dir, 'out'), { recursive: true, mode: 0o700 });
            const configPath = join(dir, 'config.json');
            writeFileSync(configPath, JSON.stringify(estateConfig(SOURCES, { outputs: [{ kind: 'file', dir: join(dir, 'out') }] })), { mode: 0o600 });
            chmodSync(configPath, 0o600);
            const report = await runDoctor({ configPath, env: estateEnv(), fetchImpl: wire, resolveHost: PUBLIC_RESOLVER, now: () => NOW, nodeVersion: 'v24.1.0', uid: 1000 });
            assertNone(renderDoctorText(report), 'the preflight table');
            assertNone(renderDoctorJson(report), 'the preflight JSON');
            // A source that is failing is never called ready, whatever the failure answers with.
            expect(report.checks.some((c) => c.scope.startsWith(kind === 'mcp' ? 'mcp:' : kind) && c.status === 'FAIL')).toBe(true);
            expect(report.ready).toBe(false);
        });
    });

    it('hosts lists names and no credential, in every format', () => {
        const config = parseScannerConfig(estateConfig(SOURCES));
        for (const format of ['lines', 'json', 'egress-allow'] as const) assertNone(renderHosts(hostsFor(config), format), `hosts as ${format}`);
    });

    it('a diff of two runs, one of them with a source failing, holds none of them', async () => {
        const world = worldFor();
        const before = await runWhole(world.fetchImpl);
        const failing: FetchLike = async (url, init) =>
            new URL(url).hostname === 'acme.okta.com'
                ? new Response(JSON.stringify({ errorSummary: [...new Headers(init.headers).values()].join(' ') }), { status: 401, headers: { 'content-type': 'application/json' } })
                : world.fetchImpl(url, init);
        const after = await (async () => {
            const dir = join(base, `run-${runs++}`);
            mkdirSync(dir, { mode: 0o700 });
            const logged = capturedLog();
            await scanAndDeliver({
                config: parseScannerConfig(estateConfig(SOURCES)),
                env: estateEnv(),
                log: logged.log,
                fetchImpl: failing,
                resolveHost: PUBLIC_RESOLVER,
                now: () => NOW + 86_400_000,
                outputs: [{ kind: 'file', dir }],
            });
            return tree(dir);
        })();
        const dir = join(base, `diff-${runs++}`);
        mkdirSync(dir);
        const pathOf = (files: Record<string, string>, name: string): string => {
            const key = Object.keys(files).find((f) => f.endsWith('results.json')) as string;
            const path = join(dir, name);
            writeFileSync(path, files[key]);
            return path;
        };
        for (const format of ['text', 'json']) {
            const printed: string[] = [];
            const code = runDiff([pathOf(before.files, 'old.json'), pathOf(after, 'new.json'), '--format', format], { stdout: (t) => printed.push(t), stderr: (t) => printed.push(t) });
            expect([1, 3]).toContain(code);
            assertNone(printed.join(''), `the diff as ${format}`);
            expect(printed.join('')).toContain('okta-app');
        }
    });
});
