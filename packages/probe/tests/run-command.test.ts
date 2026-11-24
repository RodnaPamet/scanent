/**
 * `scanent-probe run`, sending for real through an injected fetch: the signed
 * report it writes, what it prints, and what it refuses before sending
 * anything.
 */
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { verifyAndParseProbesReport } from '@rodnapamet/scanent-contract/probes-contract';

import { PROBE_EXIT, main } from '../src/cli';
import { signScope } from '../src/scope-sign';
import { FAKE_TOOL_TOKEN, PLANTED_MARKER, obedient, resistant } from './helpers/fake-agents';
import { fakeServers, listedTool } from './helpers/fake-servers';
import { MCP_TOOL, START_MS, chatTarget, makeKey, mcpTarget, scopeBody } from './helpers/scope-keys';

const approver = makeKey();
const prober = makeKey();
const MCP = 'https://mcp.estate.example/mcp';
const CHAT = 'https://chat.estate.example/api/turn';

function setup(env: Record<string, string> = {}) {
    const cwd = mkdtempSync(join(tmpdir(), 'scanent-probe-run-'));
    writeFileSync(join(cwd, 'scope.signed.json'), signScope(scopeBody(prober, { targets: [mcpTarget(MCP), chatTarget(CHAT)], ratePerMinute: 120 }), approver));
    const world = fakeServers({
        [MCP]: { kind: 'mcp', agent: obedient, token: 'mcp-secret-token', tools: [listedTool(MCP_TOOL.name, MCP_TOOL.argument)] },
        [CHAT]: { kind: 'http-chat', agent: resistant },
    });
    let stop = false;
    const invoke = async (...argv: string[]) => {
        let out = '';
        let err = '';
        const code = await main(argv, {
            out: (t) => (out += t),
            err: (t) => (err += t),
            cwd,
            env: { PROBER_KEY: prober.pem, MCP_TOKEN: 'mcp-secret-token', MARKER: PLANTED_MARKER, ...env },
            fetchImpl: world.fetchImpl,
            now: () => START_MS,
            sleep: async () => undefined,
            stopRequested: () => stop,
        });
        return { code, out, err };
    };
    return { cwd, world, invoke, stopNow: () => (stop = true) };
}

const BASE = ['run', '--scope', 'scope.signed.json', '--trusted-key', approver.hex, '--signing-key-env', 'PROBER_KEY', '--out', 'report.json'];
const FULL = [...BASE, '--credential', `${MCP}=MCP_TOKEN`, '--planted-marker-env', 'MARKER'];

describe('scanent-probe run', () => {
    it('sends, and writes a report the contract\'s verifier accepts under the prober\'s key', async () => {
        const { invoke, cwd, world } = setup();
        const result = await invoke(...FULL);
        expect(result.err).toBe('');
        expect(result.code).toBe(PROBE_EXIT.OK);
        const read = verifyAndParseProbesReport(readFileSync(join(cwd, 'report.json'), 'utf8'), [prober.hex]);
        expect(read.ok).toBe(true);
        if (read.ok) expect(read.body.targets.map((t) => t.reason)).toEqual(['REACHED', 'REACHED']);
        expect(result.out).toMatch(/^run: \d+ probes sent\nengagement: eng-2026-12-acme\nverdicts: /);
        expect(result.out).toContain('target 1  mcp  REACHED');
        expect(result.out).toContain('concluded: yes');
        expect(world.log.length).toBeGreaterThan(0);
    });

    it('prints and writes no credential, no marker, no excerpt and no secret the agent returned', async () => {
        const { invoke, cwd } = setup();
        const result = await invoke(...FULL);
        const report = readFileSync(join(cwd, 'report.json'), 'utf8');
        for (const absent of ['mcp-secret-token', PLANTED_MARKER, FAKE_TOOL_TOKEN, 'BEGIN PRIVATE KEY']) {
            expect(result.out + result.err).not.toContain(absent);
            expect(report).not.toContain(absent);
        }
        expect(result.out).not.toMatch(/scanent-[0-9a-f]{24}/);
    });

    it('without the credential the MCP target refuses, and the note says why', async () => {
        const { invoke } = setup();
        const result = await invoke(...BASE);
        expect(result.code).toBe(PROBE_EXIT.OK);
        expect(result.out).toContain('target 1  mcp  NO_REPLY  (AUTH_FAILED)');
    });

    it('a stop file present before the first request sends nothing, and the report says the run stopped', async () => {
        const { invoke, cwd, world } = setup();
        writeFileSync(join(cwd, 'STOP'), '');
        const result = await invoke(...FULL, '--stop-file', 'STOP');
        expect(world.log).toHaveLength(0);
        expect(result.out).toContain('stopped early (STOPPED)');
        expect(result.out).toContain('concluded: no');
        const read = verifyAndParseProbesReport(readFileSync(join(cwd, 'report.json'), 'utf8'), [prober.hex]);
        expect(read.ok && read.body.run.stopped).toBe('STOPPED');
    });

    it('a signal stops it at the next request', async () => {
        const { invoke, world, stopNow } = setup();
        stopNow();
        const result = await invoke(...FULL);
        expect(world.log).toHaveLength(0);
        expect(result.out).toContain('(STOPPED)');
    });
});

describe('what run refuses before sending anything', () => {
    it('an output file that exists', async () => {
        const { invoke, cwd, world } = setup();
        writeFileSync(join(cwd, 'report.json'), 'kept');
        expect(await invoke(...FULL)).toMatchObject({ code: PROBE_EXIT.USAGE, err: 'run: the output file exists; it is never overwritten\n' });
        expect(readFileSync(join(cwd, 'report.json'), 'utf8')).toBe('kept');
        expect(world.log).toHaveLength(0);
    });

    it('a prober key the scope does not name', async () => {
        const { invoke, world, cwd } = setup({ PROBER_KEY: makeKey().pem });
        expect(await invoke(...FULL)).toMatchObject({ code: PROBE_EXIT.FAILED, err: 'scope: refused (PROBER_NOT_NAMED)\n' });
        expect(world.log).toHaveLength(0);
        expect(existsSync(join(cwd, 'report.json'))).toBe(false);
    });

    it('a missing or unreadable key, credential or marker, never echoing a value', async () => {
        const noKey = setup({ PROBER_KEY: '' });
        expect(await noKey.invoke(...FULL)).toMatchObject({ code: PROBE_EXIT.CONFIG, err: "run: the prober's key: PROBER_KEY is not set\n" });
        const badKey = setup({ PROBER_KEY: 'not a pem' });
        expect(await badKey.invoke(...FULL)).toMatchObject({ code: PROBE_EXIT.CONFIG });
        const noToken = setup({ MCP_TOKEN: '' });
        expect(await noToken.invoke(...FULL)).toMatchObject({ code: PROBE_EXIT.CONFIG, err: 'run: a credential: MCP_TOKEN is not set\n' });
        const both = setup({ MARKER_FILE: '/nonexistent' });
        const refused = await both.invoke(...FULL);
        expect(refused).toMatchObject({ code: PROBE_EXIT.CONFIG, err: 'run: a planted marker: MARKER and MARKER_FILE are both set\n' });
        expect(refused.err).not.toContain(PLANTED_MARKER);
    });

    it('reads a secret from NAME_FILE, one trailing new line removed', async () => {
        const { invoke, cwd } = setup();
        writeFileSync(join(cwd, 'token'), 'mcp-secret-token\n');
        const unset = await invoke(...BASE, '--credential', `${MCP}=FILE_TOKEN`);
        expect(unset).toMatchObject({ code: PROBE_EXIT.CONFIG, err: 'run: a credential: FILE_TOKEN is not set\n' });
        const viaFile = setup({ FILE_TOKEN_FILE: join(cwd, 'token') });
        const ok = await viaFile.invoke(...BASE, '--credential', `${MCP}=FILE_TOKEN`);
        expect(ok.out).toContain('target 1  mcp  REACHED');
    });

    it('a credential for an endpoint the scope does not name, or a malformed one', async () => {
        const { invoke, world } = setup();
        expect(await invoke(...BASE, '--credential', 'https://elsewhere.example/api=MCP_TOKEN')).toMatchObject({
            code: PROBE_EXIT.USAGE,
            err: 'run: a --credential names an endpoint the scope does not\n',
        });
        expect((await invoke(...BASE, '--credential', 'no-equals-sign')).code).toBe(PROBE_EXIT.USAGE);
        expect((await invoke(...BASE, '--credential', `${MCP}=lower_case`)).code).toBe(PROBE_EXIT.USAGE);
        expect(world.log).toHaveLength(0);
    });

    it('missing flags', async () => {
        const { invoke } = setup();
        expect((await invoke('run', '--scope', 'scope.signed.json')).code).toBe(PROBE_EXIT.USAGE);
        expect((await invoke(...BASE.slice(0, -2))).code).toBe(PROBE_EXIT.USAGE);
    });
});
