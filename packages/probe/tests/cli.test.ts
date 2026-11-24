/**
 * `scanent-probe scope sign` and `scope verify`: the approver signs, the
 * prober verifies, and nothing a file or flag carried is echoed.
 */
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { PROBE_EXIT, PROBE_HELP, main } from '../src/cli';
import { planRequests } from '../src/runner';
import { EngagementScopeSchema } from '../src/scope';
import { EXIT } from '../../scanner/src/exit-codes';
import { START_MS, makeKey, scopeBody } from './helpers/scope-keys';

const scopeOf = (p: ReturnType<typeof makeKey>) => EngagementScopeSchema.parse(scopeBody(p));

const approver = makeKey();
const prober = makeKey();

function harness(now = START_MS) {
    const cwd = mkdtempSync(join(tmpdir(), 'scanent-probe-'));
    let out = '';
    let err = '';
    const run = (...argv: string[]) => {
        out = '';
        err = '';
        const code = main(argv, { out: (t) => (out += t), err: (t) => (err += t), cwd, now: () => now });
        return { code, out, err };
    };
    writeFileSync(join(cwd, 'approver.pem'), approver.pem);
    writeFileSync(join(cwd, 'prober.pem'), prober.pem);
    writeFileSync(join(cwd, 'scope.json'), JSON.stringify(scopeBody(prober)));
    return { cwd, run };
}

const sign = (run: ReturnType<typeof harness>['run'], key = 'approver.pem', out = 'signed.json') =>
    run('scope', 'sign', '--key', key, '--in', 'scope.json', '--out', out);
const verifyArgs = ['scope', 'verify', '--scope', 'signed.json', '--trusted-key', approver.hex, '--prober-key', prober.hex];

describe('scanent-probe scope', () => {
    it('uses the scanner\'s exit numbers for the same meanings', () => {
        expect(PROBE_EXIT).toEqual({ OK: EXIT.OK, FAILED: EXIT.FAILED, USAGE: EXIT.USAGE, CONFIG: EXIT.CONFIG });
    });

    it('signs, then verifies inside the window', () => {
        const { run, cwd } = harness();
        expect(sign(run)).toEqual({ code: 0, out: 'scope: signed\n', err: '' });
        expect(JSON.parse(readFileSync(join(cwd, 'signed.json'), 'utf8')).signature.signerKey).toBe(approver.hex);

        const result = run(...verifyArgs, '--target', 'https://mcp.estate.example/mcp', '--class', 'canary');
        expect(result.code).toBe(PROBE_EXIT.OK);
        expect(result.out).toMatch(/^scope: verified\nengagement: eng-2026-12-acme\n/);
        expect(result.out).toMatch(/\ndigest: sha256:[0-9a-f]{64}\n/);
        expect(result.out).toMatch(/\nsigner key fingerprint: [0-9a-f]{64}\n$/);
        // The approver's name and the contact are the estate's, and not printed.
        expect(result.out).not.toContain('Dana');
        expect(result.out).not.toContain('+44');
    });

    it('never overwrites a signed scope', () => {
        const { run, cwd } = harness();
        sign(run);
        const before = readFileSync(join(cwd, 'signed.json'), 'utf8');
        expect(sign(run)).toMatchObject({ code: PROBE_EXIT.USAGE, err: 'scope sign: the output file exists; it is never overwritten\n' });
        expect(readFileSync(join(cwd, 'signed.json'), 'utf8')).toBe(before);
    });

    it('will not sign with the prober\'s key, and writes nothing', () => {
        const { run, cwd } = harness();
        expect(sign(run, 'prober.pem').code).toBe(PROBE_EXIT.FAILED);
        expect(() => readFileSync(join(cwd, 'signed.json'))).toThrow();
    });

    it('a missing scope is NO_SCOPE', () => {
        const { run } = harness();
        expect(run(...verifyArgs)).toEqual({ code: PROBE_EXIT.FAILED, out: '', err: 'scope: refused (NO_SCOPE)\n' });
    });

    it('reads a scope through one descriptor: over the cap is TOO_LARGE, and a directory is no scope', () => {
        const { run, cwd } = harness();
        writeFileSync(join(cwd, 'signed.json'), 'x'.repeat(5 * 1024 * 1024 + 1));
        expect(run(...verifyArgs).err).toBe('scope: refused (TOO_LARGE)\n');
        expect(run('scope', 'verify', '--scope', '.', '--trusted-key', approver.hex, '--prober-key', prober.hex).err).toBe(
            'scope: refused (NO_SCOPE)\n',
        );
    });

    it('names each refusal and nothing it read', () => {
        const { run, cwd } = harness();
        sign(run);
        const stranger = makeKey();
        expect(run('scope', 'verify', '--scope', 'signed.json', '--trusted-key', stranger.hex, '--prober-key', prober.hex).err).toBe(
            'scope: refused (UNTRUSTED_SIGNER)\n',
        );
        expect(run('scope', 'verify', '--scope', 'signed.json', '--trusted-key', approver.hex, '--prober-key', stranger.hex).err).toBe(
            'scope: refused (PROBER_NOT_NAMED)\n',
        );
        expect(run(...verifyArgs, '--target', 'https://evil.example/ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa').err).toBe(
            'scope: refused (TARGET_NOT_NAMED)\n',
        );
        expect(run(...verifyArgs, '--class', 'side-effect').err).toBe('scope: refused (CLASS_NOT_ALLOWED)\n');

        writeFileSync(join(cwd, 'scope.json'), JSON.stringify(scopeBody(prober, { killContact: 'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' })));
        const refused = sign(run, 'approver.pem', 'other.json');
        expect(refused.code).toBe(PROBE_EXIT.FAILED);
        expect(refused.err).toContain('killContact');
        expect(refused.err).not.toContain('ghp_');
    });

    it('reads the window from the clock: before it, and at its end, are refused', () => {
        const early = harness(START_MS - 1);
        sign(early.run);
        expect(early.run(...verifyArgs).err).toBe('scope: refused (NOT_YET_OPEN)\n');
        const late = harness(Date.parse('2026-12-03T17:00:00.000Z'));
        sign(late.run);
        expect(late.run(...verifyArgs).err).toBe('scope: refused (CLOSED)\n');
    });

    it('usage errors name the flag, never a value', () => {
        const { run } = harness();
        expect(run('scope', 'verify', '--scope', 'signed.json', '--prober-key', prober.hex)).toMatchObject({ code: PROBE_EXIT.USAGE });
        const bad = run('scope', 'verify', '--scope', 'signed.json', '--trusted-key', 'secret-ish-value', '--prober-key', prober.hex);
        expect(bad.code).toBe(PROBE_EXIT.USAGE);
        expect(bad.err).not.toContain('secret-ish-value');
        const unknown = run('scope', 'verify', '--token', 'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
        expect(unknown).toMatchObject({ code: PROBE_EXIT.USAGE, err: 'scope verify: an argument this command does not take\n' });
        expect(run('scope', 'sign', '--key', 'approver.pem', '--key', 'prober.pem', '--in', 'x', '--out', 'y').err).toBe(
            'scope sign: --key is given twice\n',
        );
        expect(run('scope', 'sign', '--key')).toMatchObject({ code: PROBE_EXIT.USAGE, err: 'scope sign: --key needs a value\n' });
        expect(run('probe', 'now')).toMatchObject({ code: PROBE_EXIT.USAGE });
    });

    it('an unreadable key or scope file is CONFIG', () => {
        const { run, cwd } = harness();
        expect(sign(run, 'absent.pem').code).toBe(PROBE_EXIT.CONFIG);
        writeFileSync(join(cwd, 'scope.json'), '{');
        expect(sign(run).code).toBe(PROBE_EXIT.CONFIG);
    });

    it('run --dry-run verifies the scope and lists every request by target and probe, with no canary', () => {
        const { run } = harness();
        sign(run);
        const result = run('run', '--dry-run', '--scope', 'signed.json', '--trusted-key', approver.hex, '--prober-key', prober.hex);
        expect(result.code).toBe(PROBE_EXIT.OK);
        const plan = planRequests(scopeOf(prober));
        expect(result.out).toContain(`dry run: ${plan.length} requests, none sent\n`);
        expect(result.out).toContain('target 1  canary.instruction-override.1  (canary)');
        expect(result.out.split('\n').filter((l) => l.startsWith('target '))).toHaveLength(plan.length);
        expect(result.out).not.toMatch(/scanent-[0-9a-f]/);
    });

    it('run without --dry-run sends nothing and says why; a scope that does not verify is refused', () => {
        const { run } = harness();
        sign(run);
        expect(run('run', '--scope', 'signed.json', '--trusted-key', approver.hex, '--prober-key', prober.hex)).toEqual({
            code: PROBE_EXIT.USAGE,
            out: '',
            err: "run: only --dry-run is available; sending arrives with the prober's image\n",
        });
        expect(run('run', '--dry-run', '--scope', 'signed.json', '--trusted-key', makeKey().hex, '--prober-key', prober.hex).err).toBe(
            'scope: refused (UNTRUSTED_SIGNER)\n',
        );
        expect(run('run', '--dry-run', '--scope', 'absent.json', '--trusted-key', approver.hex, '--prober-key', prober.hex).err).toBe(
            'scope: refused (NO_SCOPE)\n',
        );
        expect(run('run', '--dry-run', '--scope', 'signed.json', '--prober-key', prober.hex).code).toBe(PROBE_EXIT.USAGE);
        expect(run('run', '--dry-run', '--scope', 'signed.json', '--trusted-key', 'nope', '--prober-key', prober.hex).code).toBe(PROBE_EXIT.USAGE);
        expect(run('run', '--dry-run', '--token', 'x').code).toBe(PROBE_EXIT.USAGE);
    });

    it('help names both commands; with no command it is a usage error', () => {
        const { run } = harness();
        expect(run('help')).toEqual({ code: 0, out: PROBE_HELP, err: '' });
        expect(run().code).toBe(PROBE_EXIT.USAGE);
        expect(PROBE_HELP).toContain('scanent-probe scope sign');
        expect(PROBE_HELP).toContain('scanent-probe scope verify');
    });
});
