/**
 * The engagement scope (docs/engagement-scope.md): no verified scope, no
 * probe. Every refusal, in its order, and the per-request gate.
 */
import { generateKeyPairSync } from 'node:crypto';

import {
    ENGAGEMENT_SCOPE_V1,
    MAX_SCOPE_TARGETS,
    MAX_SCOPE_WINDOW_MS,
    SCOPE_REFUSALS,
    endpointProblem,
    scopeAdmits,
    scopeDigest,
    verifyEngagementScope,
    type EngagementScope,
} from '../src/scope';
import { ScopeSignRefused, loadScopeSigningKey, signScope } from '../src/scope-sign';
import { END, END_MS, START, START_MS, makeKey, scopeBody, signRaw, a2aTarget, chatTarget, mcpTarget } from './helpers/scope-keys';

const approver = makeKey();
const prober = makeKey();
const stranger = makeKey();

const verify = (raw: string, trusted: readonly string[] = [approver.hex], proberKey: string = prober.hex) =>
    verifyEngagementScope(raw, { trustedScopeKeys: trusted, proberKey });

const signed = (overrides: Record<string, unknown> = {}) => signScope(scopeBody(prober, overrides), approver);

function scopeOf(raw: string): EngagementScope {
    const result = verify(raw);
    if (!result.ok) throw new Error(`expected a verified scope, got ${result.reason}`);
    return result.scope;
}

describe('a scope the approver signed, for this prober', () => {
    it('verifies, with its digest and the signer\'s fingerprint', () => {
        const raw = signed();
        const result = verify(raw);
        expect(result.ok).toBe(true);
        if (!result.ok) return;
        const { signature: _signature, ...body } = JSON.parse(raw) as Record<string, unknown>;
        expect(result.digest).toBe(scopeDigest(body));
        expect(result.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
        expect(result.signerKey).toBe(approver.hex);
        expect(result.signerFingerprint).toMatch(/^[0-9a-f]{64}$/);
        expect(result.scope.engagementId).toBe('eng-2026-12-acme');
    });

    it('reads the same with every key in either spelling', () => {
        const raw = signScope(scopeBody(prober, { proberKey: prober.base64 }), approver);
        expect(verify(raw, [approver.base64], prober.hex).ok).toBe(true);
        expect(verify(raw, [approver.hex], prober.base64).ok).toBe(true);
    });

    it('a scope that allows one class names only it', () => {
        expect(scopeOf(signed({ classes: ['disclosure'] })).classes).toEqual(['disclosure']);
    });
});

describe('the refusals, in order', () => {
    it('lists them in the order they are checked', () => {
        expect(SCOPE_REFUSALS).toEqual([
            'TOO_LARGE',
            'NOT_JSON',
            'NOT_AN_OBJECT',
            'UNSIGNED',
            'MALFORMED_SIGNATURE',
            'UNTRUSTED_SIGNER',
            'BAD_SIGNATURE',
            'SCHEMA',
            'SIGNER_IS_PROBER',
            'PROBER_NOT_NAMED',
        ]);
    });

    it('the envelope\'s own, before any member is read', () => {
        expect(verify('x'.repeat(5 * 1024 * 1024 + 1))).toEqual({ ok: false, reason: 'TOO_LARGE' });
        expect(verify('{')).toEqual({ ok: false, reason: 'NOT_JSON' });
        expect(verify('[]')).toEqual({ ok: false, reason: 'NOT_AN_OBJECT' });
        expect(verify(JSON.stringify(scopeBody(prober)))).toEqual({ ok: false, reason: 'UNSIGNED' });
        const raw = JSON.parse(signed()) as Record<string, unknown>;
        expect(verify(JSON.stringify({ ...raw, signature: { alg: 'rsa' } }))).toEqual({ ok: false, reason: 'MALFORMED_SIGNATURE' });
    });

    it('a key the estate did not register is UNTRUSTED_SIGNER, however valid its signature', () => {
        expect(verify(signScope(scopeBody(prober), stranger))).toEqual({ ok: false, reason: 'UNTRUSTED_SIGNER' });
        expect(verify(signed(), [])).toEqual({ ok: false, reason: 'UNTRUSTED_SIGNER' });
    });

    it('any member changed after signing is BAD_SIGNATURE', () => {
        const raw = JSON.parse(signed()) as Record<string, unknown>;
        const changes: Record<string, unknown>[] = [
            { targets: [mcpTarget('https://other.example/mcp')] },
            { window: { start: START, end: '2026-12-08T09:00:00.000Z' } },
            { classes: ['canary'] },
            { ratePerMinute: 120 },
            { engagementId: 'eng-2026-12-other' },
            { proberKey: stranger.hex },
        ];
        for (const change of changes) {
            expect(verify(JSON.stringify({ ...raw, ...change }))).toEqual({ ok: false, reason: 'BAD_SIGNATURE' });
        }
    });

    it('another contract id is SCHEMA, and the value is not echoed', () => {
        const result = verify(signRaw(scopeBody(prober, { contract: 'scanent-agent-rules/1' }), approver));
        expect(result).toEqual({ ok: false, reason: 'SCHEMA', issues: ['contract: not a contract id this verifier accepts'] });
    });

    it('signed by the prober\'s own key is SIGNER_IS_PROBER, even when that key was registered as a scope key', () => {
        const byProber = signRaw(scopeBody(prober), prober);
        expect(verify(byProber, [approver.hex, prober.hex])).toEqual({ ok: false, reason: 'SIGNER_IS_PROBER' });
        expect(verify(byProber, [prober.base64], prober.base64)).toEqual({ ok: false, reason: 'SIGNER_IS_PROBER' });
    });

    it('signed by the reading prober\'s own key is SIGNER_IS_PROBER, whichever prober the scope names', () => {
        const raw = signRaw(scopeBody(stranger), prober);
        expect(verify(raw, [approver.hex, prober.hex])).toEqual({ ok: false, reason: 'SIGNER_IS_PROBER' });
    });

    it('signed by the prober the scope names, when another prober reads it, is SIGNER_IS_PROBER', () => {
        const other = makeKey();
        const raw = signRaw(scopeBody(other), other);
        expect(verify(raw, [other.hex], prober.hex)).toEqual({ ok: false, reason: 'SIGNER_IS_PROBER' });
    });

    it('a scope naming another prober is PROBER_NOT_NAMED', () => {
        const raw = signScope(scopeBody(stranger), approver);
        expect(verify(raw)).toEqual({ ok: false, reason: 'PROBER_NOT_NAMED' });
    });

    it('a prober key that is not a key is the caller\'s error', () => {
        expect(() => verify(signed(), [approver.hex], 'not-a-key')).toThrow(TypeError);
    });
});

describe('the format (SCHEMA)', () => {
    const refusedFor = (overrides: Record<string, unknown>) => {
        const result = verify(signRaw(scopeBody(prober, overrides), approver));
        expect(result.ok).toBe(false);
        return result.ok ? null : result.reason;
    };

    it('the window is at most seven days, and the end is after the start', () => {
        const sevenDays = new Date(START_MS + MAX_SCOPE_WINDOW_MS).toISOString();
        expect(verify(signed({ window: { start: START, end: sevenDays } })).ok).toBe(true);
        const longer = new Date(START_MS + MAX_SCOPE_WINDOW_MS + 1).toISOString();
        expect(refusedFor({ window: { start: START, end: longer } })).toBe('SCHEMA');
        expect(refusedFor({ window: { start: START, end: START } })).toBe('SCHEMA');
        expect(refusedFor({ window: { start: END, end: START } })).toBe('SCHEMA');
    });

    it('the window is in UTC: an offset or a date alone is refused', () => {
        expect(refusedFor({ window: { start: '2026-12-01T09:00:00+01:00', end: END } })).toBe('SCHEMA');
        expect(refusedFor({ window: { start: '2026-12-01', end: END } })).toBe('SCHEMA');
    });

    it('the rate is a whole number from 1 to 120', () => {
        expect(verify(signed({ ratePerMinute: 1 })).ok).toBe(true);
        expect(verify(signed({ ratePerMinute: 120 })).ok).toBe(true);
        for (const rate of [0, 121, 1.5, -1, '30']) expect(refusedFor({ ratePerMinute: rate })).toBe('SCHEMA');
    });

    it('version 1 allows canary and disclosure only, each once, at least one', () => {
        expect(refusedFor({ classes: ['side-effect'] })).toBe('SCHEMA');
        expect(refusedFor({ classes: ['canary', 'side-effect'] })).toBe('SCHEMA');
        expect(refusedFor({ classes: [] })).toBe('SCHEMA');
        expect(refusedFor({ classes: ['canary', 'canary'] })).toBe('SCHEMA');
    });

    it('targets: one to fifty, each named once, of a known kind', () => {
        expect(refusedFor({ targets: [] })).toBe('SCHEMA');
        const many = Array.from({ length: MAX_SCOPE_TARGETS + 1 }, (_, i) => mcpTarget(`https://h${i}.example/mcp`));
        expect(refusedFor({ targets: many })).toBe('SCHEMA');
        expect(verify(signed({ targets: many.slice(0, MAX_SCOPE_TARGETS) })).ok).toBe(true);
        const twice = mcpTarget('https://mcp.estate.example/mcp');
        expect(refusedFor({ targets: [twice, twice] })).toBe('SCHEMA');
        expect(refusedFor({ targets: [{ kind: 'network', endpoint: 'https://mcp.estate.example/mcp' }] })).toBe('SCHEMA');
    });

    it('unknown members are refused, and counted rather than named', () => {
        const result = verify(signRaw(scopeBody(prober, { ghp_planted: 1 }), approver));
        expect(result).toMatchObject({ ok: false, reason: 'SCHEMA' });
        if (!result.ok) expect(result.issues?.join(' ')).not.toContain('ghp_planted');
    });

    it('the approver and the kill contact are one line of text, never a secret', () => {
        expect(refusedFor({ approver: { name: 'Dana', role: '' } })).toBe('SCHEMA');
        expect(refusedFor({ approver: { name: 'Dana\nEvil', role: 'CISO' } })).toBe('SCHEMA');
        expect(refusedFor({ killContact: 'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' })).toBe('SCHEMA');
        expect(refusedFor({ killContact: ' padded' })).toBe('SCHEMA');
    });

    it('the engagement id is a closed format, and the prober key a real key', () => {
        expect(refusedFor({ engagementId: 'short' })).toBe('SCHEMA');
        expect(refusedFor({ engagementId: 'has space in it' })).toBe('SCHEMA');
        expect(refusedFor({ proberKey: 'ab'.repeat(16) })).toBe('SCHEMA');
    });
});

describe('an endpoint is exact', () => {
    it('accepts an https URL in its canonical spelling', () => {
        expect(endpointProblem('https://mcp.estate.example/mcp')).toBeNull();
        expect(endpointProblem('https://mcp.estate.example:8443/a2a/tasks')).toBeNull();
        expect(endpointProblem('https://mcp.estate.example/')).toBeNull();
    });

    it.each([
        ['http://mcp.estate.example/mcp', 'not https'],
        ['https://user:pw@mcp.estate.example/mcp', 'credentials'],
        ['https://user@mcp.estate.example/mcp', 'credentials'],
        ['https://mcp.estate.example/mcp?x=1', 'query'],
        ['https://mcp.estate.example/mcp?', 'query'],
        ['https://mcp.estate.example/mcp#frag', 'query or fragment'],
        ['https://*.estate.example/mcp', 'pattern'],
        ['https://MCP.estate.example/mcp', 'canonical'],
        ['https://mcp.estate.example:443/mcp', 'canonical'],
        ['https://mcp.estate.example', 'canonical'],
        ['https://mcp.estate.example/a/../mcp', 'canonical'],
        ['mcp.estate.example/mcp', 'not a URL'],
    ])('refuses %s', (endpoint, why) => {
        expect(endpointProblem(endpoint)).toContain(why);
    });
});

describe('the gate before every request', () => {
    const scope = scopeOf(signed());
    const ok = { target: 'https://mcp.estate.example/mcp', probeClass: 'canary' };

    it('admits a named target and an allowed class inside the window', () => {
        expect(scopeAdmits(scope, { ...ok, now: START_MS })).toBeNull();
        expect(scopeAdmits(scope, { ...ok, now: END_MS - 1 })).toBeNull();
    });

    it('has no clock skew: a millisecond before the start, and the end itself, are refused', () => {
        expect(scopeAdmits(scope, { ...ok, now: START_MS - 1 })).toBe('NOT_YET_OPEN');
        expect(scopeAdmits(scope, { ...ok, now: END_MS })).toBe('CLOSED');
    });

    it('a clock it cannot read is CLOSED', () => {
        expect(scopeAdmits(scope, { ...ok, now: Number.NaN })).toBe('CLOSED');
    });

    it('a target is named byte for byte, never by its spelling', () => {
        expect(scopeAdmits(scope, { ...ok, now: START_MS, target: 'https://mcp.estate.example/mcp/' })).toBe('TARGET_NOT_NAMED');
        expect(scopeAdmits(scope, { ...ok, now: START_MS, target: 'https://MCP.estate.example/mcp' })).toBe('TARGET_NOT_NAMED');
        expect(scopeAdmits(scope, { ...ok, now: START_MS, target: 'https://other.example/mcp' })).toBe('TARGET_NOT_NAMED');
    });

    it('a class the scope does not allow is refused, side-effect included', () => {
        const disclosureOnly = scopeOf(signed({ classes: ['disclosure'] }));
        expect(scopeAdmits(disclosureOnly, { ...ok, now: START_MS })).toBe('CLASS_NOT_ALLOWED');
        expect(scopeAdmits(scope, { ...ok, now: START_MS, probeClass: 'side-effect' })).toBe('CLASS_NOT_ALLOWED');
    });

    it('the window is checked first, so a closed run is refused whatever it asks', () => {
        expect(scopeAdmits(scope, { now: END_MS, target: 'https://other.example/', probeClass: 'side-effect' })).toBe('CLOSED');
    });
});

describe('signing', () => {
    it('refuses a body that would not verify, naming paths and never values', () => {
        try {
            signScope(scopeBody(prober, { ratePerMinute: 500, killContact: 'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }), approver);
            throw new Error('expected a refusal');
        } catch (err) {
            expect(err).toBeInstanceOf(ScopeSignRefused);
            const text = (err as ScopeSignRefused).issues.join(' ');
            expect(text).toContain('ratePerMinute');
            expect(text).not.toContain('ghp_');
        }
    });

    it('refuses to sign with the key of the prober the scope names', () => {
        expect(() => signScope(scopeBody(prober), prober)).toThrow(/prober the scope names may not sign it/);
    });

    it('refuses a body that already carries a signature', () => {
        expect(() => signScope(JSON.parse(signed()), approver)).toThrow(ScopeSignRefused);
    });

    it('loads only an Ed25519 private key, and quotes nothing of the file', () => {
        expect(loadScopeSigningKey(approver.pem).publicKey.asymmetricKeyType).toBe('ed25519');
        expect(() => loadScopeSigningKey('not a pem')).toThrow('key: not a private key in PEM');
        const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
        expect(() => loadScopeSigningKey(rsa)).toThrow('key: not Ed25519');
    });

    it('names its contract', () => {
        expect(JSON.parse(signed()).contract).toBe(ENGAGEMENT_SCOPE_V1);
    });
});

describe('what a target says about how it is reached', () => {
    const refused = (targets: unknown[]) => {
        const result = verify(signRaw(scopeBody(prober, { targets }), approver));
        return result.ok ? null : result.reason;
    };

    it('an A2A target is its endpoint alone', () => {
        expect(verify(signed({ targets: [a2aTarget('https://a2a.estate.example/tasks')] })).ok).toBe(true);
        expect(refused([{ ...a2aTarget('https://a2a.estate.example/tasks'), tools: [] }])).toBe('SCHEMA');
    });

    it('an MCP target names the tools a probe may call, one to ten, each once, with the argument it goes in', () => {
        const mcp = 'https://mcp.estate.example/mcp';
        expect(refused([{ kind: 'mcp', endpoint: mcp }])).toBe('SCHEMA');
        expect(refused([mcpTarget(mcp, [])])).toBe('SCHEMA');
        const tool = { name: 'search_orders', argument: 'query' };
        expect(refused([mcpTarget(mcp, [tool, tool])])).toBe('SCHEMA');
        expect(refused([mcpTarget(mcp, Array.from({ length: 11 }, (_, i) => ({ name: `t${i}`, argument: 'q' })))])).toBe('SCHEMA');
        expect(refused([mcpTarget(mcp, [{ name: 'has space', argument: 'q' }])])).toBe('SCHEMA');
        expect(refused([mcpTarget(mcp, [{ name: 'ok', argument: '' }])])).toBe('SCHEMA');
        expect(verify(signed({ targets: [mcpTarget(mcp, [tool, { name: 'lookup.v2', argument: 'text' }])] })).ok).toBe(true);
    });

    it('a chat target declares the body sent, with the placeholder as one whole string, and where the reply is', () => {
        const chat = 'https://chat.estate.example/api/turn';
        const withBody = (body: unknown, replyPath: unknown[] = ['reply']) => [chatTarget(chat, { body, replyPath })];
        expect(verify(signed({ targets: withBody({ input: '{{probe}}', options: { temperature: 0, tags: ['a'] } }, ['output', 0, 'text']) })).ok).toBe(true);
        expect(refused([{ kind: 'http-chat', endpoint: chat }])).toBe('SCHEMA');
        expect(refused(withBody({ input: 'no placeholder' }))).toBe('SCHEMA');
        expect(refused(withBody({ a: '{{probe}}', b: '{{probe}}' }))).toBe('SCHEMA');
        expect(refused(withBody({ input: 'say {{probe}} now' }))).toBe('SCHEMA');
        expect(refused(withBody({ '{{probe}}': 'x' }))).toBe('SCHEMA');
        expect(refused(withBody({ input: '{{probe}}', token: `ghp_${'Z'.repeat(36)}` }))).toBe('SCHEMA');
        expect(refused(withBody({ input: '{{probe}}', pad: 'x'.repeat(9000) }))).toBe('SCHEMA');
        let deep: unknown = '{{probe}}';
        for (let i = 0; i < 17; i += 1) deep = { d: deep };
        expect(refused(withBody(deep))).toBe('SCHEMA');
        expect(refused(withBody({ input: '{{probe}}' }, []))).toBe('SCHEMA');
        expect(refused(withBody({ input: '{{probe}}' }, [-1]))).toBe('SCHEMA');
    });

    it('a target of one kind may not carry another kind\'s members', () => {
        expect(refused([{ ...mcpTarget('https://mcp.estate.example/mcp'), request: { body: { a: '{{probe}}' }, replyPath: ['r'] } }])).toBe('SCHEMA');
    });
});
