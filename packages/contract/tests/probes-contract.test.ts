/**
 * `scanent-probes/1`: the signed report of a probe run. Every rule the schema
 * holds, and the verifier's order, on bodies built here.
 */
import { verifyAndParseAgentRulesReport } from '../src/agent-rules-contract';
import { verifyAndParseIntegrationsReport } from '../src/integrations-contract';
import {
    MAX_PROBE_EXCERPT_CHARS,
    PROBES_CONTRACT_V1,
    PROBE_VERDICT_REASONS,
    VERDICT_OF_REASON,
    endpointProblem,
    probeReportConcluded,
    verifyAndParseProbesReport,
} from '../src/probes-contract';
import { createFakeScanner } from './helpers/agent-harness-fake-scanner';

const prober = createFakeScanner();
const MCP = 'https://mcp.estate.example/mcp';
const CHAT = 'https://chat.estate.example/api/turn';
const HASH = `sha256:${'a'.repeat(64)}`;

type Body = Record<string, unknown> & { targets: Record<string, unknown>[]; outcomes: Record<string, unknown>[] };

function body(): Body {
    return {
        contract: PROBES_CONTRACT_V1,
        engagement: { id: 'eng-2026-12-acme', scopeDigest: HASH, scopeSignerFingerprint: 'b'.repeat(64) },
        catalogue: { digest: `sha256:${'c'.repeat(64)}`, probes: 11 },
        run: { startedAt: '2026-12-01T09:00:00.000Z', endedAt: '2026-12-01T09:05:00.000Z', stopped: null },
        targets: [
            { endpoint: MCP, kind: 'mcp', reached: true, reason: 'REACHED' },
            { endpoint: CHAT, kind: 'http-chat', reached: false, reason: 'NO_REPLY' },
        ],
        outcomes: [
            { probeId: 'canary.instruction-override.1', probeClass: 'canary', endpoint: MCP, tool: 'search_orders', verdict: 'ACTED', reason: 'CANARY_RETURNED', replyDigest: HASH, excerpt: 'Done. scanent-0123456789abcdef01234567' },
            { probeId: 'disclosure.credential-disclosure.2', probeClass: 'disclosure', endpoint: MCP, tool: 'search_orders', verdict: 'DISCLOSED', reason: 'CREDENTIAL_SHAPE_RETURNED', replyDigest: HASH, excerpt: 'My token: [masked]' },
            { probeId: 'disclosure.credential-disclosure.2', probeClass: 'disclosure', endpoint: MCP, tool: 'search_orders', verdict: 'RESISTED', reason: 'NO_LEAK', replyDigest: HASH },
            { probeId: 'canary.indirect-injection.1', probeClass: 'canary', endpoint: CHAT, verdict: 'INCONCLUSIVE', reason: 'NO_REPLY' },
        ],
    };
}

const verify = (b: unknown, trusted: readonly string[] = [prober.publicKeyHex]) => verifyAndParseProbesReport(prober.serialise(b), trusted);

function refusedAt(mutate: (b: Body) => void): string[] {
    const b = body();
    mutate(b);
    const result = verify(b);
    expect(result).toMatchObject({ ok: false, reason: 'SCHEMA' });
    return result.ok ? [] : [...(result.issues ?? [])];
}

describe('a probes report', () => {
    it('verifies, signed by a trusted prober', () => {
        const result = verify(body());
        expect(result.ok).toBe(true);
        if (result.ok) {
            expect(result.signerKey).toBe(prober.publicKeyHex);
            expect(result.body.outcomes).toHaveLength(4);
        }
    });

    it('is refused in the envelope\'s order before any member is read', () => {
        expect(verifyAndParseProbesReport('{', [prober.publicKeyHex])).toEqual({ ok: false, reason: 'NOT_JSON' });
        expect(verifyAndParseProbesReport(JSON.stringify(body()), [prober.publicKeyHex])).toEqual({ ok: false, reason: 'UNSIGNED' });
        expect(verify(body(), [createFakeScanner().publicKeyHex])).toEqual({ ok: false, reason: 'UNTRUSTED_SIGNER' });
        const signed = JSON.parse(prober.serialise(body())) as Record<string, unknown>;
        expect(verifyAndParseProbesReport(JSON.stringify({ ...signed, outcomes: [] }), [prober.publicKeyHex])).toEqual({
            ok: false,
            reason: 'BAD_SIGNATURE',
        });
    });

    it('is read by no other contract\'s verifier, and reads none of theirs', () => {
        const raw = prober.serialise(body());
        expect(verifyAndParseAgentRulesReport(raw, [prober.publicKeyHex])).toMatchObject({ ok: false, reason: 'SCHEMA' });
        expect(verifyAndParseIntegrationsReport(raw, [prober.publicKeyHex])).toMatchObject({ ok: false, reason: 'SCHEMA' });
        expect(verify({ ...body(), contract: 'scanent-agent-rules/1' })).toEqual({
            ok: false,
            reason: 'SCHEMA',
            issues: ['contract: not a contract id this verifier accepts'],
        });
    });
});

describe('what it cannot say', () => {
    it('that it concluded: a reader derives it', () => {
        refusedAt((b) => {
            b.concluded = true;
        });
        const all = verify(body());
        expect(all.ok && probeReportConcluded(all.body)).toBe(true);
        const nothing = body();
        nothing.outcomes = nothing.outcomes.filter((o) => o.verdict === 'INCONCLUSIVE');
        nothing.targets = [nothing.targets[1]];
        const none = verify(nothing);
        expect(none.ok).toBe(true);
        expect(none.ok && probeReportConcluded(none.body)).toBe(false);
    });

    it('a verdict its reason does not give', () => {
        expect(refusedAt((b) => (b.outcomes[2].verdict = 'DISCLOSED')).join(' ')).toContain('outcomes.2.verdict');
        for (const reason of PROBE_VERDICT_REASONS) expect(['ACTED', 'DISCLOSED', 'RESISTED', 'INCONCLUSIVE']).toContain(VERDICT_OF_REASON[reason]);
    });

    it('ACTED on a disclosure probe, or DISCLOSED on a canary probe', () => {
        refusedAt((b) => Object.assign(b.outcomes[1], { probeClass: 'disclosure', verdict: 'ACTED', reason: 'CANARY_RETURNED' }));
        refusedAt((b) => Object.assign(b.outcomes[0], { verdict: 'DISCLOSED', reason: 'CREDENTIAL_SHAPE_RETURNED' }));
    });

    it('a class its probe id does not name, or an id of another shape', () => {
        refusedAt((b) => (b.outcomes[0].probeClass = 'disclosure'));
        // On a reason either class gives (NO_REPLY), only the id's own prefix can refuse it.
        refusedAt((b) => (b.outcomes[3].probeClass = 'disclosure'));
        refusedAt((b) => (b.outcomes[0].probeId = 'side-effect.fetch.1'));
        refusedAt((b) => (b.outcomes[0].probeId = 'canary.Override.1'));
    });

    it('side-effect: not a class version 1 has', () => {
        refusedAt((b) => Object.assign(b.outcomes[0], { probeClass: 'side-effect', probeId: 'side-effect.fetch.1' }));
    });

    it('a reply digest without a reply, or a reply without one', () => {
        refusedAt((b) => (b.outcomes[3].replyDigest = HASH));
        refusedAt((b) => delete b.outcomes[2].replyDigest);
    });

    it('an excerpt beside RESISTED or INCONCLUSIVE, none beside ACTED, one too long, or one holding a secret', () => {
        refusedAt((b) => (b.outcomes[2].excerpt = 'I cannot help with that.'));
        refusedAt((b) => delete b.outcomes[0].excerpt);
        refusedAt((b) => (b.outcomes[1].excerpt = 'x'.repeat(MAX_PROBE_EXCERPT_CHARS + 1)));
        const issues = refusedAt((b) => (b.outcomes[1].excerpt = `My token: ghp_${'Z'.repeat(36)}`));
        expect(issues.join(' ')).not.toContain('ghp_');
    });

    it('an MCP outcome without the tool it called, a tool on another kind\'s outcome, or a tool name of another shape', () => {
        refusedAt((b) => delete b.outcomes[0].tool);
        refusedAt((b) => (b.outcomes[3].tool = 'search_orders'));
        refusedAt((b) => (b.outcomes[0].tool = 'has space'));
    });

    it('an outcome for a target it did not list', () => {
        refusedAt((b) => (b.outcomes[0].endpoint = 'https://other.example/mcp'));
    });

    it('a target state its outcomes contradict', () => {
        refusedAt((b) => Object.assign(b.targets[1], { reached: true, reason: 'REACHED' }));
        refusedAt((b) => Object.assign(b.targets[0], { reached: false, reason: 'NOT_RUN' }));
        refusedAt((b) => (b.targets[0].reached = false));
        refusedAt((b) => Object.assign(b.targets[1], { reason: 'NO_PROBES_FOR_INTERFACE' }));
        // NO_REPLY with nothing sent is NOT_RUN, not NO_REPLY.
        refusedAt((b) => {
            b.outcomes = b.outcomes.filter((o) => o.endpoint !== CHAT);
        });
    });

    it('a target named twice, an endpoint that is not exact, an unknown member', () => {
        refusedAt((b) => b.targets.push({ ...b.targets[0] }));
        refusedAt((b) => (b.targets[0].endpoint = 'https://MCP.estate.example/mcp'));
        refusedAt((b) => (b.targets[0].endpoint = 'https://user:pw@mcp.estate.example/mcp'));
        refusedAt((b) => (b.engagement = { ...(b.engagement as object), approver: 'Dana' }));
        refusedAt((b) => (b.outcomes[0].canary = 'x'));
    });

    it('a run that ended before it started, or a stop it does not know', () => {
        refusedAt((b) => (b.run = { startedAt: '2026-12-01T09:05:00.000Z', endedAt: '2026-12-01T09:00:00.000Z', stopped: null }));
        refusedAt((b) => (b.run = { ...(b.run as object), stopped: 'CRASHED' }));
    });

    it('no target at all', () => {
        refusedAt((b) => {
            b.targets = [];
            b.outcomes = [];
        });
    });
});

describe('the exact-endpoint rule', () => {
    it('is the one the engagement scope uses', () => {
        expect(endpointProblem(MCP)).toBeNull();
        expect(endpointProblem('http://mcp.estate.example/mcp')).toBe('not https');
    });
});
