/**
 * A probe run as its signed report: built from a real run against fake
 * agents, signed by the prober, read back by the contract's verifier.
 */
import { createPrivateKey, createPublicKey } from 'node:crypto';

import { probeReportConcluded, verifyAndParseProbesReport } from '@rodnapamet/scanent-contract/probes-contract';

import { PROBES } from '../src/catalogue';
import { ProbeReportRefused, buildProbeReport, catalogueDigest, signProbeReport } from '../src/report';
import { runProbes } from '../src/runner';
import { verifyEngagementScope } from '../src/scope';
import { signScope } from '../src/scope-sign';
import { FAKE_TOOL_TOKEN, PLANTED_MARKER, obedient, resistant, silent } from './helpers/fake-agents';
import { fakeClock, fakeTransport } from './helpers/fake-transport';
import { START_MS, makeKey, scopeBody } from './helpers/scope-keys';

const approver = makeKey();
const prober = makeKey();
const proberKeys = () => {
    const privateKey = createPrivateKey(prober.pem);
    return { privateKey, publicKey: createPublicKey(privateKey) };
};

const MCP = 'https://mcp.estate.example/mcp';
const CHAT = 'https://chat.estate.example/api/turn';

function verifiedScope() {
    const raw = signScope(scopeBody(prober, { targets: [{ kind: 'mcp', endpoint: MCP }, { kind: 'http-chat', endpoint: CHAT }] }), approver);
    const result = verifyEngagementScope(raw, { trustedScopeKeys: [approver.hex], proberKey: prober.hex });
    if (!result.ok) throw new Error(result.reason);
    return result;
}

async function runAgainst(agents: Parameters<typeof fakeTransport>[0], dryRun = false) {
    const scope = verifiedScope();
    const clock = fakeClock(START_MS);
    const { transport } = fakeTransport(agents, clock);
    const run = await runProbes({ scope, transport, now: clock.now, sleep: clock.sleep, plantedContext: [PLANTED_MARKER], dryRun });
    return { scope, run };
}

describe('the signed report of a run', () => {
    it('round-trips: built, signed by the prober, verified against the prober\'s key', async () => {
        const { scope, run } = await runAgainst({ [MCP]: obedient, [CHAT]: resistant });
        const raw = signProbeReport(buildProbeReport(run, scope), proberKeys(), scope);
        const read = verifyAndParseProbesReport(raw, [prober.hex]);
        expect(read.ok).toBe(true);
        if (!read.ok) return;
        expect(read.body.engagement).toEqual({ id: 'eng-2026-12-acme', scopeDigest: scope.digest, scopeSignerFingerprint: scope.signerFingerprint });
        expect(read.body.catalogue).toEqual({ digest: catalogueDigest(), probes: PROBES.length });
        expect(read.body.outcomes).toHaveLength(run.outcomes.length);
        expect(read.body.targets.map((t) => t.reason)).toEqual(['REACHED', 'REACHED']);
        expect(probeReportConcluded(read.body)).toBe(true);
    });

    it('is not verified against the approver\'s key: the prober signs its report', async () => {
        const { scope, run } = await runAgainst({ [MCP]: resistant, [CHAT]: resistant });
        const raw = signProbeReport(buildProbeReport(run, scope), proberKeys(), scope);
        expect(verifyAndParseProbesReport(raw, [approver.hex])).toEqual({ ok: false, reason: 'UNTRUSTED_SIGNER' });
    });

    it('carries no secret, no planted marker, no approver and no contact', async () => {
        const { scope, run } = await runAgainst({ [MCP]: obedient, [CHAT]: obedient });
        const raw = signProbeReport(buildProbeReport(run, scope), proberKeys(), scope);
        for (const absent of [FAKE_TOOL_TOKEN, 'hunter2pass', PLANTED_MARKER, 'Dana Approver', 'Head of Security', '+44']) {
            expect(raw.toLowerCase()).not.toContain(absent.toLowerCase());
        }
    });

    it('a run that reached nothing is a report that concludes nothing', async () => {
        const { scope, run } = await runAgainst({ [MCP]: silent, [CHAT]: silent });
        const read = verifyAndParseProbesReport(signProbeReport(buildProbeReport(run, scope), proberKeys(), scope), [prober.hex]);
        expect(read.ok && probeReportConcluded(read.body)).toBe(false);
    });

    it('a dry run has no report', async () => {
        const { scope, run } = await runAgainst({}, true);
        expect(() => buildProbeReport(run, scope)).toThrow(ProbeReportRefused);
    });

    it('a run under another scope is not reported under this one', async () => {
        const { run } = await runAgainst({ [MCP]: resistant, [CHAT]: resistant });
        const other = verifyEngagementScope(signScope(scopeBody(prober, { engagementId: 'eng-other-1234' }), approver), {
            trustedScopeKeys: [approver.hex],
            proberKey: prober.hex,
        });
        if (!other.ok) throw new Error(other.reason);
        expect(() => buildProbeReport(run, other)).toThrow('not run under this scope');
    });

    it('only the prober the scope names signs', async () => {
        const { scope, run } = await runAgainst({ [MCP]: resistant, [CHAT]: resistant });
        const other = createPrivateKey(makeKey().pem);
        expect(() => signProbeReport(buildProbeReport(run, scope), { privateKey: other, publicKey: createPublicKey(other) }, scope)).toThrow(
            'not the prober the scope names',
        );
    });
});

describe('the catalogue digest', () => {
    it('changes when any probe changes, and not otherwise', () => {
        expect(catalogueDigest()).toBe(catalogueDigest());
        expect(catalogueDigest()).toMatch(/^sha256:[0-9a-f]{64}$/);
        const edited = PROBES.map((p, i) => (i === 0 ? { ...p, text: `${p.text} ` } : p));
        expect(catalogueDigest(edited)).not.toBe(catalogueDigest());
        expect(catalogueDigest(PROBES.slice(1))).not.toBe(catalogueDigest());
    });
});
