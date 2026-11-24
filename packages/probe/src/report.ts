/**
 * A probe run as the signed report `scanent-probes/1` (step 6 of
 * docs/design/active-flavour.md).
 *
 * The report names the engagement by the scope's digest and the fingerprint
 * of the key that signed it: never the approver, never the kill contact. It
 * names the catalogue by digest, so a reader knows which fixed list the
 * verdicts came from. It is signed by the PROBER, the one key the scope names
 * to run it, and checked against the contract's own schema before it is
 * signed, so a report every reader would refuse is never made.
 */
import { sign, type KeyObject } from 'node:crypto';

import { MAX_REPORT_BYTES, describeReportSchemaIssue, harnessKeyFingerprint, harnessSignedMessage } from '@rodnapamet/scanent-contract/harness-contract';
import { PROBES_CONTRACT_V1, ProbesReportBodyV1Schema, type ProbesReportBodyV1 } from '@rodnapamet/scanent-contract/probes-contract';

import { PROBES } from './catalogue';
import { catalogueDigestOf } from './catalogue-digest';
import { probeSurface, surfaceDigest } from './surface';
import type { ProbeRun } from './runner';
import type { ScopeVerifyResult } from './scope';
import { rawPublicKeyHex } from './scope-sign';

/** A report that was not made, and why: paths and rules, never values. */
export class ProbeReportRefused extends Error {
    constructor(readonly issues: readonly string[]) {
        super(`the probe report was not made: ${issues.join('; ')}`);
        this.name = 'ProbeReportRefused';
    }
}

/** The catalogue's digest, as the report and the surface name it. */
export { catalogueDigestOf as catalogueDigest } from './catalogue-digest';

/** The report body of a run, under the scope it ran under. A dry run sent nothing, and has no report. */
export function buildProbeReport(run: ProbeRun, scope: Extract<ScopeVerifyResult, { ok: true }>): ProbesReportBodyV1 {
    if (run.dryRun) throw new ProbeReportRefused(['(run): a dry run sent nothing, and has no report']);
    if (run.scopeDigest !== scope.digest) throw new ProbeReportRefused(['(run): not run under this scope']);
    const body = {
        contract: PROBES_CONTRACT_V1,
        engagement: { id: run.engagementId, scopeDigest: scope.digest, scopeSignerFingerprint: scope.signerFingerprint },
        catalogue: { digest: catalogueDigestOf(), probes: PROBES.length },
        run: { startedAt: run.startedAt, endedAt: run.endedAt, stopped: run.stopped, surfaceDigest: surfaceDigest(probeSurface(scope.scope)) },
        targets: run.targets.map((t) => ({ endpoint: t.endpoint, kind: t.kind, reached: t.reached, reason: t.reason })),
        outcomes: run.outcomes.map((o) => {
            const probe = PROBES.find((p) => p.id === o.probeId);
            if (probe === undefined) throw new ProbeReportRefused(['(outcomes): a probe the catalogue does not hold']);
            return {
                probeId: o.probeId,
                probeClass: probe.class,
                endpoint: o.endpoint,
                verdict: o.verdict,
                reason: o.reason,
                ...(o.tool === undefined ? {} : { tool: o.tool }),
                ...(o.replyDigest === undefined ? {} : { replyDigest: o.replyDigest }),
                ...(o.excerpt === undefined ? {} : { excerpt: o.excerpt }),
            };
        }),
    };
    const parsed = ProbesReportBodyV1Schema.safeParse(body);
    if (!parsed.success) throw new ProbeReportRefused(parsed.error.issues.map(describeReportSchemaIssue));
    return parsed.data;
}

/**
 * Sign a report with the prober's key. Refused when the key is not the prober
 * the scope names: a report another key signed would be refused by every
 * reader that trusts only the registered prober, and by this one first.
 */
export function signProbeReport(
    body: ProbesReportBodyV1,
    keys: { privateKey: KeyObject; publicKey: KeyObject },
    scope: Extract<ScopeVerifyResult, { ok: true }>,
): string {
    const signerKey = rawPublicKeyHex(keys.publicKey);
    if (harnessKeyFingerprint(signerKey) !== harnessKeyFingerprint(scope.scope.proberKey)) {
        throw new ProbeReportRefused(['key: not the prober the scope names']);
    }
    const parsed = ProbesReportBodyV1Schema.safeParse(body);
    if (!parsed.success) throw new ProbeReportRefused(parsed.error.issues.map(describeReportSchemaIssue));

    // Sign what the wire carries, as every report of this repository is signed.
    const wireBody = JSON.parse(JSON.stringify(parsed.data)) as Record<string, unknown>;
    const signature = { alg: 'ed25519' as const, signerKey, sig: sign(null, harnessSignedMessage(wireBody), keys.privateKey).toString('hex') };
    const raw = JSON.stringify({ ...wireBody, signature });
    if (Buffer.byteLength(raw, 'utf8') > MAX_REPORT_BYTES) throw new ProbeReportRefused(['(report): too large']);
    return raw;
}
