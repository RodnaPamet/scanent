/**
 * `scanent-vulnerabilities/1`: a strict schema of its own, verified by the
 * agent report's envelope rules, and the planner that reads it.
 */
import { generateKeyPairSync, sign } from 'crypto';

import { harnessSignedMessage } from '../src/harness-contract';
import { verifyAndParseIntegrationsReport } from '../src/integrations-contract';
import {
    ATTACK_CLASSES,
    ATTACK_CLASS_TITLE,
    capSeverity,
    codeRangeLocator,
    OWASP_API_TOP_10_2023,
    OWASP_API_TOP_10_2023_TITLE,
    OWASP_TOP_10_2021,
    OWASP_TOP_10_2021_TITLE,
    parseCodeRange,
    rangesOverlap,
    SEVERITY_CAP,
    VulnerabilitiesReportBodyV1Schema,
    verifyAndParseVulnerabilitiesReport,
    withinSeverityCap,
} from '../src/vulnerabilities-contract';
import { planVulnerabilitiesScan, VULNERABILITY_NOT_CONCLUDED_WHY } from '../src/vulnerabilities-findings';
import { body as integrationsBody } from './helpers/integrations-bodies';
import { body, finding, notRunBody } from './helpers/vulnerabilities-bodies';

const keys = generateKeyPairSync('ed25519');
const PUBLIC = keys.publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('hex');
function signed(b: unknown): string {
    const wire = JSON.parse(JSON.stringify(b)) as Record<string, unknown>;
    return JSON.stringify({ ...wire, signature: { alg: 'ed25519', signerKey: PUBLIC, sig: sign(null, harnessSignedMessage(wire), keys.privateKey).toString('hex') } });
}

const issuesOf = (b: unknown): string[] => {
    const r = VulnerabilitiesReportBodyV1Schema.safeParse(b);
    return r.success ? [] : r.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`);
};

describe('the closed lists', () => {
    it('names a title for every attack class and every OWASP category', () => {
        expect(Object.keys(ATTACK_CLASS_TITLE)).toEqual([...ATTACK_CLASSES]);
        expect(Object.keys(OWASP_TOP_10_2021_TITLE)).toEqual([...OWASP_TOP_10_2021]);
        expect(Object.keys(OWASP_API_TOP_10_2023_TITLE)).toEqual([...OWASP_API_TOP_10_2023]);
    });
});

describe('the severity cap (owner decision, 2026-11-15)', () => {
    it('lets a confirmed finding reach HIGH and holds one that needs validation to MEDIUM', () => {
        expect(SEVERITY_CAP).toEqual({ confirmed: 'HIGH', needs_validation: 'MEDIUM' });
        expect(withinSeverityCap('confirmed', 'HIGH')).toBe(true);
        expect(withinSeverityCap('needs_validation', 'HIGH')).toBe(false);
        expect(withinSeverityCap('needs_validation', 'MEDIUM')).toBe(true);
    });

    it('lowers a model answer to the cap, and reads CRITICAL or nonsense as the cap', () => {
        expect(capSeverity('confirmed', 'CRITICAL')).toBe('HIGH');
        expect(capSeverity('needs_validation', 'HIGH')).toBe('MEDIUM');
        expect(capSeverity('needs_validation', 'critical!')).toBe('MEDIUM');
        expect(capSeverity('confirmed', 'LOW')).toBe('LOW');
        expect(capSeverity('needs_validation', 'INFO')).toBe('INFO');
    });
});

describe('locators', () => {
    it('reads and writes a place, and refuses one that climbs out or runs backwards', () => {
        const r = parseCodeRange('code://shop/src/a.ts#L3-L9');
        expect(r).toEqual({ label: 'shop', path: 'src/a.ts', startLine: 3, endLine: 9 });
        expect(codeRangeLocator(r!)).toBe('code://shop/src/a.ts#L3-L9');
        expect(parseCodeRange('code://shop/../etc/passwd#L1-L1')).toBeNull();
        expect(parseCodeRange('code://shop/src/./a.ts#L1-L1')).toBeNull();
        expect(parseCodeRange('code://shop/src/a.ts#L9-L3')).toBeNull();
        expect(parseCodeRange('code://shop/src/a.ts#L3')).toBeNull();
        expect(parseCodeRange('https://example.com/a.ts#L1-L2')).toBeNull();
        expect(parseCodeRange(`code://shop/${'a/'.repeat(400)}x.ts#L1-L2`)).toBeNull();
    });

    it('says two ranges overlap only in one file and on a shared line', () => {
        const a = parseCodeRange('code://shop/a.ts#L3-L5')!;
        expect(rangesOverlap(a, parseCodeRange('code://shop/a.ts#L5-L8')!)).toBe(true);
        expect(rangesOverlap(a, parseCodeRange('code://shop/a.ts#L6-L8')!)).toBe(false);
        expect(rangesOverlap(a, parseCodeRange('code://shop/b.ts#L3-L5')!)).toBe(false);
        expect(rangesOverlap(a, parseCodeRange('code://other/a.ts#L3-L5')!)).toBe(false);
    });
});

describe('the strict schema', () => {
    it('accepts a body as the scanner writes it, and the default run that did not run', () => {
        expect(issuesOf(body())).toEqual([]);
        expect(issuesOf(notRunBody())).toEqual([]);
    });

    it('refuses an unknown member anywhere: code, a level, completeness', () => {
        expect(issuesOf({ ...body(), complete: true })).not.toEqual([]);
        expect(issuesOf(body({ findings: [{ ...finding(), excerpt: 'SELECT 1' } as never] }))).not.toEqual([]);
        expect(issuesOf(body({ sent: ['src/routes/users.ts'] }))).not.toEqual([]);
    });

    it('refuses CRITICAL, and more than a verdict allows', () => {
        expect(issuesOf(body({ findings: [finding({ severity: 'CRITICAL' as never })] }))).not.toEqual([]);
        const nv = finding({ verdict: 'needs_validation', severity: 'HIGH', remediation: null, toValidate: 'Check whether the route is mounted behind the admin gate.' });
        expect(issuesOf(body({ findings: [nv] }))).toEqual(['findings.0.severity: a needs_validation finding is at most MEDIUM']);
        expect(issuesOf(body({ findings: [{ ...nv, severity: 'MEDIUM' }] }))).toEqual([]);
    });

    it('pairs a confirmed finding with a remediation, and one that needs validation with what would settle it', () => {
        expect(issuesOf(body({ findings: [finding({ remediation: null })] }))).not.toEqual([]);
        expect(issuesOf(body({ findings: [finding({ toValidate: 'Something.' })] }))).not.toEqual([]);
        expect(issuesOf(body({ findings: [finding({ verdict: 'needs_validation', severity: 'LOW', toValidate: null, remediation: null })] }))).not.toEqual([]);
    });

    it('holds a trace to entry point, propagation, sink', () => {
        const step = (kind: 'entrypoint' | 'propagation' | 'sink', l = 8) => ({ kind, locator: `code://shop/src/routes/users.ts#L${l}-L${l}` });
        expect(issuesOf(body({ findings: [finding({ trace: [step('sink')] })] }))).toEqual([]);
        expect(issuesOf(body({ findings: [finding({ trace: [step('propagation')] })] }))).not.toEqual([]);
        expect(issuesOf(body({ findings: [finding({ trace: [step('entrypoint'), step('propagation'), step('sink')] })] }))).toEqual([]);
        expect(issuesOf(body({ findings: [finding({ trace: [step('sink'), step('entrypoint')] })] }))).not.toEqual([]);
        expect(issuesOf(body({ findings: [finding({ trace: [step('entrypoint'), step('sink'), step('sink')] })] }))).not.toEqual([]);
    });

    it('refuses a code block or a secret in prose', () => {
        const token = ['gh', 'p_', 'A1'.repeat(12)].join('');
        expect(issuesOf(body({ findings: [finding({ remediation: 'Use ```db.query(sql, [name])```' })] }))).not.toEqual([]);
        expect(issuesOf(body({ findings: [finding({ condition: `The token ${token} is accepted.` })] }))).not.toEqual([]);
        expect(issuesOf(body({ findings: [finding({ title: 'two\nlines' })] }))).not.toEqual([]);
    });

    it('places every locator in a repository the report lists', () => {
        expect(issuesOf(body({ sent: ['code://elsewhere/a.ts#L1-L2'] }))).toEqual(['sent.0: a place names a repository the report lists']);
        expect(issuesOf(body({ findings: [finding({ trace: [{ kind: 'sink', locator: 'code://elsewhere/a.ts#L1-L2' }] })] }))).not.toEqual([]);
        expect(issuesOf(body({ run: { ...body().run, status: 'INCOMPLETE', reason: 'TIME_BOX' }, notReviewed: [{ locator: 'code://elsewhere/a.ts#L1-L2', reason: 'TIME_BOX' }] }))).not.toEqual([]);
    });

    it('lists each repository, excerpt and finding once', () => {
        expect(issuesOf(body({ repositories: [body().repositories[0], body().repositories[0]] }))).not.toEqual([]);
        expect(issuesOf(body({ sent: [body().sent[0], body().sent[0]] }))).not.toEqual([]);
        expect(issuesOf(body({ findings: [finding(), finding()], counts: { candidates: 3, rejected: 0, discarded: 0 } }))).not.toEqual([]);
    });

    it('keeps the counts honest: a finding is a candidate that survived', () => {
        expect(issuesOf(body({ counts: { candidates: 1, rejected: 1, discarded: 0 } }))).not.toEqual([]);
        expect(issuesOf(body({ counts: { candidates: 1, rejected: 2, discarded: 0 } }))).not.toEqual([]);
    });

    it('lets a run that did not run send and find nothing, and say why', () => {
        const nr = notRunBody();
        expect(issuesOf({ ...nr, findings: [finding()], counts: { candidates: 1, rejected: 0, discarded: 0 } })).not.toEqual([]);
        expect(issuesOf({ ...nr, sent: ['code://shop/a.ts#L1-L2'] })).not.toEqual([]);
        expect(issuesOf({ ...nr, run: { ...nr.run, reason: undefined } })).not.toEqual([]);
        expect(issuesOf({ ...nr, run: { ...nr.run, reason: 'TIME_BOX' } })).not.toEqual([]);
        expect(issuesOf({ ...nr, run: { ...nr.run, used: { tokens: 5, files: 0, seconds: 0 } } })).not.toEqual([]);
        expect(issuesOf({ ...nr, repositories: [{ label: 'shop', status: 'REVIEWED', selectedFiles: 1 }] })).not.toEqual([]);
        expect(issuesOf({ ...nr, run: { ...nr.run, model: body().run.model } })).not.toEqual([]);
        expect(issuesOf({ ...nr, run: { ...nr.run, reason: 'NO_REPOSITORY' } })).not.toEqual([]);
        expect(issuesOf({ ...nr, run: { ...nr.run, reason: 'NO_REPOSITORY' }, repositories: [] })).toEqual([]);
        expect(issuesOf({ ...nr, repositories: [] })).not.toEqual([]);
    });

    it('lets a run that ran name its model and the record that let it run', () => {
        expect(issuesOf(body({ run: { ...body().run, model: null } }))).not.toEqual([]);
        expect(issuesOf(body({ run: { ...body().run, evaluation: null } }))).not.toEqual([]);
        expect(issuesOf(body({ run: { ...body().run, model: { ...body().run.model!, host: 'https://api.anthropic.com/v1' } } }))).not.toEqual([]);
    });

    it('never calls a review of no repository, or of part of one, complete', () => {
        const none = { repositories: [], sent: [], findings: [], counts: { candidates: 0, rejected: 0, discarded: 0 } };
        const noneMessage = 'repositories: a run that ran reviewed at least one repository: with none, it did not run (NO_REPOSITORY)';
        expect(issuesOf(body(none))).toEqual([noneMessage]);
        expect(issuesOf(body({ ...none, run: { ...body().run, status: 'INCOMPLETE', reason: 'TIME_BOX' } }))).toEqual([noneMessage]);
        expect(issuesOf(body({ repositories: [{ label: 'shop', status: 'PARTIAL', selectedFiles: 2 }] }))).not.toEqual([]);
        expect(issuesOf(body({ notReviewed: [{ locator: 'code://shop/a.ts#L1-L2', reason: 'BYTE_CAP' }] }))).not.toEqual([]);
        expect(issuesOf(body({ run: { ...body().run, reason: 'TIME_BOX' } }))).not.toEqual([]);
    });

    it('makes an incomplete run say what it did not review', () => {
        const run = { ...body().run, status: 'INCOMPLETE' as const, reason: 'TOKEN_BUDGET' as const };
        expect(issuesOf(body({ run }))).toEqual(['notReviewed: an INCOMPLETE run says what it did not review']);
        expect(issuesOf(body({ run, repositories: [{ label: 'shop', status: 'PARTIAL', selectedFiles: 2 }] }))).toEqual([]);
        expect(issuesOf(body({ run: { ...run, reason: 'MODEL_NOT_CONFIGURED' as never }, repositories: [{ label: 'shop', status: 'PARTIAL', selectedFiles: 2 }] }))).not.toEqual([]);
    });
});

describe('verifyAndParseVulnerabilitiesReport', () => {
    it('accepts a signed report from a trusted key, and says whether it is complete', () => {
        const ok = verifyAndParseVulnerabilitiesReport(signed(body()), [PUBLIC]);
        expect(ok).toMatchObject({ ok: true, complete: true });
        expect(verifyAndParseVulnerabilitiesReport(signed(notRunBody()), [PUBLIC])).toMatchObject({ ok: true, complete: false });
    });

    it('refuses an untrusted signer, a changed body and a bad schema, in the envelope order', () => {
        expect(verifyAndParseVulnerabilitiesReport(signed(body()), [])).toEqual({ ok: false, reason: 'UNTRUSTED_SIGNER' });
        const tampered = JSON.parse(signed(body())) as Record<string, unknown>;
        (tampered.counts as Record<string, number>).rejected = 0;
        expect(verifyAndParseVulnerabilitiesReport(JSON.stringify(tampered), [PUBLIC])).toEqual({ ok: false, reason: 'BAD_SIGNATURE' });
        const bad = verifyAndParseVulnerabilitiesReport(signed({ ...body(), complete: true }), [PUBLIC]);
        expect(bad).toMatchObject({ ok: false, reason: 'SCHEMA' });
        expect(JSON.stringify(bad)).not.toContain('complete');
    });

    it('reads no other contract, and no other verifier reads it', () => {
        expect(verifyAndParseVulnerabilitiesReport(signed(integrationsBody()), [PUBLIC])).toEqual({
            ok: false,
            reason: 'SCHEMA',
            issues: ['contract: not a contract id this verifier accepts'],
        });
        expect(verifyAndParseIntegrationsReport(signed(body()), [PUBLIC])).toMatchObject({ ok: false, reason: 'SCHEMA' });
    });
});

describe('planVulnerabilitiesScan', () => {
    it('plans each finding with its code, its place and a stable reference', () => {
        const plan = planVulnerabilitiesScan(body());
        expect(plan.outcome).toBe('FINDINGS');
        expect(plan.findings).toEqual([
            expect.objectContaining({
                code: 'VULNERABILITY_CONFIRMED',
                sourceRef: 'vulnerability:0123456789abcdef',
                severity: 'HIGH',
                attackClassTitle: 'Injection',
                entry: 'code://shop/src/routes/users.ts#L6-L7',
                sink: 'code://shop/src/routes/users.ts#L8-L9',
            }),
        ]);
        expect(plan).toMatchObject({ rejected: 1, discarded: 0, reviewedRepositories: 1, repositories: 1, notConcluded: [] });
    });

    it('orders findings by severity, then confirmed first, then by fingerprint', () => {
        const nv = (id: string, severity: 'LOW' | 'MEDIUM') =>
            finding({ id, verdict: 'needs_validation', severity, remediation: null, toValidate: 'Confirm the route is public.' });
        const findings = [nv('cccccccccccccccc', 'MEDIUM'), finding({ id: 'dddddddddddddddd', severity: 'MEDIUM' }), nv('aaaaaaaaaaaaaaaa', 'LOW'), finding({ id: 'bbbbbbbbbbbbbbbb' }), nv('eeeeeeeeeeeeeeee', 'MEDIUM')];
        const plan = planVulnerabilitiesScan(body({ findings, counts: { candidates: 5, rejected: 0, discarded: 0 } }));
        expect(plan.findings.map((f) => f.sourceRef.slice(-1))).toEqual(['b', 'd', 'c', 'e', 'a']);
        expect(plan.findings[2].code).toBe('VULNERABILITY_NEEDS_VALIDATION');
    });

    it('calls "no finding" clean only on a complete review of something', () => {
        expect(planVulnerabilitiesScan(body({ findings: [] })).outcome).toBe('NO_FINDING_ON_A_COMPLETE_REVIEW');
        const nr = planVulnerabilitiesScan(notRunBody());
        expect(nr.outcome).toBe('NOT_CONCLUDED');
        expect(nr.notConcluded).toEqual([{ scope: 'run', why: 'MODEL_NOT_CONFIGURED' }]);
    });

    it('says what was not reviewed, per repository and per place, on an incomplete run', () => {
        const plan = planVulnerabilitiesScan(
            body({
                run: { ...body().run, status: 'INCOMPLETE', reason: 'TIME_BOX' },
                repositories: [
                    { label: 'shop', status: 'PARTIAL', selectedFiles: 2 },
                    { label: 'admin', status: 'NOT_REVIEWED', selectedFiles: 4 },
                ],
                notReviewed: [{ locator: 'code://shop/src/big.ts#L1-L900', reason: 'BYTE_CAP' }],
                findings: [],
            }),
        );
        expect(plan.outcome).toBe('NOT_CONCLUDED');
        expect(plan.notConcluded).toEqual([
            { scope: 'run', why: 'TIME_BOX' },
            { scope: 'shop', why: 'REPOSITORY_PARTIAL' },
            { scope: 'admin', why: 'REPOSITORY_NOT_REVIEWED' },
            { scope: 'code://shop/src/big.ts#L1-L900', why: 'BYTE_CAP' },
        ]);
        for (const n of plan.notConcluded) expect(VULNERABILITY_NOT_CONCLUDED_WHY[n.why]).toMatch(/\.$/);
    });
});
