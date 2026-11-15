/**
 * The evaluation scorer and gate: rates are recomputed from raw answers, a
 * record is for one corpus and one revision, and no floor means no run.
 */
import {
    evaluationGate,
    evaluationRecordDigest,
    EvaluationRefusal,
    scoreEvaluation,
    VULNERABILITY_EVALUATION_FLOOR,
    type EvaluationCorpus,
    type EvaluationFloor,
    type EvaluationRecord,
} from '../src/vulnerabilities-evaluation';
import type { VulnerabilityFinding } from '../src/vulnerabilities-contract';
import { finding } from './helpers/vulnerabilities-bodies';

const DIGEST = `sha256:${'c'.repeat(64)}`;
const MODEL = { provider: 'anthropic' as const, model: 'claude-test', revision: 'claude-test-20261101' };

const corpus: EvaluationCorpus = {
    digest: DIGEST,
    cases: [
        {
            id: 'sqli',
            kind: 'vulnerable',
            expected: [
                { id: 'sqli-1', attackClass: 'injection', cwe: 'CWE-89', sink: 'code://sqli/src/users.ts#L8-L9' },
                { id: 'sqli-2', attackClass: 'injection', cwe: 'CWE-89', sink: 'code://sqli/src/orders.ts#L4-L4' },
            ],
        },
        { id: 'ssrf', kind: 'vulnerable', expected: [{ id: 'ssrf-1', attackClass: 'resource-and-file-handling', cwe: 'CWE-918', sink: 'code://ssrf/app.py#L10-L10' }] },
        { id: 'clean', kind: 'clean', expected: [] },
    ],
};

let n = 0;
function at(sink: string, over: Partial<VulnerabilityFinding> = {}): VulnerabilityFinding {
    n += 1;
    return finding({ id: n.toString(16).padStart(16, '0'), trace: [{ kind: 'sink', locator: sink }], ...over });
}

function record(answers: Record<string, VulnerabilityFinding[]>, over: Partial<EvaluationRecord> = {}): EvaluationRecord {
    return {
        contract: 'scanent-vulnerability-evaluation/1',
        corpusDigest: DIGEST,
        model: MODEL,
        madeAt: '2026-11-15T12:00:00.000Z',
        answers: Object.entries(answers).map(([caseId, findings]) => ({ caseId, findings, rejected: 0 })),
        ...over,
    };
}

const perfect = () =>
    record({
        sqli: [at('code://sqli/src/users.ts#L9-L9'), at('code://sqli/src/orders.ts#L3-L5')],
        ssrf: [at('code://ssrf/app.py#L10-L10', { attackClass: 'resource-and-file-handling', cwe: 'CWE-918' })],
        clean: [],
    });

describe('scoreEvaluation', () => {
    it('finds every planted weakness when the answers name its class and overlap its sink', () => {
        const s = scoreEvaluation(corpus, perfect());
        expect(s).toMatchObject({ expected: 3, found: 3, missed: 0, invented: 0, duplicates: 0, cweAgreement: 3, findings: 3 });
        expect(s.foundRate).toEqual({ numerator: 3, denominator: 3 });
        expect(s.inventedRate).toEqual({ numerator: 0, denominator: 3 });
        expect(s.perClass.injection).toEqual({ expected: 2, found: 2, missed: 0, invented: 0 });
    });

    it('counts a wrong class or a sink elsewhere as invented, and the planted one as missed', () => {
        const s = scoreEvaluation(
            corpus,
            record({
                sqli: [at('code://sqli/src/users.ts#L8-L8', { attackClass: 'access-control' }), at('code://sqli/src/users.ts#L20-L22')],
                ssrf: [],
                clean: [],
            }),
        );
        expect(s).toMatchObject({ found: 0, missed: 3, invented: 2, inventedOnClean: 0 });
        expect(s.missedIds).toEqual(['sqli-1', 'sqli-2', 'ssrf-1']);
        expect(s.perClass['access-control']).toEqual({ expected: 0, found: 0, missed: 0, invented: 1 });
    });

    it('counts anything on a clean case as invented', () => {
        const s = scoreEvaluation(corpus, record({ sqli: [], ssrf: [], clean: [at('code://clean/src/format.ts#L1-L3')] }));
        expect(s).toMatchObject({ invented: 1, inventedOnClean: 1, found: 0 });
    });

    it('counts a second answer on a weakness already found as a duplicate, never as invented', () => {
        const s = scoreEvaluation(corpus, record({ sqli: [at('code://sqli/src/users.ts#L8-L8'), at('code://sqli/src/users.ts#L9-L9')], ssrf: [], clean: [] }));
        expect(s).toMatchObject({ found: 1, duplicates: 1, invented: 0 });
    });

    it('reports a CWE that disagrees without missing the weakness', () => {
        const s = scoreEvaluation(corpus, record({ sqli: [at('code://sqli/src/users.ts#L8-L8', { cwe: 'CWE-564' })], ssrf: [], clean: [] }));
        expect(s).toMatchObject({ found: 1, cweAgreement: 0 });
    });

    it('refuses a corpus with nothing planted, a record for another corpus, and an unanswered or unknown case', () => {
        expect(() => scoreEvaluation({ digest: DIGEST, cases: [{ id: 'clean', kind: 'clean', expected: [] }] }, record({ clean: [] }))).toThrow(new EvaluationRefusal('EMPTY_CORPUS'));
        expect(() => scoreEvaluation(corpus, { ...perfect(), corpusDigest: `sha256:${'d'.repeat(64)}` })).toThrow(new EvaluationRefusal('CORPUS_MISMATCH'));
        expect(() => scoreEvaluation(corpus, record({ sqli: [], ssrf: [] }))).toThrow(new EvaluationRefusal('CASE_NOT_ANSWERED'));
        expect(() => scoreEvaluation(corpus, record({ sqli: [], ssrf: [], clean: [], extra: [] }))).toThrow(new EvaluationRefusal('UNKNOWN_CASE'));
        const bad: EvaluationCorpus = { digest: DIGEST, cases: [{ id: 'sqli', kind: 'vulnerable', expected: [{ id: 'x', attackClass: 'injection', cwe: 'CWE-89', sink: 'code://other/a.ts#L1-L1' }] }] };
        expect(() => scoreEvaluation(bad, record({ sqli: [] }))).toThrow(new EvaluationRefusal('BAD_EXPECTATION'));
    });
});

describe('evaluationGate', () => {
    const floor: EvaluationFloor = { minFoundRate: { numerator: 2, denominator: 3 }, maxInventedRate: { numerator: 1, denominator: 4 } };

    it('lets nothing run until a floor is published', () => {
        expect(VULNERABILITY_EVALUATION_FLOOR).toBeNull();
        expect(evaluationGate(corpus, MODEL, perfect())).toMatchObject({ ok: false, why: 'FLOOR_NOT_SET' });
    });

    it('runs a revision whose record clears the floor, and names the record by digest', () => {
        const r = perfect();
        const g = evaluationGate(corpus, MODEL, r, floor);
        expect(g).toMatchObject({ ok: true, recordDigest: evaluationRecordDigest(r) });
        expect(evaluationRecordDigest(r)).toMatch(/^sha256:[0-9a-f]{64}$/);
        expect(evaluationRecordDigest({ ...r, madeAt: '2026-11-16T12:00:00.000Z' })).not.toBe(evaluationRecordDigest(r));
    });

    it('stops a revision that finds too little or invents too much, the floor compared in whole numbers', () => {
        const findsTwo = record({ sqli: [at('code://sqli/src/users.ts#L9-L9'), at('code://sqli/src/orders.ts#L4-L4')], ssrf: [], clean: [] });
        expect(evaluationGate(corpus, MODEL, findsTwo, floor)).toMatchObject({ ok: true });
        const findsOne = record({ sqli: [at('code://sqli/src/users.ts#L9-L9')], ssrf: [], clean: [] });
        expect(evaluationGate(corpus, MODEL, findsOne, floor)).toMatchObject({ ok: false, why: 'EVALUATION_BELOW_FLOOR' });
        const invents = record({ ...Object.fromEntries(perfect().answers.map((a) => [a.caseId, a.findings])), clean: [at('code://clean/a.ts#L1-L1'), at('code://clean/b.ts#L1-L1')] });
        expect(evaluationGate(corpus, MODEL, invents, floor)).toMatchObject({ ok: false, why: 'EVALUATION_BELOW_FLOOR' });
    });

    it('treats no record, another revision, another corpus and an unreadable record alike: no record for this one', () => {
        expect(evaluationGate(corpus, MODEL, null, floor)).toEqual({ ok: false, why: 'EVALUATION_MISSING' });
        expect(evaluationGate(corpus, { ...MODEL, revision: 'claude-test-20261201' }, perfect(), floor)).toEqual({ ok: false, why: 'EVALUATION_MISSING' });
        expect(evaluationGate(corpus, MODEL, { ...perfect(), corpusDigest: `sha256:${'d'.repeat(64)}` }, floor)).toEqual({ ok: false, why: 'EVALUATION_MISSING' });
        expect(evaluationGate(corpus, MODEL, { ...perfect(), foundRate: 1 }, floor)).toEqual({ ok: false, why: 'EVALUATION_MISSING' });
        expect(evaluationGate(corpus, MODEL, record({ sqli: [], ssrf: [] }), floor)).toEqual({ ok: false, why: 'EVALUATION_MISSING' });
    });

    it("refuses a record whose answers place a finding outside their own case", () => {
        const r = record({ sqli: [at('code://ssrf/app.py#L10-L10')], ssrf: [], clean: [] });
        expect(evaluationGate(corpus, MODEL, r, floor)).toEqual({ ok: false, why: 'EVALUATION_MISSING' });
    });

    it('lets a corpus defect surface rather than read as a missing record', () => {
        const empty: EvaluationCorpus = { digest: DIGEST, cases: [{ id: 'clean', kind: 'clean', expected: [] }] };
        expect(() => evaluationGate(empty, MODEL, record({ clean: [] }), floor)).toThrow(new EvaluationRefusal('EMPTY_CORPUS'));
    });
});
