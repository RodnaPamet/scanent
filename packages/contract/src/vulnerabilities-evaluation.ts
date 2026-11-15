/**
 * HOW A MODEL REVISION EARNS THE RIGHT TO REVIEW A CLIENT'S CODE.
 *
 * A fixed corpus ships with the scanner: small repositories with weaknesses
 * planted across the attack classes, and clean ones that must produce
 * nothing. A model revision is run over it once, and its raw answers are kept
 * as an evaluation record. This module scores a record and decides whether
 * the revision may run.
 *
 *   • THE SCORE IS RECOMPUTED, NEVER STORED. A record holds the model's
 *     answers, not its rates; `scoreEvaluation` derives found, missed and
 *     invented from the answers every time, so a record cannot claim a rate
 *     its answers do not support.
 *   • A RECORD IS FOR ONE CORPUS AND ONE REVISION. A record scored on another
 *     corpus, or made by another revision, is no record for this one.
 *   • NO FLOOR, NO RUN. Until the owner publishes a floor
 *     (`VULNERABILITY_EVALUATION_FLOOR`), no revision runs, whatever its
 *     record says.
 *   • A CORPUS WITH NOTHING PLANTED SCORES NOTHING. Zero expected weaknesses
 *     is refused, not scored as a perfect find rate.
 *
 * Matching is by place, not by words: an answer finds a planted weakness when
 * it names the same attack class and its sink's lines overlap the planted
 * sink's. A second answer on a weakness already found is a duplicate, counted
 * apart, never "invented". Anything else an answer reports is invented.
 */
import { createHash } from 'crypto';
import { z } from 'zod';

import { canonicalJson } from './canonical-json';
import {
    ATTACK_CLASSES,
    CWE_ID,
    MODEL_NAME,
    MODEL_PROVIDERS,
    parseCodeRange,
    rangesOverlap,
    REPOSITORY_LABEL,
    type AttackClass,
    type CodeRange,
    type ModelProvider,
} from './vulnerabilities-contract-rules';
import { VulnerabilityFindingSchema, type VulnerabilityFinding } from './vulnerabilities-contract';

/** The evaluation record's own contract id. */
export const VULNERABILITY_EVALUATION_CONTRACT_V1 = 'scanent-vulnerability-evaluation/1';

const SHA256_HEX = /^sha256:[0-9a-f]{64}$/;

/** One planted weakness: its class, its CWE and where it does harm. */
export interface EvaluationExpectation {
    readonly id: string;
    readonly attackClass: AttackClass;
    readonly cwe: string;
    /** A locator in the case's own repository: `code://<case id>/<path>#L<a>-L<b>`. */
    readonly sink: string;
}

/** One small repository of the corpus. Its id is the repository label its locators use. */
export interface EvaluationCase {
    readonly id: string;
    readonly kind: 'vulnerable' | 'clean';
    readonly expected: readonly EvaluationExpectation[];
}

export interface EvaluationCorpus {
    /** `sha256:` over the corpus's files; the scanner computes it. */
    readonly digest: string;
    readonly cases: readonly EvaluationCase[];
}

export const EvaluationRecordSchema = z
    .object({
        contract: z.literal(VULNERABILITY_EVALUATION_CONTRACT_V1),
        corpusDigest: z.string().regex(SHA256_HEX),
        model: z
            .object({
                provider: z.enum(MODEL_PROVIDERS),
                model: z.string().regex(MODEL_NAME),
                revision: z.string().regex(MODEL_NAME),
            })
            .strict(),
        /** When the run over the corpus was made. */
        madeAt: z.string().datetime(),
        answers: z
            .array(
                z
                    .object({
                        caseId: z.string().regex(REPOSITORY_LABEL),
                        findings: z.array(VulnerabilityFindingSchema).max(200),
                        /** Candidates the refutation broke on this case. */
                        rejected: z.number().int().min(0),
                    })
                    .strict(),
            )
            .min(1)
            .max(1000),
    })
    .strict()
    .superRefine((r, ctx) => {
        const ids = r.answers.map((a) => a.caseId);
        if (new Set(ids).size !== ids.length) ctx.addIssue({ code: 'custom', message: 'each case is answered once', path: ['answers'] });
        r.answers.forEach((a, i) =>
            a.findings.forEach((f, j) =>
                f.trace.forEach((s, k) => {
                    if (parseCodeRange(s.locator)?.label !== a.caseId) {
                        ctx.addIssue({ code: 'custom', message: "an answer's places are in its own case", path: ['answers', i, 'findings', j, 'trace', k] });
                    }
                }),
            ),
        );
    });

export type EvaluationRecord = z.infer<typeof EvaluationRecordSchema>;

/** The digest a report names as the record that let its model run. */
export function evaluationRecordDigest(record: EvaluationRecord): string {
    return `sha256:${createHash('sha256').update(canonicalJson(record), 'utf8').digest('hex')}`;
}

/** A fraction, kept whole so a rate is never rounded into a pass. Null denominator: nothing to rate. */
export interface Rate {
    readonly numerator: number;
    readonly denominator: number;
}

export interface ClassScore {
    readonly expected: number;
    readonly found: number;
    readonly missed: number;
    readonly invented: number;
}

export interface EvaluationScore {
    readonly expected: number;
    readonly found: number;
    readonly missed: number;
    readonly invented: number;
    readonly duplicates: number;
    /** Found weaknesses whose CWE also matches the planted one. */
    readonly cweAgreement: number;
    /** Findings on clean cases: each is invented. */
    readonly inventedOnClean: number;
    readonly findings: number;
    readonly foundRate: Rate;
    /** Invented findings over every finding answered. */
    readonly inventedRate: Rate;
    readonly perClass: Readonly<Partial<Record<AttackClass, ClassScore>>>;
    /** Each planted weakness that was missed, by id. */
    readonly missedIds: readonly string[];
}

export class EvaluationRefusal extends Error {
    constructor(readonly why: 'EMPTY_CORPUS' | 'CORPUS_MISMATCH' | 'CASE_NOT_ANSWERED' | 'UNKNOWN_CASE' | 'BAD_EXPECTATION') {
        super(`evaluation refused: ${why}`);
        this.name = 'EvaluationRefusal';
    }
}

function sinkOf(f: VulnerabilityFinding): CodeRange | null {
    return parseCodeRange(f.trace[f.trace.length - 1].locator);
}

/**
 * Score a record against the corpus it names. Throws `EvaluationRefusal` for a
 * corpus with nothing planted, a record for another corpus, or a record that
 * leaves a case unanswered or answers one the corpus does not have.
 */
export function scoreEvaluation(corpus: EvaluationCorpus, record: EvaluationRecord): EvaluationScore {
    const expectations = corpus.cases.flatMap((c) => c.expected);
    if (expectations.length === 0) throw new EvaluationRefusal('EMPTY_CORPUS');
    if (record.corpusDigest !== corpus.digest) throw new EvaluationRefusal('CORPUS_MISMATCH');
    const answers = new Map(record.answers.map((a) => [a.caseId, a]));
    for (const a of record.answers) if (!corpus.cases.some((c) => c.id === a.caseId)) throw new EvaluationRefusal('UNKNOWN_CASE');

    const perClass: Partial<Record<AttackClass, { expected: number; found: number; missed: number; invented: number }>> = {};
    const bump = (cls: AttackClass, key: 'expected' | 'found' | 'missed' | 'invented') => {
        const s = (perClass[cls] ??= { expected: 0, found: 0, missed: 0, invented: 0 });
        s[key] += 1;
    };

    let found = 0;
    let invented = 0;
    let duplicates = 0;
    let cweAgreement = 0;
    let inventedOnClean = 0;
    let findings = 0;
    const missedIds: string[] = [];

    for (const c of corpus.cases) {
        const answer = answers.get(c.id);
        if (answer === undefined) throw new EvaluationRefusal('CASE_NOT_ANSWERED');
        const planted = c.expected.map((e) => {
            const range = parseCodeRange(e.sink);
            if (range === null || range.label !== c.id || !CWE_ID.test(e.cwe) || !(ATTACK_CLASSES as readonly string[]).includes(e.attackClass)) {
                throw new EvaluationRefusal('BAD_EXPECTATION');
            }
            return { e, range, hit: false };
        });
        for (const p of planted) bump(p.e.attackClass, 'expected');

        const ordered = [...answer.findings].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
        for (const f of ordered) {
            findings += 1;
            const sink = sinkOf(f);
            const matches = sink === null ? [] : planted.filter((p) => p.e.attackClass === f.attackClass && rangesOverlap(p.range, sink));
            const fresh = matches.find((p) => !p.hit);
            if (fresh !== undefined) {
                fresh.hit = true;
                found += 1;
                bump(f.attackClass, 'found');
                if (fresh.e.cwe === f.cwe) cweAgreement += 1;
            } else if (matches.length > 0) {
                duplicates += 1;
            } else {
                invented += 1;
                bump(f.attackClass, 'invented');
                if (c.kind === 'clean') inventedOnClean += 1;
            }
        }
        for (const p of planted) {
            if (!p.hit) {
                bump(p.e.attackClass, 'missed');
                missedIds.push(p.e.id);
            }
        }
    }

    return {
        expected: expectations.length,
        found,
        missed: expectations.length - found,
        invented,
        duplicates,
        cweAgreement,
        inventedOnClean,
        findings,
        foundRate: { numerator: found, denominator: expectations.length },
        inventedRate: { numerator: invented, denominator: findings },
        perClass,
        missedIds: missedIds.sort(),
    };
}

/** The bar a model revision's record must clear to run. */
export interface EvaluationFloor {
    /** The lowest share of planted weaknesses it must find, as a fraction. */
    readonly minFoundRate: Rate;
    /** The highest share of its findings that may be invented, as a fraction. */
    readonly maxInventedRate: Rate;
}

/**
 * The published floor. Null until one is fixed from measurements on the
 * corpus and on a real repository, because a floor chosen before anything was
 * measured would be a guess: until then no revision runs, and the report says
 * `FLOOR_NOT_SET` (docs/design/vulnerability-scanner.md).
 */
export const VULNERABILITY_EVALUATION_FLOOR: EvaluationFloor | null = null;

/** a/b >= c/d, in whole numbers. */
const atLeast = (a: Rate, b: Rate): boolean => a.numerator * b.denominator >= b.numerator * a.denominator;

export type EvaluationGate =
    | { readonly ok: true; readonly recordDigest: string; readonly score: EvaluationScore }
    | { readonly ok: false; readonly why: 'EVALUATION_MISSING' | 'EVALUATION_BELOW_FLOOR' | 'FLOOR_NOT_SET'; readonly score?: EvaluationScore };

/**
 * Whether the configured model revision may run. No record, a record for
 * another revision or another corpus, and a record that does not parse are all
 * `EVALUATION_MISSING`: none is a record for this revision on this corpus.
 */
export function evaluationGate(
    corpus: EvaluationCorpus,
    model: { readonly provider: ModelProvider; readonly model: string; readonly revision: string },
    rawRecord: unknown,
    floor: EvaluationFloor | null = VULNERABILITY_EVALUATION_FLOOR,
): EvaluationGate {
    if (rawRecord === null || rawRecord === undefined) return { ok: false, why: 'EVALUATION_MISSING' };
    const parsed = EvaluationRecordSchema.safeParse(rawRecord);
    if (!parsed.success) return { ok: false, why: 'EVALUATION_MISSING' };
    const record = parsed.data;
    if (record.model.provider !== model.provider || record.model.model !== model.model || record.model.revision !== model.revision) {
        return { ok: false, why: 'EVALUATION_MISSING' };
    }
    if (record.corpusDigest !== corpus.digest) return { ok: false, why: 'EVALUATION_MISSING' };
    let score: EvaluationScore;
    try {
        score = scoreEvaluation(corpus, record);
    } catch (e) {
        if (e instanceof EvaluationRefusal && (e.why === 'CASE_NOT_ANSWERED' || e.why === 'UNKNOWN_CASE')) return { ok: false, why: 'EVALUATION_MISSING' };
        throw e;
    }
    if (floor === null) return { ok: false, why: 'FLOOR_NOT_SET', score };
    const findsEnough = atLeast(score.foundRate, floor.minFoundRate);
    const inventsLittle = score.inventedRate.denominator === 0 || atLeast(floor.maxInventedRate, score.inventedRate);
    if (!findsEnough || !inventsLittle) return { ok: false, why: 'EVALUATION_BELOW_FLOOR', score };
    return { ok: true, recordDigest: evaluationRecordDigest(record), score };
}
