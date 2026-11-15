/**
 * THE VULNERABILITIES PLANNER — what a `scanent-vulnerabilities/1` report
 * means.
 *
 * Pure and browser-safe: a body in, the findings, what was not concluded and
 * the one-line answer about the code out. The model's verdicts are not
 * re-judged here: the schema has already held each to its severity cap, and a
 * person confirms every finding. The planner's job is the honesty rules:
 *
 *   • ZERO IS NEVER CLEAN ON ITS OWN. "No finding" is said only of a COMPLETE
 *     review of at least one repository. A run that did not run, or that did
 *     not finish, with no finding, is NOT CONCLUDED, with why.
 *   • WHAT WAS NOT REVIEWED IS SAID, PER PLACE. Every repository not reviewed
 *     in full, and every place left out, is listed with its reason.
 *   • A REJECTED CANDIDATE IS A COUNT. It is reported beside the findings, and
 *     so are the model answers that were discarded.
 *   • A FINDING IS A SUGGESTION. Each one says whether it is `confirmed` or
 *     `needs_validation`, and none changes any other scanner's result.
 */
import { ATTACK_CLASS_TITLE, type AttackClass, type NotReviewedReason, type VulnerabilitySeverity, type VulnerabilityVerdict } from './vulnerabilities-contract-rules';
import type { VulnerabilitiesReportBody, VulnerabilityFinding } from './vulnerabilities-contract';

export const VULNERABILITY_FINDING_CODES = ['VULNERABILITY_CONFIRMED', 'VULNERABILITY_NEEDS_VALIDATION'] as const;
export type VulnerabilityFindingCode = (typeof VULNERABILITY_FINDING_CODES)[number];

const CODE_BY_VERDICT: Readonly<Record<VulnerabilityVerdict, VulnerabilityFindingCode>> = Object.freeze({
    confirmed: 'VULNERABILITY_CONFIRMED',
    needs_validation: 'VULNERABILITY_NEEDS_VALIDATION',
});

export interface PlannedVulnerabilityFinding {
    readonly code: VulnerabilityFindingCode;
    /** Stable across scans of the same code: `vulnerability:<fingerprint>`. */
    readonly sourceRef: string;
    readonly severity: VulnerabilitySeverity;
    readonly verdict: VulnerabilityVerdict;
    readonly attackClass: AttackClass;
    readonly attackClassTitle: string;
    readonly title: string;
    readonly cwe: string;
    readonly owasp: string | null;
    readonly owaspApi: string | null;
    readonly attack: string | null;
    /** The first step and the last: where it enters, where it does harm. */
    readonly entry: string;
    readonly sink: string;
    readonly trace: readonly string[];
    readonly confidence: VulnerabilityFinding['confidence'];
    readonly condition: string;
    readonly remediation: string | null;
    readonly toValidate: string | null;
}

/** Why something was not concluded. */
export type VulnerabilityNotConcludedWhy =
    | 'MODEL_NOT_CONFIGURED'
    | 'EVALUATION_MISSING'
    | 'EVALUATION_BELOW_FLOOR'
    | 'FLOOR_NOT_SET'
    | 'NO_REPOSITORY'
    | 'TOKEN_BUDGET'
    | 'FILE_BUDGET'
    | 'TIME_BOX'
    | 'MODEL_FAILED'
    | 'MODEL_REFUSED'
    | 'REPOSITORY_NOT_REVIEWED'
    | 'REPOSITORY_PARTIAL'
    | NotReviewedReason;

export interface VulnerabilityNotConcluded {
    /** `run`, a repository label, or a place's locator. */
    readonly scope: string;
    readonly why: VulnerabilityNotConcludedWhy;
}

/** The sentence each reason is said with. */
export const VULNERABILITY_NOT_CONCLUDED_WHY: Readonly<Record<VulnerabilityNotConcludedWhy, string>> = Object.freeze({
    MODEL_NOT_CONFIGURED: 'No model is configured, so the code was not reviewed. The scanner is off by default.',
    EVALUATION_MISSING: 'The configured model revision has no evaluation record, so it did not run.',
    EVALUATION_BELOW_FLOOR: "The configured model revision's evaluation record is below the published floor, so it did not run.",
    FLOOR_NOT_SET: 'No evaluation floor is published yet, so no model revision runs.',
    NO_REPOSITORY: 'No repository was configured for review.',
    TOKEN_BUDGET: 'The token budget ran out before the review finished.',
    FILE_BUDGET: 'The file budget ran out before the review finished.',
    TIME_BOX: 'The time box ran out before the review finished.',
    MODEL_FAILED: 'The model failed to answer.',
    MODEL_REFUSED: 'The model refused to answer.',
    REPOSITORY_NOT_REVIEWED: 'This repository was not reviewed.',
    REPOSITORY_PARTIAL: 'This repository was reviewed in part.',
    SECRET_IN_EXCERPT: 'The excerpt failed the secret checks and was not sent.',
    BYTE_CAP: 'The file is larger than the byte cap.',
    UNPARSEABLE: 'The file could not be parsed.',
});

/** The answer about the code as a whole, in one value. */
export type VulnerabilityOutcome = 'FINDINGS' | 'NO_FINDING_ON_A_COMPLETE_REVIEW' | 'NOT_CONCLUDED';

export interface VulnerabilitiesPlan {
    readonly outcome: VulnerabilityOutcome;
    readonly findings: readonly PlannedVulnerabilityFinding[];
    readonly notConcluded: readonly VulnerabilityNotConcluded[];
    readonly rejected: number;
    readonly discarded: number;
    readonly reviewedRepositories: number;
    readonly repositories: number;
}

const SEVERITY_ORDER: readonly VulnerabilitySeverity[] = ['HIGH', 'MEDIUM', 'LOW', 'INFO'];

function plannedFinding(f: VulnerabilityFinding): PlannedVulnerabilityFinding {
    const trace = f.trace.map((s) => s.locator);
    return {
        code: CODE_BY_VERDICT[f.verdict],
        sourceRef: `vulnerability:${f.id}`,
        severity: f.severity,
        verdict: f.verdict,
        attackClass: f.attackClass,
        attackClassTitle: ATTACK_CLASS_TITLE[f.attackClass],
        title: f.title,
        cwe: f.cwe,
        owasp: f.owasp,
        owaspApi: f.owaspApi,
        attack: f.attack,
        entry: trace[0],
        sink: trace[trace.length - 1],
        trace,
        confidence: f.confidence,
        condition: f.condition,
        remediation: f.remediation,
        toValidate: f.toValidate,
    };
}

/**
 * Plan a report. Findings come most severe first, `confirmed` before
 * `needs_validation` at one severity, then by fingerprint, so two plans of one
 * report are equal.
 */
export function planVulnerabilitiesScan(body: VulnerabilitiesReportBody): VulnerabilitiesPlan {
    const findings = body.findings.map(plannedFinding).sort((a, b) => {
        const bySeverity = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
        if (bySeverity !== 0) return bySeverity;
        if (a.verdict !== b.verdict) return a.verdict === 'confirmed' ? -1 : 1;
        return a.sourceRef < b.sourceRef ? -1 : a.sourceRef > b.sourceRef ? 1 : 0;
    });

    const notConcluded: VulnerabilityNotConcluded[] = [];
    if (body.run.reason !== undefined) notConcluded.push({ scope: 'run', why: body.run.reason });
    for (const repo of body.repositories) {
        if (repo.status === 'NOT_REVIEWED' && body.run.status !== 'NOT_RUN') notConcluded.push({ scope: repo.label, why: 'REPOSITORY_NOT_REVIEWED' });
        if (repo.status === 'PARTIAL') notConcluded.push({ scope: repo.label, why: 'REPOSITORY_PARTIAL' });
    }
    for (const n of body.notReviewed) notConcluded.push({ scope: n.locator, why: n.reason });

    const reviewedRepositories = body.repositories.filter((r) => r.status === 'REVIEWED').length;
    const complete = body.run.status === 'COMPLETE' && body.repositories.length > 0 && reviewedRepositories === body.repositories.length;
    const outcome: VulnerabilityOutcome = findings.length > 0 ? 'FINDINGS' : complete ? 'NO_FINDING_ON_A_COMPLETE_REVIEW' : 'NOT_CONCLUDED';

    return {
        outcome,
        findings,
        notConcluded,
        rejected: body.counts.rejected,
        discarded: body.counts.discarded,
        reviewedRepositories,
        repositories: body.repositories.length,
    };
}
