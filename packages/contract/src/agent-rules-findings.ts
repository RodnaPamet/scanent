/**
 * THE AGENT-RULES PLANNER — what a `scanent-agent-rules/1` report means.
 *
 * Pure and browser-safe: a body in, the findings and what was not concluded
 * out. The severities are not re-judged — the schema already held each to its
 * code's ceiling, and a person confirms every finding. The planner's job is
 * the order and the honesty rules:
 *
 *   • ZERO IS NEVER CLEAN ON ITS OWN. "No finding" is said only of a COMPLETE
 *     read of a population that held something. A population read in part, with
 *     no finding, is NOT CONCLUDED, with the reason; a complete read of nothing
 *     is NOTHING_READ, never clean.
 *   • A FINDING IS CLOSED ONLY BY ITS OWN SERVER. `serversReadInFull` names the
 *     servers a consumer may close a finding against: those the report read
 *     COMPLETE. A server absent from the report, or read in part, closes
 *     nothing.
 *   • A FINDING IS A SUGGESTION. Each carries the rule that fired and where,
 *     never the text, and a person confirms it.
 */
import { SUBJECT_KIND_TITLE, type AgentRuleFindingCode, type AgentRuleSeverity, type AgentRulesSubjectKind } from './agent-rules-contract-rules';
import type { AgentRulesReportBody, AgentRuleFinding, AgentRulesServer } from './agent-rules-contract';

export interface PlannedAgentRuleFinding {
    readonly code: AgentRuleFindingCode;
    /** Stable across scans of the same text: `agent-rule:<ruleId>@<locator>`. */
    readonly sourceRef: string;
    readonly severity: AgentRuleSeverity;
    readonly ruleId: string;
    readonly subjectKind: AgentRulesSubjectKind;
    readonly subjectKindTitle: string;
    readonly subjectRef: string;
    /** The MCP server the subject was read from. */
    readonly serverRef: string;
    readonly locator: string;
}

export type AgentRulesNotConcludedWhy = 'POPULATION_INCOMPLETE';

export interface AgentRulesNotConcluded {
    /** A subject kind. */
    readonly scope: AgentRulesSubjectKind;
    readonly why: AgentRulesNotConcludedWhy;
    /** The population's own incompleteness reason. */
    readonly reason: string;
}

/**
 * The answer about the surface as a whole: findings; no finding on a complete
 * read of at least one subject; a complete read of nothing; or not concluded.
 */
export type AgentRulesOutcome = 'FINDINGS' | 'NO_FINDING_ON_A_COMPLETE_READ' | 'NOTHING_READ' | 'NOT_CONCLUDED';

export interface AgentRulesPlan {
    readonly outcome: AgentRulesOutcome;
    readonly findings: readonly PlannedAgentRuleFinding[];
    readonly notConcluded: readonly AgentRulesNotConcluded[];
    /** Every server the report read, in its order. */
    readonly servers: readonly AgentRulesServer[];
    readonly subjects: number;
    readonly flagged: number;
}

/** A finding's stable reference: `agent-rule:<ruleId>@<locator>`. The same for the same rule on the same field, scan after scan. */
export function agentRuleFindingRef(f: Pick<AgentRuleFinding, 'ruleId' | 'locator'>): string {
    return `agent-rule:${f.ruleId}@${f.locator}`;
}

/** The servers a report read in full: the only ones a finding may be closed against. */
export function serversReadInFull(body: AgentRulesReportBody): ReadonlySet<string> {
    return new Set(body.servers.filter((s) => s.status === 'COMPLETE').map((s) => s.ref));
}

const SEVERITY_ORDER: readonly AgentRuleSeverity[] = ['HIGH', 'MEDIUM', 'LOW', 'INFO'];

function planned(f: AgentRuleFinding): PlannedAgentRuleFinding {
    return {
        code: f.code,
        sourceRef: agentRuleFindingRef(f),
        severity: f.severity,
        ruleId: f.ruleId,
        subjectKind: f.subjectKind,
        subjectKindTitle: SUBJECT_KIND_TITLE[f.subjectKind],
        subjectRef: f.subjectRef,
        serverRef: f.serverRef,
        locator: f.locator,
    };
}

/**
 * Plan a report. Findings come most severe first, then by rule id, then by
 * locator, so two plans of one report are equal.
 */
export function planAgentRulesScan(body: AgentRulesReportBody): AgentRulesPlan {
    const findings = body.findings.map(planned).sort((a, b) => {
        const bySeverity = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
        if (bySeverity !== 0) return bySeverity;
        if (a.ruleId !== b.ruleId) return a.ruleId < b.ruleId ? -1 : 1;
        return a.locator < b.locator ? -1 : a.locator > b.locator ? 1 : 0;
    });

    const notConcluded: AgentRulesNotConcluded[] = [];
    for (const p of body.population) {
        if (p.status === 'INCOMPLETE') notConcluded.push({ scope: p.kind, why: 'POPULATION_INCOMPLETE', reason: p.reason ?? 'INCOMPLETE' });
    }

    const outcome = agentRulesOutcome(findings.length, body.population);
    return { outcome, findings, notConcluded, servers: body.servers, subjects: body.counts.subjects, flagged: body.counts.flagged };
}

/**
 * The outcome in ONE expression, for the planner and every reader that
 * re-checks it: "no finding" only of a complete read that held something.
 */
export function agentRulesOutcome(findings: number, population: readonly { readonly status: 'COMPLETE' | 'INCOMPLETE'; readonly subjects: number }[]): AgentRulesOutcome {
    if (findings > 0) return 'FINDINGS';
    const complete = population.length > 0 && population.every((p) => p.status === 'COMPLETE');
    if (!complete) return 'NOT_CONCLUDED';
    return population.reduce((n, p) => n + p.subjects, 0) > 0 ? 'NO_FINDING_ON_A_COMPLETE_READ' : 'NOTHING_READ';
}
