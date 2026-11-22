/**
 * THE AGENT-RULES PLANNER — what a `scanent-agent-rules/1` report means.
 *
 * Pure and browser-safe: a body in, the findings and what was not concluded
 * out. The severities are not re-judged — the schema already held each to its
 * code's ceiling, and a person confirms every finding. The planner's job is
 * the order and the honesty rules:
 *
 *   • ZERO IS NEVER CLEAN ON ITS OWN. "No finding" is said only of a COMPLETE
 *     read of a population. A population read in part, with no finding, is NOT
 *     CONCLUDED, with the reason.
 *   • A FINDING IS A SUGGESTION. Each carries the rule that fired and where,
 *     never the text, and a person confirms it.
 */
import { SUBJECT_KIND_TITLE, type AgentRuleFindingCode, type AgentRuleSeverity, type AgentRulesSubjectKind } from './agent-rules-contract-rules';
import type { AgentRulesReportBody, AgentRuleFinding } from './agent-rules-contract';

export interface PlannedAgentRuleFinding {
    readonly code: AgentRuleFindingCode;
    /** Stable across scans of the same text: `agent-rule:<ruleId>@<locator>`. */
    readonly sourceRef: string;
    readonly severity: AgentRuleSeverity;
    readonly ruleId: string;
    readonly subjectKind: AgentRulesSubjectKind;
    readonly subjectKindTitle: string;
    readonly subjectRef: string;
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

export type AgentRulesOutcome = 'FINDINGS' | 'NO_FINDING_ON_A_COMPLETE_READ' | 'NOT_CONCLUDED';

export interface AgentRulesPlan {
    readonly outcome: AgentRulesOutcome;
    readonly findings: readonly PlannedAgentRuleFinding[];
    readonly notConcluded: readonly AgentRulesNotConcluded[];
    readonly subjects: number;
    readonly flagged: number;
}

const SEVERITY_ORDER: readonly AgentRuleSeverity[] = ['HIGH', 'MEDIUM', 'LOW', 'INFO'];

function planned(f: AgentRuleFinding): PlannedAgentRuleFinding {
    return {
        code: f.code,
        sourceRef: `agent-rule:${f.ruleId}@${f.locator}`,
        severity: f.severity,
        ruleId: f.ruleId,
        subjectKind: f.subjectKind,
        subjectKindTitle: SUBJECT_KIND_TITLE[f.subjectKind],
        subjectRef: f.subjectRef,
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

    const everyPopulationComplete = body.population.every((p) => p.status === 'COMPLETE');
    const outcome: AgentRulesOutcome = findings.length > 0 ? 'FINDINGS' : everyPopulationComplete ? 'NO_FINDING_ON_A_COMPLETE_READ' : 'NOT_CONCLUDED';

    return { outcome, findings, notConcluded, subjects: body.counts.subjects, flagged: body.counts.flagged };
}
