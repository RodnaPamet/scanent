/**
 * THE AGENT-SURFACE RULES' SECTION OF `results.json`.
 *
 * The signed `scanent-agent-rules/1` report, planned by the contract's own
 * planner (`planAgentRulesScan`) and laid out for the local results. It adds
 * nothing the report does not say: every finding is the report's, in the
 * planner's order, and "no finding" is said only of a complete read.
 */
import type { AgentRulesReportBody } from '@rodnapamet/scanent-contract/agent-rules-contract';
import { planAgentRulesScan } from '@rodnapamet/scanent-contract/agent-rules-findings';

import type { LocalAgentRulesResults } from './types';

export interface AgentRulesScoreInput {
    readonly body: AgentRulesReportBody;
    /** The signed report's file name in the run and the SHA-256 of its bytes. */
    readonly report: { readonly file: string; readonly sha256: string };
}

/** Score one agent-rules report for the local results. Pure. */
export function scoreAgentRulesLocally(input: AgentRulesScoreInput): LocalAgentRulesResults {
    const plan = planAgentRulesScan(input.body);
    return {
        report: input.report,
        outcome: plan.outcome,
        population: input.body.population.map((p) => ({ kind: p.kind, status: p.status, reason: p.reason ?? null, subjects: p.subjects })),
        counts: { subjects: input.body.counts.subjects, flagged: input.body.counts.flagged, findings: plan.findings.length },
        findings: plan.findings.map((f) => ({
            code: f.code,
            ruleId: f.ruleId,
            severity: f.severity,
            subjectKind: f.subjectKind,
            subjectRef: f.subjectRef,
            locator: f.locator,
            sourceRef: f.sourceRef,
        })),
        notConcluded: plan.notConcluded.map((n) => ({ scope: n.scope, why: n.why, reason: n.reason })),
    };
}
