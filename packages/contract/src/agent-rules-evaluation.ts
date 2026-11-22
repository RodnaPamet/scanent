/**
 * HOW THE RULE SET IS HELD HONEST.
 *
 * A fixed corpus ships with the rules: poisoned subjects, each with the rule
 * that MUST fire on it, and clean ones that must fire nothing. This module
 * scores the rules against the corpus and is a regression check, not a model
 * gate: the rules are deterministic, so there is no revision and no floor. The
 * numbers it computes — fired, missed, false on clean — are recomputed from the
 * corpus's own inputs every time, never stored.
 *
 * `scoreAgentRules` takes the SAME `runAgentRules` the scanner runs, so the
 * corpus scores exactly what a scan would raise.
 */
import { runAgentRules, type AgentRuleMatch } from './agent-rules';
import type { AgentRulesSubjectKind } from './agent-rules-contract-rules';

/** One planted expectation: a rule id that must fire on a case's input. */
export interface AgentRulesExpectation {
    readonly ruleId: string;
}

/** One case of the corpus: a subject's text, and what must (or must not) fire. */
export interface AgentRulesCase {
    readonly id: string;
    readonly kind: AgentRulesSubjectKind;
    readonly text: string;
    /** `vulnerable`: every `expected` rule must fire. `clean`: nothing fires. */
    readonly disposition: 'poisoned' | 'clean';
    readonly expected: readonly AgentRulesExpectation[];
}

export interface AgentRulesCorpus {
    readonly digest: string;
    readonly cases: readonly AgentRulesCase[];
}

export interface AgentRulesScore {
    readonly cases: number;
    readonly poisoned: number;
    readonly clean: number;
    /** Planted rules that fired as expected. */
    readonly fired: number;
    /** Planted rules that did not fire. */
    readonly missed: number;
    /** Rules that fired on a clean case, or an unexpected rule on a poisoned one. */
    readonly falseOnClean: number;
    /** Each planted (caseId, ruleId) that did not fire. */
    readonly missedRefs: readonly string[];
    /** Each (caseId, ruleId) that fired where nothing was planted for it. */
    readonly falseRefs: readonly string[];
}

export class AgentRulesEvaluationError extends Error {
    constructor(readonly why: 'EMPTY_CORPUS' | 'BAD_EXPECTATION') {
        super(`agent-rules evaluation refused: ${why}`);
        this.name = 'AgentRulesEvaluationError';
    }
}

/** The run shape: the rules in, the matches out. The scanner's own `runAgentRules`. */
export type AgentRuleRun = (text: string, kind: AgentRulesSubjectKind) => readonly AgentRuleMatch[];

/**
 * Score a rule run against the corpus. A poisoned case must fire each rule it
 * plants and no other; a clean case must fire nothing. Throws for an empty
 * corpus (nothing planted) or an expectation with no rule id.
 */
export function scoreAgentRules(corpus: AgentRulesCorpus, run: AgentRuleRun = runAgentRules): AgentRulesScore {
    const planted = corpus.cases.filter((c) => c.disposition === 'poisoned').flatMap((c) => c.expected);
    if (planted.length === 0) throw new AgentRulesEvaluationError('EMPTY_CORPUS');

    let fired = 0;
    let missed = 0;
    let falseOnClean = 0;
    const missedRefs: string[] = [];
    const falseRefs: string[] = [];

    for (const c of corpus.cases) {
        for (const e of c.expected) if (typeof e.ruleId !== 'string' || e.ruleId === '') throw new AgentRulesEvaluationError('BAD_EXPECTATION');
        const firedIds = new Set(run(c.text, c.kind).map((m) => m.ruleId));
        const expectedIds = new Set(c.expected.map((e) => e.ruleId));
        for (const want of expectedIds) {
            if (firedIds.has(want)) fired += 1;
            else {
                missed += 1;
                missedRefs.push(`${c.id}:${want}`);
            }
        }
        for (const got of firedIds) {
            if (!expectedIds.has(got)) {
                falseOnClean += 1;
                falseRefs.push(`${c.id}:${got}`);
            }
        }
    }

    return {
        cases: corpus.cases.length,
        poisoned: corpus.cases.filter((c) => c.disposition === 'poisoned').length,
        clean: corpus.cases.filter((c) => c.disposition === 'clean').length,
        fired,
        missed,
        falseOnClean,
        missedRefs: missedRefs.sort(),
        falseRefs: falseRefs.sort(),
    };
}

/** The corpus passes when every planted rule fired and nothing fired falsely. */
export function agentRulesRegressionPasses(score: AgentRulesScore): boolean {
    return score.missed === 0 && score.falseOnClean === 0;
}
