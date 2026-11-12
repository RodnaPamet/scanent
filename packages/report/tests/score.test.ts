/**
 * Local scoring: one scan, judged with no tenant.
 *
 *   1. It decides nothing the contract decides: levels, cells, bars and
 *      findings are the contract's own.
 *   2. An agent whose sources were not read in full is NOT JUDGED, and nothing
 *      states a level for it.
 *   3. Removing a verdict never raises a level (why rule 2 is enough).
 *   4. An empty scan is a finding, never a clean result; zero sources is not complete.
 *   5. An unbound credential is an orphan only where the planner opens one.
 *   6. The inventory: exact match, declared and labelled, never above H1,
 *      never over an observation.
 *   7. Coverage says what this run could not have evidenced.
 *   8. The result is deterministic, carries nothing secret-shaped, and passes its own schema.
 */
import { canonicalJson } from '@rodnapamet/scanent-contract/canonical-json';
import { LADDER_VERSION, type HarnessReportBody } from '@rodnapamet/scanent-contract/harness-contract';
import { firstSecretShapedMember, planHarnessScan, toolEvidenceSourcesOf, type PriorHarnessState } from '@rodnapamet/scanent-contract/harness-findings';
import {
    ALL_HARNESS_CRITERIA,
    collapseVerdicts,
    criterionState,
    HARNESS_CRITERIA,
    HARNESS_LEVELS,
    rungOf,
    scoreHarness,
} from '@rodnapamet/scanent-contract/harness-ladder';

import {
    GCP_SA_ID,
    UNBOUND_VAULT_REF,
    validV2CompleteReportBody,
    validV2ReportBody,
    validV3ReportBody,
    validV3ReportBodyWithSandbox,
    validV3ReportBodyWithSdkAgent,
} from '../../contract/tests/helpers/agent-harness-fake-scanner';
import { CROSS_AGENT_VERDICT_SOURCE, judgementBasisOf } from '../src/results/judgement';
import { renderSummaryHtml } from '../src/render/html';
import { LocalResultsSchema } from '../src/results/schema';
import { coverageOf, scoreReportLocally } from '../src/results/score';
import { RESULTS_SCHEMA, type LocalAgentResult, type LocalResults } from '../src/results/types';
import { ALPHA, AS_OF, BRAVO, fullRow, input, INVENTORY_SHA, inventoryOf, META, standaloneBody, TEST_READERS, withSource } from './helpers/fixtures';

const REGISTERED = 'entra:sp:registered-1';
const SHADOW = 'entra:sp:shadow-1';

const agentOf = (results: LocalResults, id: string): LocalAgentResult => {
    const agent = results.agents.find((a) => a.discoveredId === id);
    if (agent === undefined) throw new Error(`no agent ${id}`);
    return agent;
};
const cellOf = (agent: LocalAgentResult, criterion: string) => agent.criteria.find((c) => c.criterion === criterion)!;
const codesFor = (results: LocalResults, id: string) => results.findings.filter((f) => f.discoveredId === id).map((f) => f.code).sort();

/** The prior state a standalone run has: nothing stored, and the report's own register claims. */
function standalonePrior(body: HarnessReportBody): PriorHarnessState {
    return {
        previousLevels: new Map(),
        acceptedShortfalls: new Set(),
        openOrphanCredentials: new Set(),
        intakeClaims: new Map(),
        registeredAgentIds: new Set(body.agents.flatMap((a) => (a.registeredAgentId === null ? [] : [a.registeredAgentId]))),
    };
}

describe('1. the contract decides', () => {
    const bodies: [string, () => HarnessReportBody][] = [
        ['a /3 estate', validV3ReportBody],
        ['a /3 estate with a sandbox', validV3ReportBodyWithSandbox],
        ['a /3 estate with an SDK agent', validV3ReportBodyWithSdkAgent],
        ['a /2 estate, every source read', validV2CompleteReportBody],
        ['an estate with no register', standaloneBody],
    ];

    it.each(bodies)('%s: level, reach and blocking criteria are the planner\'s', (_label, make) => {
        const body = make();
        const results = scoreReportLocally(input(body));
        const plan = planHarnessScan(body, standalonePrior(body));
        expect(results.agents).toHaveLength(plan.agents.length);
        for (const planned of plan.agents) {
            const agent = agentOf(results, planned.discoveredId);
            expect(agent.judgement).toMatchObject({ state: 'JUDGED', level: planned.level, blockingNextRung: planned.blockingNextRung });
            expect(agent.reach).toBe(planned.reach);
        }
    });

    it.each(bodies)('%s: each cell is the ladder\'s state of the collapsed verdict', (_label, make) => {
        const body = make();
        const results = scoreReportLocally(input(body));
        for (const reported of body.agents) {
            const collapsed = collapseVerdicts(reported.verdicts);
            const agent = agentOf(results, reported.discoveredId);
            expect(agent.criteria.map((c) => c.criterion)).toEqual(ALL_HARNESS_CRITERIA);
            for (const cell of agent.criteria) {
                const verdict = collapsed.get(cell.criterion);
                expect(cell.state).toBe(criterionState(verdict));
                expect(cell.evidence).toBe(verdict?.evidence ?? null);
                expect(cell.basis).toBe(verdict === undefined ? null : 'OBSERVED');
            }
        }
    });

    it.each(bodies)('%s: the findings are the planner\'s, in its order', (_label, make) => {
        const body = make();
        const results = scoreReportLocally(input(body));
        const plan = planHarnessScan(body, standalonePrior(body));
        expect(results.findings.map((f) => f.sourceRef)).toEqual(plan.assert.map((f) => f.sourceRef));
        expect(results.findings.map((f) => [f.code, f.severity, f.type, f.title])).toEqual(
            plan.assert.map((f) => [f.code, f.severity, f.type, f.title]),
        );
    });

    it('states the estate a register reads as the planner words it', () => {
        const body = validV3ReportBody();
        const results = scoreReportLocally(input(body));
        const plan = planHarnessScan(body, standalonePrior(body));
        expect(results.findings.map((f) => f.description)).toEqual(plan.assert.map((f) => f.description));
    });

    it('derives the bar and the shortfall from the level and the reach', () => {
        const results = scoreReportLocally(input(validV3ReportBody()));
        // Registered, read-only, at H2: at its bar.
        expect(agentOf(results, REGISTERED).judgement).toEqual({
            state: 'JUDGED',
            level: 'H2',
            observedLevel: 'H2',
            bar: 'H2',
            shortfall: false,
            blockingNextRung: HARNESS_CRITERIA.H3,
            caveats: [],
        });
        // An unpinned write tool and no verdict: H0 against the higher bar.
        expect(agentOf(results, SHADOW).judgement).toMatchObject({ level: 'H0', bar: 'H3', shortfall: true });
        expect(agentOf(results, SHADOW).reach).toBe('WRITE_OR_EXTERNAL');
        // No tools, and the MCP source read in full: read-only, the lower bar.
        expect(agentOf(results, GCP_SA_ID).judgement).toMatchObject({ level: 'H0', bar: 'H2', shortfall: true });
        expect(agentOf(results, GCP_SA_ID).reach).toBe('READ_ONLY');
    });

    it('takes the register link a report carries, and names the agents without one as shadow agents', () => {
        const results = scoreReportLocally(input(validV3ReportBody()));
        expect(agentOf(results, REGISTERED).registration).toEqual({ basis: 'OBSERVED_REGISTER', ref: 'agt_registered_1' });
        expect(agentOf(results, SHADOW).registration).toEqual({ basis: 'NONE', ref: null });
        expect(results.estate.shadowAgents).toEqual([SHADOW, GCP_SA_ID].sort());
        expect(results.estate.registrationBasis).toBe('INFLECT_REGISTER');
        expect(results.estate.registrationConflicts).toEqual([]);
    });

    it('says which agent each finding is about, and none for a finding about the scan', () => {
        const results = scoreReportLocally(input(withSource(validV2CompleteReportBody(), 'mcp', 'BYTE_CAP')));
        expect(codesFor(results, SHADOW)).toEqual(['HARNESS_SHORTFALL', 'SHADOW_AGENT', 'UNPINNED_WRITE_TOOL']);
        const incomplete = results.findings.find((f) => f.code === 'INCOMPLETE_SOURCE');
        expect(incomplete).toMatchObject({ discoveredId: null, sourceRef: 'INCOMPLETE_SOURCE:agt_scanner:mcp' });
    });

    it('never raises a finding about a fall in level: there is no earlier run to fall from', () => {
        for (const [, make] of bodies) {
            expect(scoreReportLocally(input(make())).findings.some((f) => f.code === 'LEVEL_DROP')).toBe(false);
        }
    });

    it('carries the scan, the report and the ladder it was scored on', () => {
        const body = validV3ReportBody();
        const results = scoreReportLocally(input(body));
        expect(results.schema).toBe(RESULTS_SCHEMA);
        expect(results.ladder).toEqual({ version: LADDER_VERSION, levels: HARNESS_LEVELS, criteria: HARNESS_CRITERIA });
        expect(results.scan).toEqual({
            id: body.scan.id,
            asOf: body.scan.asOf,
            estate: 'acme',
            contract: 'inflect-agent-harness/3',
            scanner: body.scan.scanner,
            complete: true,
            registerClaimsVerified: true,
        });
        expect(results.report).toEqual(META.report);
        expect(results.inventory).toBeNull();
    });

    it('passes on what the caller says of a report it did not build', () => {
        const meta = { estate: null, registerClaimsVerified: false, report: { ...META.report, signerPinned: false } };
        const results = scoreReportLocally(input(validV3ReportBody(), { meta }));
        expect(results.scan.estate).toBeNull();
        expect(results.scan.registerClaimsVerified).toBe(false);
        expect(results.report.signerPinned).toBe(false);
        // The claim is still trusted, and labelled as the register's.
        expect(agentOf(results, REGISTERED).registration.basis).toBe('OBSERVED_REGISTER');
    });

    it('lists each source with its status, its rows and the agents found through it', () => {
        const results = scoreReportLocally(input(withSource(validV3ReportBody(), 'vault', 'RATE_LIMITED')));
        expect(results.sources).toEqual([
            { kind: 'entra-sp', status: 'COMPLETE', reason: null, rows: 412, agents: 2 },
            { kind: 'vault', status: 'INCOMPLETE', reason: 'RATE_LIMITED', rows: 37, agents: 2 },
            { kind: 'mcp', status: 'COMPLETE', reason: null, rows: 3, agents: 0 },
            { kind: 'inflect-register', status: 'COMPLETE', reason: null, rows: 1, agents: 1 },
            { kind: 'gcp-sa', status: 'COMPLETE', reason: null, rows: 3, agents: 1 },
        ]);
        expect(results.scan.complete).toBe(false);
    });

    it('lists agents by id, whatever order the report had them in', () => {
        const results = scoreReportLocally(input(standaloneBody()));
        expect(standaloneBody().agents.map((a) => a.discoveredId)).toEqual([BRAVO, ALPHA]);
        expect(results.agents.map((a) => a.discoveredId)).toEqual([ALPHA, BRAVO]);
    });

    it('counts credentials and tools, and keeps "no models reported" apart from "none"', () => {
        const results = scoreReportLocally(input(validV2CompleteReportBody()));
        expect(agentOf(results, REGISTERED).counts).toEqual({ credentials: 1, tools: 1, writeCapableTools: 0, unpinnedWriteTools: 0, models: 2 });
        expect(agentOf(results, SHADOW).counts).toEqual({ credentials: 1, tools: 1, writeCapableTools: 1, unpinnedWriteTools: 1, models: null });
        const none = validV2CompleteReportBody();
        none.agents[0] = { ...none.agents[0], models: [] };
        expect(agentOf(scoreReportLocally(input(none)), REGISTERED).counts.models).toBe(0);
    });

    it('keeps the owner a source observed, and no owner where none was', () => {
        const results = scoreReportLocally(input(standaloneBody()));
        expect(agentOf(results, ALPHA).observedOwner).toEqual({ kind: 'user', ref: 'usr_alpha_owner' });
        expect(agentOf(results, BRAVO).observedOwner).toBeNull();
        expect(agentOf(results, ALPHA).declared).toBeNull();
    });
});

describe('2. an agent that cannot be judged', () => {
    it('has no level, bar or shortfall when a source it was found through stopped early', () => {
        const results = scoreReportLocally(input(withSource(validV3ReportBody(), 'gcp-sa', 'AUTH_FAILED')));
        const agent = agentOf(results, GCP_SA_ID);
        expect(agent.judgement).toEqual({ state: 'NOT_JUDGED', reasons: ['SOURCE_INCOMPLETE:gcp-sa:AUTH_FAILED'] });
        for (const key of ['level', 'observedLevel', 'bar', 'shortfall', 'blockingNextRung', 'caveats']) {
            expect(Object.hasOwn(agent.judgement, key)).toBe(false);
        }
        expect(JSON.stringify(agent)).not.toMatch(/"(level|observedLevel|bar|shortfall)"/);
    });

    it('raises no shortfall for it, and keeps what was positively observed', () => {
        const judged = scoreReportLocally(input(validV3ReportBody()));
        expect(codesFor(judged, SHADOW)).toEqual(['HARNESS_SHORTFALL', 'SHADOW_AGENT', 'UNPINNED_WRITE_TOOL']);

        const results = scoreReportLocally(input(withSource(validV3ReportBody(), 'entra-sp', 'PAGINATION_TORN')));
        expect(agentOf(results, SHADOW).judgement.state).toBe('NOT_JUDGED');
        expect(codesFor(results, SHADOW)).toEqual(['SHADOW_AGENT', 'UNPINNED_WRITE_TOOL']);
        // No finding anywhere states a level for it.
        for (const f of results.findings.filter((x) => x.discoveredId === SHADOW)) {
            expect(`${f.title} ${f.description}`).not.toMatch(/\bH[0-5]\b/);
        }
        // Its cells are still what a source reported, and its reach what the planner derived.
        expect(cellOf(agentOf(results, REGISTERED), 'H1.registered').state).toBe('EVIDENCED');
        expect(agentOf(results, SHADOW).reach).toBe('WRITE_OR_EXTERNAL');
    });

    it('names every source that stopped early, in the order the agent lists them', () => {
        const body = withSource(withSource(validV3ReportBody(), 'entra-sp', 'TIME_BOX'), 'vault', 'UNREACHABLE');
        const results = scoreReportLocally(input(body));
        expect(agentOf(results, SHADOW).judgement).toEqual({
            state: 'NOT_JUDGED',
            reasons: ['SOURCE_INCOMPLETE:entra-sp:TIME_BOX', 'SOURCE_INCOMPLETE:vault:UNREACHABLE'],
        });
    });

    it('is every agent when the register, which reports on other sources\' agents, stopped early', () => {
        const results = scoreReportLocally(input(withSource(validV3ReportBody(), 'inflect-register', 'AUTH_FAILED')));
        expect(agentOf(results, REGISTERED).judgement).toEqual({ state: 'NOT_JUDGED', reasons: ['SOURCE_INCOMPLETE:inflect-register:AUTH_FAILED'] });
        expect(agentOf(results, SHADOW).judgement).toEqual({ state: 'NOT_JUDGED', reasons: ['VERDICT_SOURCE_INCOMPLETE:inflect-register:AUTH_FAILED'] });
        expect(agentOf(results, GCP_SA_ID).judgement).toEqual({ state: 'NOT_JUDGED', reasons: ['VERDICT_SOURCE_INCOMPLETE:inflect-register:AUTH_FAILED'] });
        expect(results.estate).toMatchObject({ agentCount: 3, judgedCount: 0, notJudgedCount: 3, shortfallCount: 0 });
        expect(results.estate.byLevel).toEqual({ H0: 0, H1: 0, H2: 0, H3: 0, H4: 0, H5: 0 });
        expect(results.findings.some((f) => f.code === 'HARNESS_SHORTFALL')).toBe(false);
    });

    it('stays judged, with a caveat, when the source that stopped early does not bear on it', () => {
        const results = scoreReportLocally(input(withSource(validV3ReportBody(), 'gcp-sa', 'RATE_LIMITED')));
        expect(agentOf(results, REGISTERED).judgement).toMatchObject({ state: 'JUDGED', level: 'H2', caveats: ['OTHER_SOURCE_INCOMPLETE:gcp-sa'] });
        expect(agentOf(results, SHADOW).judgement).toMatchObject({ state: 'JUDGED', level: 'H0', caveats: ['OTHER_SOURCE_INCOMPLETE:gcp-sa'] });
        expect(results.estate).toMatchObject({ judgedCount: 2, notJudgedCount: 1, shortfallCount: 1 });
        expect(results.estate.byLevel).toEqual({ H0: 1, H1: 0, H2: 1, H3: 0, H4: 0, H5: 0 });
    });

    it('holds an incomplete MCP read as a caveat and an unknown reach, never a read-only one', () => {
        const results = scoreReportLocally(input(withSource(validV3ReportBody(), 'mcp', 'BYTE_CAP')));
        const agent = agentOf(results, GCP_SA_ID);
        expect(agent.reach).toBe('UNKNOWN');
        expect(agent.judgement).toMatchObject({ state: 'JUDGED', bar: 'H3', caveats: ['OTHER_SOURCE_INCOMPLETE:mcp'] });
    });

    it('does not judge an agent found through a source the report does not list', () => {
        const body = validV3ReportBody();
        body.population.sources = body.population.sources.filter((s) => s.kind !== 'gcp-sa');
        expect(agentOf(scoreReportLocally(input(body)), GCP_SA_ID).judgement).toEqual({
            state: 'NOT_JUDGED',
            reasons: ['SOURCE_INCOMPLETE:gcp-sa:NOT_LISTED'],
        });
    });

    it('classifies every source kind, and only the register as reporting on other sources\' agents', () => {
        expect(Object.entries(CROSS_AGENT_VERDICT_SOURCE).filter(([, cross]) => cross).map(([kind]) => kind)).toEqual(['inflect-register']);
        expect(Object.keys(CROSS_AGENT_VERDICT_SOURCE)).toHaveLength(9);
    });

    it('judges on listed sources alone: a kind it does not know is a caveat, and a source with no reason still counts', () => {
        expect(judgementBasisOf(['entra-sp'], [{ kind: 'entra-sp', status: 'COMPLETE' }, { kind: 'future-kind', status: 'INCOMPLETE', reason: 'TIME_BOX' }])).toEqual({
            judged: true,
            caveats: ['OTHER_SOURCE_INCOMPLETE:future-kind'],
        });
        expect(judgementBasisOf(['entra-sp'], [{ kind: 'entra-sp', status: 'INCOMPLETE' }, { kind: 'inflect-register', status: 'INCOMPLETE' }])).toEqual({
            judged: false,
            reasons: ['SOURCE_INCOMPLETE:entra-sp:UNKNOWN', 'VERDICT_SOURCE_INCOMPLETE:inflect-register:UNKNOWN'],
        });
        expect(judgementBasisOf(['entra-sp'], [])).toEqual({ judged: false, reasons: ['SOURCE_INCOMPLETE:entra-sp:NOT_LISTED'] });
    });
});

describe('3. removing a verdict never raises a level', () => {
    /** A small deterministic generator: the test must not depend on a seed nobody can read. */
    function* subsets(n: number, count: number): Generator<boolean[]> {
        let state = 0x2f6e2b1;
        for (let k = 0; k < count; k++) {
            const keep: boolean[] = [];
            for (let i = 0; i < n; i++) {
                state = (Math.imul(state, 1103515245) + 12345) >>> 0;
                keep.push((state >>> 16) % 3 !== 0);
            }
            yield keep;
        }
    }

    const everyCriterionMet = ALL_HARNESS_CRITERIA.map((criterion) => ({ criterion, met: true, evidence: 'seen' }));
    // A report holds one verdict per criterion (the scanner's builder collapses
    // them), and an answer a partial read missed is a criterion left
    // unanswered. So what is removed is a criterion's answer, whole.
    const verdictSets = [
        everyCriterionMet,
        [...everyCriterionMet, { criterion: 'H3.manifests_pinned' as const, met: false, evidence: 'seen' }],
        everyCriterionMet.map((v, i) => (i % 4 === 3 ? { ...v, met: false } : v)),
        everyCriterionMet.map((v, i) => (i % 5 === 2 ? { ...v, evidence: null } : v)),
        ...[validV3ReportBody, validV3ReportBodyWithSandbox, validV3ReportBodyWithSdkAgent].flatMap((make) => make().agents.map((a) => a.verdicts)),
    ];

    it('holds for every criterion left unanswered, alone and in a few hundred combinations', () => {
        let compared = 0;
        for (const verdicts of verdictSets) {
            const full = rungOf(scoreHarness(verdicts).level);
            const answered = [...new Set(verdicts.map((v) => v.criterion))];
            for (const dropped of answered) {
                expect(rungOf(scoreHarness(verdicts.filter((v) => v.criterion !== dropped)).level)).toBeLessThanOrEqual(full);
                compared += 1;
            }
            for (const keep of subsets(answered.length, 40)) {
                const kept = new Set(answered.filter((_, j) => keep[j]));
                expect(rungOf(scoreHarness(verdicts.filter((v) => kept.has(v.criterion))).level)).toBeLessThanOrEqual(full);
                compared += 1;
            }
        }
        expect(compared).toBeGreaterThan(300);
        // And the set that could reach the top does: the property is not vacuous.
        expect(scoreHarness(everyCriterionMet).level).toBe('H5');
    });

    it('but a verdict a partial read missed can leave a level too high, which is why the agent is not judged', () => {
        const met = scoreHarness(HARNESS_CRITERIA.H1.map((criterion) => ({ criterion, met: true, evidence: 'seen' })));
        const withTheMissedNo = scoreHarness([
            ...HARNESS_CRITERIA.H1.map((criterion) => ({ criterion, met: true, evidence: 'seen' })),
            { criterion: 'H1.owner' as const, met: false, evidence: 'another source' },
        ]);
        expect(met.level).toBe('H1');
        expect(withTheMissedNo.level).toBe('H0');
    });
});

describe('4. zero is never complete', () => {
    const empty = (): HarnessReportBody => ({ ...standaloneBody(), agents: [] });

    it('an empty scan is a finding, with no agent and no level anywhere', () => {
        const results = scoreReportLocally(input(empty()));
        expect(results.estate.empty).toBe(true);
        expect(results.estate).toMatchObject({ agentCount: 0, judgedCount: 0, notJudgedCount: 0, shortfallCount: 0, shadowAgents: [] });
        expect(results.estate.byLevel).toEqual({ H0: 0, H1: 0, H2: 0, H3: 0, H4: 0, H5: 0 });
        expect(results.agents).toEqual([]);
        expect(results.findings.map((f) => f.code)).toEqual(['EMPTY_SCAN']);
        expect(results.findings[0]).toMatchObject({ severity: 'HIGH', discoveredId: null, sourceRef: 'EMPTY_SCAN:agt_scanner' });
        // The sources were read in full, and that is not a clean result either.
        expect(results.scan.complete).toBe(true);
        expect(JSON.stringify(results)).not.toMatch(/"(level|observedLevel|bar)":/);
    });

    it('an empty scan of an incomplete estate says both', () => {
        const results = scoreReportLocally(input(withSource(empty(), 'entra-sp', 'AUTH_FAILED')));
        expect(results.findings.map((f) => f.code).sort()).toEqual(['EMPTY_SCAN', 'INCOMPLETE_SOURCE']);
        expect(results.scan.complete).toBe(false);
    });

    it('a scan that looked nowhere is not complete', () => {
        const nowhere = { ...empty(), population: { sources: [] } } as unknown as HarnessReportBody;
        const results = scoreReportLocally(input(nowhere, { configuredSources: [] }));
        expect(results.scan.complete).toBe(false);
        expect(results.sources).toEqual([]);
        expect(results.estate.empty).toBe(true);
    });

    it('an agent with no verdict at all is at H0 below its bar, not unscored and not clean', () => {
        const results = scoreReportLocally(input(standaloneBody()));
        expect(agentOf(results, BRAVO).judgement).toMatchObject({ state: 'JUDGED', level: 'H0', shortfall: true, blockingNextRung: HARNESS_CRITERIA.H1 });
        expect(agentOf(results, BRAVO).criteria.every((c) => c.state === 'UNANSWERED' && c.basis === null && c.evidence === null)).toBe(true);
    });
});

describe('5. credentials seen bound to no agent', () => {
    it('are orphans where the planner opens the finding', () => {
        const results = scoreReportLocally(input(validV2CompleteReportBody()));
        expect(results.estate.orphanCredentials).toEqual([{ ref: UNBOUND_VAULT_REF, sourceKind: 'vault' }]);
        expect(results.estate.unboundNotConcluded).toEqual([]);
        expect(results.findings.filter((f) => f.code === 'ORPHAN_CREDENTIAL')).toHaveLength(1);
    });

    it('are not concluded while a source that could name the agent stopped early', () => {
        const results = scoreReportLocally(input(validV2ReportBody()));
        expect(results.estate.orphanCredentials).toEqual([]);
        expect(results.estate.unboundNotConcluded).toEqual([{ ref: UNBOUND_VAULT_REF, sourceKind: 'vault', why: 'IDENTITY_SOURCE_INCOMPLETE' }]);
        expect(results.findings.some((f) => f.code === 'ORPHAN_CREDENTIAL')).toBe(false);
    });

    it('are not concluded while the source that saw them stopped early', () => {
        const results = scoreReportLocally(input(withSource(validV2CompleteReportBody(), 'vault', 'TIME_BOX')));
        expect(results.estate.orphanCredentials).toEqual([]);
        expect(results.estate.unboundNotConcluded).toEqual([{ ref: UNBOUND_VAULT_REF, sourceKind: 'vault', why: 'OWN_SOURCE_INCOMPLETE' }]);
    });

    it('are still orphans when the only source that stopped early cannot name an agent', () => {
        const results = scoreReportLocally(input(withSource(validV2CompleteReportBody(), 'mcp', 'BYTE_CAP')));
        expect(results.estate.orphanCredentials).toEqual([{ ref: UNBOUND_VAULT_REF, sourceKind: 'vault' }]);
    });
});

describe('6. the inventory', () => {
    const scored = (rows: readonly unknown[], body: HarnessReportBody = standaloneBody()) =>
        scoreReportLocally(input(body, { inventory: inventoryOf(rows) }));

    it('with none, every agent is a shadow agent and the finding says why', () => {
        const results = scoreReportLocally(input(standaloneBody()));
        expect(results.inventory).toBeNull();
        expect(results.estate.registrationBasis).toBe('NONE');
        expect(results.estate.shadowAgents).toEqual([ALPHA, BRAVO]);
        const shadow = results.findings.find((f) => f.sourceRef === `SHADOW_AGENT:${ALPHA}`)!;
        expect(shadow.description).toContain('no inventory was supplied, so no agent can be shown as registered');
        expect(shadow.description).not.toContain('agent register');
        expect(shadow).toMatchObject({ code: 'SHADOW_AGENT', severity: 'HIGH', type: 'NONCONFORMITY', title: `Shadow agent ${ALPHA}`, discoveredId: ALPHA });
    });

    it('a full row makes the agent registered at H1, on the operator\'s word and labelled as such', () => {
        const results = scored([fullRow(ALPHA)]);
        const agent = agentOf(results, ALPHA);
        expect(agent.declared).toEqual({ name: 'Invoice triage', owner: 'finance-operations', purpose: 'Sorts incoming invoices into queues', row: 1 });
        expect(agent.registration).toEqual({ basis: 'DECLARED_INVENTORY', ref: 'inventory:row-1' });
        expect(agent.judgement).toMatchObject({ state: 'JUDGED', level: 'H1', observedLevel: 'H0', bar: 'H2', shortfall: true });
        for (const criterion of HARNESS_CRITERIA.H1) {
            expect(cellOf(agent, criterion)).toEqual({
                criterion,
                state: 'EVIDENCED',
                basis: 'DECLARED',
                evidence: 'inventory:sha256:0123456789abcdef#row-1',
                readable: true,
            });
        }
        // What a source observed stays observed, beside it.
        expect(cellOf(agent, 'H2.credential_bound')).toMatchObject({ state: 'EVIDENCED', basis: 'OBSERVED' });
        expect(agent.observedOwner).toEqual({ kind: 'user', ref: 'usr_alpha_owner' });
        expect(codesFor(results, ALPHA)).toEqual(['HARNESS_SHORTFALL']);
    });

    it('states the inventory it used, as declared by the operator', () => {
        const results = scoreReportLocally(input(standaloneBody(), { inventory: inventoryOf([fullRow(ALPHA), fullRow('entra:sp:nowhere')], 'csv') }));
        expect(results.inventory).toEqual({
            provenance: 'DECLARED_BY_OPERATOR',
            sha256: INVENTORY_SHA,
            format: 'csv',
            rows: 2,
            matched: 1,
            unmatched: ['entra:sp:nowhere'],
        });
        expect(results.estate.registrationBasis).toBe('INVENTORY');
        expect(results.estate.shadowAgents).toEqual([BRAVO]);
    });

    it('says so in the shortfall when the level rests on a declaration', () => {
        const results = scored([fullRow(ALPHA)]);
        const shortfall = results.findings.find((f) => f.sourceRef === `HARNESS_SHORTFALL:${ALPHA}`)!;
        expect(shortfall.title).toBe(`Agent ${ALPHA} is below the harness bar (H1, bar H2)`);
        expect(shortfall.description).toContain('rests in part on what the operator declared');
        expect(shortfall.description).toContain('on what the sources observed alone it is H0');
        // And not when it does not.
        const plain = results.findings.find((f) => f.sourceRef === `HARNESS_SHORTFALL:${BRAVO}`)!;
        expect(plain.description).not.toContain('operator declared');
    });

    it('words the shadow finding for an inventory that does not name the agent', () => {
        const shadow = scored([fullRow(ALPHA)]).findings.find((f) => f.sourceRef === `SHADOW_AGENT:${BRAVO}`)!;
        expect(shadow.description).toContain('is not in the operator\'s inventory');
        expect(shadow.description).not.toContain('agent register');
    });

    it.each([
        ['another case', 'ENTRA:SP:ALPHA'],
        ['a trailing space', `${ALPHA} `],
        ['a leading space', ` ${ALPHA}`],
        ['a prefix of the id', 'entra:sp:alph'],
        ['the id as a prefix', `${ALPHA}-2`],
        ['the declared name of another row', 'Invoice triage'],
        ['the owner the source observed', 'usr_alpha_owner'],
    ])('matches by exact id only: %s matches nothing', (_label, id) => {
        const results = scored([fullRow(id)]);
        const without = scored([]);
        expect(results.inventory).toMatchObject({ rows: 1, matched: 0, unmatched: [id] });
        // Nothing else changes: the agents are exactly what they are under an inventory that names nobody.
        expect(results.agents).toEqual(without.agents);
        expect(results.estate.shadowAgents).toEqual([ALPHA, BRAVO]);
        expect(results.findings.map((f) => [f.code, f.sourceRef])).toEqual(without.findings.map((f) => [f.code, f.sourceRef]));
        // An unmatched row is not a finding.
        expect(results.findings.some((f) => f.description.includes(id) && !f.description.includes(ALPHA))).toBe(false);
    });

    it('answers NOT MET for axes the operator left out, and the agent stays at H0', () => {
        const agent = agentOf(scored([fullRow(ALPHA, { axes: undefined })]), ALPHA);
        expect(cellOf(agent, 'H1.axes_declared')).toMatchObject({ state: 'NOT_MET', basis: 'DECLARED' });
        expect(cellOf(agent, 'H1.registered')).toMatchObject({ state: 'EVIDENCED', basis: 'DECLARED' });
        expect(agent.judgement).toMatchObject({ level: 'H0', observedLevel: 'H0', blockingNextRung: ['H1.axes_declared'] });
        // Declared, and so registered, all the same.
        expect(agent.registration.basis).toBe('DECLARED_INVENTORY');
    });

    it.each([
        ['365 days before the scan', '2025-11-03', 'EVIDENCED', 'H1'],
        ['366 days before the scan', '2025-11-02', 'NOT_MET', 'H0'],
        ['after the scan', '2026-11-04', 'NOT_MET', 'H0'],
    ])('a tier assessed %s', (_label, riskAssessedOn, state, level) => {
        const agent = agentOf(scored([fullRow(ALPHA, { riskAssessedOn })]), ALPHA);
        expect(cellOf(agent, 'H1.tier_scored_fresh')).toMatchObject({ state, basis: 'DECLARED' });
        expect(agent.judgement).toMatchObject({ level });
        expect(AS_OF.startsWith('2026-11-03')).toBe(true);
    });

    it('never outvotes an observation: an observed NOT MET stands over a declared met', () => {
        const body = standaloneBody();
        body.agents[1].verdicts.push({ criterion: 'H1.owner', met: false, evidence: 'entra-sp:servicePrincipals/alpha#owners' });
        const agent = agentOf(scored([fullRow(ALPHA)], body), ALPHA);
        expect(cellOf(agent, 'H1.owner')).toEqual({
            criterion: 'H1.owner',
            state: 'NOT_MET',
            basis: 'OBSERVED',
            evidence: 'entra-sp:servicePrincipals/alpha#owners',
            readable: true,
        });
        expect(agent.judgement).toMatchObject({ level: 'H0', observedLevel: 'H0' });
    });

    it('reads as observed where a source and the operator say the same', () => {
        const results = scored([fullRow(REGISTERED)], validV3ReportBody());
        const agent = agentOf(results, REGISTERED);
        for (const criterion of HARNESS_CRITERIA.H1) {
            expect(cellOf(agent, criterion)).toMatchObject({ state: 'EVIDENCED', basis: 'OBSERVED' });
            expect(cellOf(agent, criterion).evidence).toMatch(/^inflect-register:/);
        }
        expect(agent.judgement).toMatchObject({ level: 'H2', observedLevel: 'H2' });
        expect(agent.declared?.name).toBe('Invoice triage');
    });

    it('a declared NOT MET stands over an observed met: the least favourable answer wins either way', () => {
        const agent = agentOf(scored([fullRow(REGISTERED, { axes: undefined })], validV3ReportBody()), REGISTERED);
        expect(cellOf(agent, 'H1.axes_declared')).toMatchObject({ state: 'NOT_MET', basis: 'DECLARED' });
        expect(agent.judgement).toMatchObject({ level: 'H0', observedLevel: 'H2' });
    });

    it('never overrides a register link the report carries, and an agent in both is not a conflict', () => {
        const results = scored([fullRow(REGISTERED)], validV3ReportBody());
        expect(agentOf(results, REGISTERED).registration).toEqual({ basis: 'OBSERVED_REGISTER', ref: 'agt_registered_1' });
        // The inventory names the agent; it holds no register id to disagree with.
        expect(results.estate.registrationConflicts).toEqual([]);
        expect(agentOf(results, REGISTERED).declared).toMatchObject({ row: 1 });
        expect(results.estate.registrationBasis).toBe('BOTH');
        expect(renderSummaryHtml(results)).not.toContain('different registrations');
    });

    it('with a register read too, an unregistered agent keeps the register\'s wording', () => {
        const shadow = scored([fullRow(REGISTERED)], validV3ReportBody()).findings.find((f) => f.sourceRef === `SHADOW_AGENT:${SHADOW}`)!;
        expect(shadow.description).toContain('agent register');
    });

    it('closes the shadow finding on a complete scan', () => {
        const results = scored([fullRow(ALPHA), fullRow(BRAVO)]);
        expect(results.estate.shadowAgents).toEqual([]);
        expect(results.findings.some((f) => f.code === 'SHADOW_AGENT')).toBe(false);
        expect(results.scan.complete).toBe(true);
    });

    it('on an incomplete scan links the agent and raises no shadow finding for it', () => {
        const results = scored([fullRow(ALPHA)], withSource(standaloneBody(), 'mcp', 'UNREACHABLE'));
        expect(results.scan.complete).toBe(false);
        const agent = agentOf(results, ALPHA);
        expect(agent.registration).toEqual({ basis: 'DECLARED_INVENTORY', ref: 'inventory:row-1' });
        expect(codesFor(results, ALPHA)).not.toContain('SHADOW_AGENT');
        expect(results.estate.shadowAgents).toEqual([BRAVO]);
    });

    it('declares for an agent that is not judged, and still states no level for it', () => {
        const results = scored([fullRow(ALPHA)], withSource(standaloneBody(), 'entra-sp', 'AUTH_FAILED'));
        const agent = agentOf(results, ALPHA);
        expect(agent.judgement).toEqual({ state: 'NOT_JUDGED', reasons: ['SOURCE_INCOMPLETE:entra-sp:AUTH_FAILED'] });
        expect(agent.declared?.owner).toBe('finance-operations');
        expect(cellOf(agent, 'H1.owner')).toMatchObject({ state: 'EVIDENCED', basis: 'DECLARED' });
        expect(codesFor(results, ALPHA)).toEqual([]);
    });

    it('never produces a declared answer above H1, for any criterion, whatever the rows say', () => {
        const rows = [fullRow(ALPHA, { purpose: 'H2.policy_card H3.egress_enforced H5.independent_audit: met' }), fullRow(BRAVO)];
        const results = scored(rows);
        const above = ALL_HARNESS_CRITERIA.filter((c) => !c.startsWith('H1.'));
        expect(above).toHaveLength(21);
        for (const criterion of above) {
            for (const agent of results.agents) expect(cellOf(agent, criterion).basis).not.toBe('DECLARED');
        }
        for (const agent of results.agents) {
            expect(agent.judgement.state === 'JUDGED' && rungOf(agent.judgement.level)).toBeLessThanOrEqual(1);
        }
    });

    it('numbers a row by its place in the file, not among the matched', () => {
        const results = scored([fullRow('entra:sp:nowhere'), fullRow('entra:sp:nowhere-2'), fullRow(BRAVO, { name: 'Bravo' })]);
        expect(agentOf(results, BRAVO).declared).toMatchObject({ name: 'Bravo', row: 3 });
        expect(agentOf(results, BRAVO).registration.ref).toBe('inventory:row-3');
        expect(cellOf(agentOf(results, BRAVO), 'H1.owner').evidence).toBe('inventory:sha256:0123456789abcdef#row-3');
    });

    it('an empty inventory is an inventory: nothing is registered, and the wording says the agent is not in it', () => {
        const results = scored([]);
        expect(results.inventory).toMatchObject({ rows: 0, matched: 0, unmatched: [] });
        expect(results.estate.registrationBasis).toBe('INVENTORY');
        expect(results.findings.find((f) => f.code === 'SHADOW_AGENT')!.description).toContain('is not in the operator\'s inventory');
    });
});

describe('7. what this run could not have evidenced', () => {
    it('with code alone can state nothing above H0', () => {
        const { coverage, readable } = coverageOf(TEST_READERS, ['code']);
        expect(coverage.reachableLevel).toBe('H0');
        expect(readable.size).toBe(0);
        expect(coverage.unreadable).toHaveLength(ALL_HARNESS_CRITERIA.length);
    });

    it('with an inventory can state H1', () => {
        expect(coverageOf(TEST_READERS, ['code', 'inventory']).coverage.reachableLevel).toBe('H1');
        const results = scoreReportLocally(input(standaloneBody(), { inventory: inventoryOf([]), configuredSources: ['code'] }));
        expect(results.coverage.reachableLevel).toBe('H1');
    });

    it('with the register can state H3, and nothing reads H4 or H5', () => {
        const { coverage } = coverageOf(TEST_READERS, ['inflect-register']);
        expect(coverage.reachableLevel).toBe('H3');
        expect(coverage.unreadable.map((u) => u.criterion)).toEqual([...HARNESS_CRITERIA.H4, ...HARNESS_CRITERIA.H5]);
        expect(coverage.unreadable.every((u) => u.why === 'NO_READER' && u.readers.length === 0)).toBe(true);
    });

    it('tells a criterion nothing reads from one whose reader was not configured, and names that reader', () => {
        const { coverage } = coverageOf(TEST_READERS, ['entra-sp']);
        expect(coverage.reachableLevel).toBe('H0');
        const why = new Map(coverage.unreadable.map((u) => [u.criterion, u]));
        expect(why.has('H2.credential_bound')).toBe(false);
        expect(why.get('H2.policy_card')).toEqual({ criterion: 'H2.policy_card', why: 'READER_NOT_CONFIGURED', readers: ['inflect-register'] });
        expect(why.get('H1.owner')).toEqual({ criterion: 'H1.owner', why: 'READER_NOT_CONFIGURED', readers: ['inflect-register', 'inventory'] });
        expect(why.get('H4.receipts')).toEqual({ criterion: 'H4.receipts', why: 'NO_READER', readers: [] });
    });

    it('does not count a reader that can only report NOT MET', () => {
        // `code` reports H2.tools_allowlisted, and only ever as not met.
        expect(TEST_READERS['H2.tools_allowlisted'].reportedBy).toContain('code');
        expect(coverageOf(TEST_READERS, ['code']).readable.has('H2.tools_allowlisted')).toBe(false);
    });

    it('marks each cell with whether this run could have answered it', () => {
        const results = scoreReportLocally(input(standaloneBody()));
        const agent = agentOf(results, BRAVO);
        expect(cellOf(agent, 'H2.credential_bound')).toMatchObject({ state: 'UNANSWERED', readable: true });
        expect(cellOf(agent, 'H2.policy_card')).toMatchObject({ state: 'UNANSWERED', readable: false });
        expect(cellOf(agent, 'H1.owner')).toMatchObject({ state: 'UNANSWERED', readable: false });
        expect(results.coverage.reachableLevel).toBe('H0');
    });

    it('counts the inventory as a reader only when one was supplied', () => {
        const without = scoreReportLocally(input(standaloneBody()));
        const withOne = scoreReportLocally(input(standaloneBody(), { inventory: inventoryOf([]) }));
        expect(cellOf(agentOf(without, BRAVO), 'H1.owner').readable).toBe(false);
        expect(cellOf(agentOf(withOne, BRAVO), 'H1.owner').readable).toBe(true);
    });
});

describe('8. the result', () => {
    const cases: [string, () => LocalResults][] = [
        ['a register estate', () => scoreReportLocally(input(validV3ReportBody()))],
        ['an estate with a sandbox and an inventory', () => scoreReportLocally(input(validV3ReportBodyWithSandbox(), { inventory: inventoryOf([fullRow(SHADOW), fullRow('nowhere')]) }))],
        ['an incomplete /2 estate', () => scoreReportLocally(input(validV2ReportBody()))],
        ['a standalone estate with an inventory', () => scoreReportLocally(input(standaloneBody(), { inventory: inventoryOf([fullRow(ALPHA)], 'csv') }))],
        ['an estate nothing could be judged in', () => scoreReportLocally(input(withSource(validV3ReportBody(), 'inflect-register', 'AUTH_FAILED')))],
        ['an empty estate', () => scoreReportLocally(input({ ...standaloneBody(), agents: [] }))],
    ];

    it.each(cases)('%s: is the same value for the same input', (_label, score) => {
        expect(canonicalJson(score())).toBe(canonicalJson(score()));
        expect(JSON.stringify(score())).toBe(JSON.stringify(score()));
    });

    it.each(cases)('%s: passes its own strict schema, and survives being written and read', (_label, score) => {
        const results = score();
        const reread = LocalResultsSchema.parse(JSON.parse(JSON.stringify(results)));
        expect(reread).toEqual(results);
    });

    it.each(cases)('%s: holds nothing secret-shaped', (_label, score) => {
        expect(firstSecretShapedMember(score())).toBeNull();
    });

    it('does not change the body it was given', () => {
        const body = validV3ReportBody();
        const before = JSON.stringify(body);
        scoreReportLocally(input(body, { inventory: inventoryOf([fullRow(SHADOW)]) }));
        expect(JSON.stringify(body)).toBe(before);
    });

    describe('tool-evidence sources', () => {
        const sourcesOf = (results: LocalResults, id: string) => agentOf(results, id).toolEvidenceSources;

        it('is the planner\'s own rule over the tools as reported: each tool\'s source, and where an unlisted one would be', () => {
            const body = standaloneBody();
            // Found through an identity source, tools on an MCP server.
            expect(sourcesOf(scoreReportLocally(input(body)), BRAVO)).toEqual(['mcp']);
            // Found through code, with a tool the code defines and one an MCP server serves.
            const mixed = {
                ...body,
                population: { sources: [{ kind: 'code' as const, status: 'COMPLETE' as const, rows: 1 }, { kind: 'mcp' as const, status: 'COMPLETE' as const, rows: 1 }] },
                agents: body.agents.map((a) => ({
                    ...a,
                    discoveredVia: ['code' as const],
                    tools: [...a.tools, { server: 'code://example/agent.py#local_tool', name: 'local_tool', manifestHash: null, pinned: false, readOnlyHint: null }],
                })),
            };
            expect(sourcesOf(scoreReportLocally(input(mixed)), BRAVO)).toEqual(['code', 'mcp']);
            // Found through code with no tool listed: where one would have been is the code.
            const bare = { ...mixed, agents: mixed.agents.map((a) => ({ ...a, tools: [] })) };
            expect(sourcesOf(scoreReportLocally(input(bare)), BRAVO)).toEqual(['code']);
            for (const agent of scoreReportLocally(input(mixed)).agents) {
                const observed = mixed.agents.find((a) => a.discoveredId === agent.discoveredId)!;
                expect(agent.toolEvidenceSources).toEqual([...toolEvidenceSourcesOf(observed)].sort());
            }
        });

        it('the schema reads a file without the member, and refuses a value it does not know, an empty list and a repeat', () => {
            const written = () => JSON.parse(JSON.stringify(scoreReportLocally(input(standaloneBody())))) as { agents: Record<string, unknown>[] };
            const older = written();
            for (const agent of older.agents) delete agent.toolEvidenceSources;
            expect(LocalResultsSchema.safeParse(older).success).toBe(true);
            for (const bad of [['runtime'], [], ['mcp', 'mcp'], 'mcp', null]) {
                const results = written();
                results.agents[0].toolEvidenceSources = bad;
                expect(LocalResultsSchema.safeParse(results).success).toBe(false);
            }
        });
    });

    describe('read back, a results file is refused when', () => {
        const valid = () => JSON.parse(JSON.stringify(scoreReportLocally(input(withSource(validV3ReportBody(), 'gcp-sa', 'AUTH_FAILED'))))) as {
            [key: string]: unknown;
            agents: { judgement: Record<string, unknown>; criteria: Record<string, unknown>[]; registration: Record<string, unknown>; discoveredId: string }[];
            estate: Record<string, unknown>;
            scan: Record<string, unknown>;
        };
        const notJudged = (r: ReturnType<typeof valid>) => r.agents.find((a) => a.judgement.state === 'NOT_JUDGED')!;
        const judged = (r: ReturnType<typeof valid>) => r.agents.find((a) => a.judgement.state === 'JUDGED')!;

        it('the fixture itself is accepted', () => {
            expect(LocalResultsSchema.safeParse(valid()).success).toBe(true);
            expect(notJudged(valid())).toBeDefined();
        });

        it.each([
            ['it names another schema', (r: ReturnType<typeof valid>) => { r.schema = 'scanent-results/2'; }],
            ['it carries a member this version does not know', (r: ReturnType<typeof valid>) => { r.generatedAt = '2026-11-03'; }],
            ['an agent that was not judged carries a level', (r: ReturnType<typeof valid>) => { notJudged(r).judgement.level = 'H3'; }],
            ['an agent that was not judged carries a bar', (r: ReturnType<typeof valid>) => { notJudged(r).judgement.bar = 'H2'; }],
            ['an agent that was not judged gives no reason', (r: ReturnType<typeof valid>) => { notJudged(r).judgement.reasons = []; }],
            ['a judged agent has no level', (r: ReturnType<typeof valid>) => { delete judged(r).judgement.level; }],
            ['a level is not a rung', (r: ReturnType<typeof valid>) => { judged(r).judgement.level = 'H6'; }],
            ['an agent leaves a criterion out', (r: ReturnType<typeof valid>) => { judged(r).criteria.pop(); }],
            ['an agent answers the criteria out of order', (r: ReturnType<typeof valid>) => { judged(r).criteria.reverse(); }],
            ['a cell names a criterion the ladder does not have', (r: ReturnType<typeof valid>) => { judged(r).criteria[0].criterion = 'H1.invented'; }],
            ['an unanswered cell claims a basis', (r: ReturnType<typeof valid>) => {
                const cell = judged(r).criteria.find((c) => c.state === 'UNANSWERED')!;
                cell.basis = 'OBSERVED';
            }],
            ['an answered cell has no basis', (r: ReturnType<typeof valid>) => {
                const cell = judged(r).criteria.find((c) => c.state === 'EVIDENCED')!;
                cell.basis = null;
            }],
            ['a registration has a basis and no reference', (r: ReturnType<typeof valid>) => { judged(r).registration = { basis: 'DECLARED_INVENTORY', ref: null }; }],
            ['the counts are not the agents listed', (r: ReturnType<typeof valid>) => { r.estate.judgedCount = 99; }],
            ['it says complete beside a source that was not read in full', (r: ReturnType<typeof valid>) => { r.scan.complete = true; }],
            ['it says incomplete with every source read in full', (r: ReturnType<typeof valid>) => {
                (r.sources as { status: string; reason: string | null }[]).forEach((s) => { s.status = 'COMPLETE'; s.reason = null; });
            }],
            ['it says complete with no source at all', (r: ReturnType<typeof valid>) => { r.sources = []; r.scan.complete = true; }],
            ['the agents per level are not the judged agents listed', (r: ReturnType<typeof valid>) => {
                const byLevel = r.estate.byLevel as Record<string, number>;
                const level = judged(r).judgement.level as string;
                byLevel[level] -= 1;
                byLevel[level === 'H5' ? 'H4' : 'H5'] += 1;
            }],
            ['the shortfall count is not the judged agents below their bar', (r: ReturnType<typeof valid>) => { r.estate.shortfallCount = (r.estate.shortfallCount as number) + 1; }],
            ['it says empty while listing agents', (r: ReturnType<typeof valid>) => { r.estate.empty = true; }],
            ['an agent is listed twice', (r: ReturnType<typeof valid>) => { r.agents[1].discoveredId = r.agents[0].discoveredId; }],
            ['the scan time is not a time', (r: ReturnType<typeof valid>) => { r.scan.asOf = 'yesterday'; }],
        ])('%s', (_label, change) => {
            const results = valid();
            change(results);
            expect(LocalResultsSchema.safeParse(results).success).toBe(false);
        });
    });
});
