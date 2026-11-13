/**
 * The shared table model: every cell state, when a row is judged, the bar, the
 * row order, the population, and that the module is safe in a browser bundle.
 */
import { readFileSync } from 'fs';
import { builtinModules } from 'module';
import { resolve } from 'path';
import * as ts from 'typescript';

import type { HarnessReportBody } from '../src/harness-contract';
import { planHarnessScan, type PriorHarnessState } from '../src/harness-findings';
import { ALL_HARNESS_CRITERIA, HARNESS_CRITERIA, HARNESS_LEVELS, type CriterionVerdict, type HarnessCriterionId } from '../src/harness-ladder';
import {
    buildHarnessMatrix,
    compareHarnessMatrixRows,
    CROSS_AGENT_VERDICT_SOURCE,
    HARNESS_MATRIX_CELL_STATES,
    HARNESS_MATRIX_COLUMNS,
    harnessBarStatusOf,
    harnessCoverageOf,
    harnessJudgementOf,
    harnessMatrixBarFor,
    harnessMatrixCellState,
    harnessMatrixCompleteness,
    isHarnessMatrixCellMet,
    SOURCES_UNREADABLE,
    VERDICTS_UNREADABLE,
    type CriterionReaders,
    type HarnessMatrixAgentInput,
    type HarnessMatrixInput,
    type HarnessMatrixRow,
    type HarnessMatrixRowRank,
    type ReaderKind,
} from '../src/harness-matrix-model';
import { PAYING_AGENT_ID, PAYING_AGENT_PAYMENT_AT, validV4ReportBody } from './helpers/agent-harness-fake-scanner';

const SRC = resolve(__dirname, '..', 'src');
const EV = 'https://evidence.example/1';
const ID = 'entra:sp:alpha';

/** The register and the inventory read H1; identity sources two H2 criteria; `code` only says NOT MET; nothing reads H4 or H5. */
const READERS: CriterionReaders = Object.fromEntries(
    ALL_HARNESS_CRITERIA.map((criterion): [HarnessCriterionId, CriterionReaders[HarnessCriterionId]] => {
        if (criterion.startsWith('H1.')) return [criterion, { reportedBy: ['inflect-register', 'inventory'], metBy: ['inflect-register', 'inventory'] }];
        if (criterion === 'H2.credential_bound') return [criterion, { reportedBy: ['entra-sp'], metBy: ['entra-sp'] }];
        if (criterion === 'H2.tools_allowlisted') return [criterion, { reportedBy: ['inflect-register', 'code'], metBy: ['inflect-register'] }];
        if (criterion.startsWith('H2.') || criterion.startsWith('H3.')) return [criterion, { reportedBy: ['inflect-register'], metBy: ['inflect-register'] }];
        return [criterion, { reportedBy: [], metBy: [] }];
    }),
) as CriterionReaders;

const v = (criterion: HarnessCriterionId, met: boolean, evidence: string | null = EV): CriterionVerdict => ({ criterion, met, evidence });
const H1 = HARNESS_CRITERIA.H1 as readonly HarnessCriterionId[];
const H2 = HARNESS_CRITERIA.H2 as readonly HarnessCriterionId[];

function agent(over: Partial<HarnessMatrixAgentInput> = {}): HarnessMatrixAgentInput {
    return {
        discoveredId: ID,
        discoveredVia: ['entra-sp'],
        verdicts: [],
        reach: 'READ_ONLY',
        registeredAgentId: 'agt_1',
        linkBasis: 'REPORT',
        unregisteredIdentity: false,
        modelSigns: ['LISTS_A_TOOL'],
        paymentCapabilities: null,
        ...over,
    };
}

function one(a: HarnessMatrixAgentInput, over: Partial<HarnessMatrixInput> = {}): HarnessMatrixRow {
    return buildHarnessMatrix({ agents: [a], sources: [{ kind: 'entra-sp', status: 'COMPLETE' }], readers: { table: READERS, configured: ['entra-sp'] }, ...over }).rows[0];
}

const cellOf = (row: HarnessMatrixRow, criterion: HarnessCriterionId) => row.cells.find((c) => c.criterion === criterion)!;

describe('a cell has one of seven states', () => {
    it('names them in legend order, and only the first two are met', () => {
        expect([...HARNESS_MATRIX_CELL_STATES]).toEqual(['EVIDENCED', 'DECLARED', 'MET_UNEVIDENCED', 'NOT_MET', 'NOT_MET_DECLARED', 'UNANSWERED', 'NOT_READABLE']);
        expect(HARNESS_MATRIX_CELL_STATES.filter(isHarnessMatrixCellMet)).toEqual(['EVIDENCED', 'DECLARED']);
    });

    it('reaches each state from the verdicts, the declarations and the readers', () => {
        const row = one(
            agent({ verdicts: [v('H1.registered', true), v('H1.axes_declared', true, null), v('H2.credential_bound', false)] }),
            {
                readers: { table: READERS, configured: ['entra-sp', 'inventory'] },
                declared: new Map([[ID, [v('H1.owner', true, 'inventory:row-1'), v('H1.tier_scored_fresh', false, 'inventory:row-1')]]]),
            },
        );
        expect(cellOf(row, 'H1.registered').state).toBe('EVIDENCED');
        expect(cellOf(row, 'H1.owner').state).toBe('DECLARED');
        expect(cellOf(row, 'H1.axes_declared').state).toBe('MET_UNEVIDENCED');
        expect(cellOf(row, 'H2.credential_bound').state).toBe('NOT_MET');
        expect(cellOf(row, 'H1.tier_scored_fresh').state).toBe('NOT_MET_DECLARED');
        // Read by the register, which this run did not configure.
        expect(cellOf(row, 'H2.policy_card').state).toBe('NOT_READABLE');
        // A criterion no reader reads at all.
        expect(cellOf(row, 'H5.independent_audit').state).toBe('NOT_READABLE');
        expect(new Set(row.cells.map((c) => c.state))).toEqual(new Set(HARNESS_MATRIX_CELL_STATES.filter((s) => s !== 'UNANSWERED')));
        // Configured, and nothing said.
        expect(cellOf(one(agent()), 'H2.credential_bound').state).toBe('UNANSWERED');
    });

    it('carries the deciding verdict: its ladder state, its basis and its evidence', () => {
        const row = one(agent({ verdicts: [v('H1.registered', true)] }), { declared: new Map([[ID, [v('H1.owner', true, 'inventory:row-1')]]]) });
        expect(cellOf(row, 'H1.registered')).toEqual({ criterion: 'H1.registered', level: 'H1', state: 'EVIDENCED', verdictState: 'EVIDENCED', basis: 'OBSERVED', evidence: EV, readable: false });
        expect(cellOf(row, 'H1.owner')).toMatchObject({ state: 'DECLARED', basis: 'DECLARED', evidence: 'inventory:row-1' });
        expect(cellOf(row, 'H2.policy_card')).toMatchObject({ verdictState: 'UNANSWERED', basis: null, evidence: null });
    });

    it('maps the four ladder states with the same rule the files use', () => {
        expect(harnessMatrixCellState({ state: 'EVIDENCED', basis: 'OBSERVED', readable: false })).toBe('EVIDENCED');
        expect(harnessMatrixCellState({ state: 'EVIDENCED', basis: 'DECLARED', readable: true })).toBe('DECLARED');
        expect(harnessMatrixCellState({ state: 'MET_UNEVIDENCED', basis: 'DECLARED', readable: true })).toBe('MET_UNEVIDENCED');
        expect(harnessMatrixCellState({ state: 'NOT_MET', basis: 'OBSERVED', readable: false })).toBe('NOT_MET');
        expect(harnessMatrixCellState({ state: 'NOT_MET', basis: 'DECLARED', readable: true })).toBe('NOT_MET_DECLARED');
        expect(harnessMatrixCellState({ state: 'UNANSWERED', basis: null, readable: true })).toBe('UNANSWERED');
        expect(harnessMatrixCellState({ state: 'UNANSWERED', basis: null, readable: false })).toBe('NOT_READABLE');
    });

    it('lists every criterion once, in ladder order, under the level that first requires it', () => {
        const row = one(agent());
        expect(row.cells.map((c) => c.criterion)).toEqual([...ALL_HARNESS_CRITERIA]);
        for (const c of row.cells) expect((HARNESS_CRITERIA[c.level] as readonly string[]).includes(c.criterion)).toBe(true);
        expect(HARNESS_MATRIX_COLUMNS.map((g) => g.level)).toEqual(HARNESS_LEVELS.slice(1));
        expect(HARNESS_MATRIX_COLUMNS.flatMap((g) => g.criteria)).toEqual([...ALL_HARNESS_CRITERIA]);
        expect(HARNESS_MATRIX_COLUMNS[0].name).toBe('Registered');
    });
});

describe('a cell is the ladder\'s rule', () => {
    it('a met with no evidence is not met, and does not raise the level', () => {
        const row = one(agent({ verdicts: H1.map((c) => v(c, true, c === 'H1.owner' ? '  ' : EV)) }));
        expect(cellOf(row, 'H1.owner').state).toBe('MET_UNEVIDENCED');
        expect(row.level).toBe('H0');
        expect(row.blockingNextRung).toEqual(['H1.owner']);
    });

    it('a criterion reported twice shows its least favourable answer', () => {
        const row = one(agent({ verdicts: [v('H2.credential_bound', true), v('H2.credential_bound', false, 'https://evidence.example/2')] }));
        expect(cellOf(row, 'H2.credential_bound')).toMatchObject({ state: 'NOT_MET', evidence: 'https://evidence.example/2' });
    });
});

describe('a declaration is never shown as an observation', () => {
    const declaredH1 = new Map([[ID, H1.map((c) => v(c, true, 'inventory:row-1'))]]);

    it('a declared met never outvotes an observed NOT MET', () => {
        const row = one(agent({ verdicts: [v('H1.owner', false)] }), { declared: declaredH1 });
        expect(cellOf(row, 'H1.owner')).toMatchObject({ state: 'NOT_MET', basis: 'OBSERVED' });
        expect(row.level).toBe('H0');
    });

    it('where both say the same, the observed one stands', () => {
        const row = one(agent({ verdicts: [v('H1.registered', true)] }), { declared: declaredH1 });
        expect(cellOf(row, 'H1.registered')).toMatchObject({ state: 'EVIDENCED', basis: 'OBSERVED', evidence: EV });
    });

    it('the level counts declarations; the observed level does not', () => {
        const row = one(agent(), { declared: declaredH1 });
        expect(row.level).toBe('H1');
        expect(row.observedLevel).toBe('H0');
        expect(one(agent({ verdicts: H1.map((c) => v(c, true)) })).observedLevel).toBe('H1');
    });

    it('a declaration for another agent changes nothing', () => {
        expect(one(agent(), { declared: new Map([['entra:sp:other', H1.map((c) => v(c, true, 'inventory:row-1'))]]) }).level).toBe('H0');
    });
});

describe('not readable is not unanswered', () => {
    it('a reader that can only say NOT MET does not make a criterion readable', () => {
        expect(cellOf(one(agent(), { readers: { table: READERS, configured: ['code'] } }), 'H2.tools_allowlisted').state).toBe('NOT_READABLE');
    });

    it('a verdict that arrived is shown as it is, readable or not', () => {
        const row = one(agent({ verdicts: [v('H4.receipts', false)] }));
        expect(cellOf(row, 'H4.receipts')).toMatchObject({ state: 'NOT_MET', readable: false });
    });

    it('without readers, nothing is NOT_READABLE and no coverage is stated', () => {
        const model = buildHarnessMatrix({ agents: [agent()], sources: [{ kind: 'entra-sp', status: 'COMPLETE' }] });
        expect(model.coverage).toBeNull();
        expect(new Set(model.rows[0].cells.map((c) => c.state))).toEqual(new Set(['UNANSWERED']));
    });

    it('coverage names the highest level the run could state, and why each other criterion was out of reach', () => {
        const configured: ReaderKind[] = ['entra-sp', 'inventory'];
        const { readable, coverage } = harnessCoverageOf(READERS, configured);
        expect(coverage.reachableLevel).toBe('H1');
        expect(readable.has('H1.owner')).toBe(true);
        expect(coverage.unreadable.find((u) => u.criterion === 'H2.policy_card')).toEqual({ criterion: 'H2.policy_card', why: 'READER_NOT_CONFIGURED', readers: ['inflect-register'] });
        expect(coverage.unreadable.find((u) => u.criterion === 'H4.receipts')).toEqual({ criterion: 'H4.receipts', why: 'NO_READER', readers: [] });
        expect(harnessCoverageOf(READERS, ['inflect-register', 'entra-sp']).coverage.reachableLevel).toBe('H3');
        expect(buildHarnessMatrix({ agents: [], sources: [], readers: { table: READERS, configured } }).coverage).toEqual(coverage);
    });
});

describe('an incomplete source closes nothing', () => {
    const allH1 = H1.map((c) => v(c, true));

    it('an agent whose own source was not read in full states no level, no bar standing and no shortfall', () => {
        const row = one(agent({ verdicts: allH1, reach: 'WRITE_OR_EXTERNAL' }), { sources: [{ kind: 'entra-sp', status: 'INCOMPLETE', reason: 'TIME_BOX' }] });
        expect(row.judgement).toEqual({ kind: 'NOT_JUDGED', reasons: ['SOURCE_INCOMPLETE:entra-sp:TIME_BOX'] });
        expect([row.level, row.observedLevel, row.blockingNextRung]).toEqual([null, null, null]);
        expect(row.barStatus).toBe('NOT_JUDGED');
        expect(row.countsAsShortfall).toBe(false);
        // The bar is a fact about its reach, and is still stated.
        expect(row.bar).toBe('H3');
        // The cells are still what was reported.
        expect(cellOf(row, 'H1.owner').state).toBe('EVIDENCED');
    });

    it('an incomplete register withholds every level; any other incomplete source is a caveat', () => {
        const sources = [
            { kind: 'entra-sp', status: 'COMPLETE' as const },
            { kind: 'inflect-register', status: 'INCOMPLETE' as const, reason: 'HTTP_ERROR' },
        ];
        expect(one(agent(), { sources }).judgement).toEqual({ kind: 'NOT_JUDGED', reasons: ['VERDICT_SOURCE_INCOMPLETE:inflect-register:HTTP_ERROR'] });
        expect(one(agent(), { sources: [sources[0], { kind: 'vault', status: 'INCOMPLETE', reason: null }] }).judgement).toEqual({
            kind: 'JUDGED',
            caveats: ['OTHER_SOURCE_INCOMPLETE:vault'],
        });
    });

    it('a source the scan does not list, sources that cannot be read back, and verdicts that cannot be read back are each a reason', () => {
        expect(harnessJudgementOf(['code'], [{ kind: 'entra-sp', status: 'COMPLETE' }])).toEqual({ kind: 'NOT_JUDGED', reasons: ['SOURCE_INCOMPLETE:code:NOT_LISTED'] });
        expect(harnessJudgementOf(['entra-sp'], [{ kind: 'entra-sp', status: 'INCOMPLETE' }])).toEqual({ kind: 'NOT_JUDGED', reasons: ['SOURCE_INCOMPLETE:entra-sp:UNKNOWN'] });
        expect(one(agent(), { sources: null }).judgement).toEqual({ kind: 'NOT_JUDGED', reasons: [SOURCES_UNREADABLE] });
        const unreadable = one(agent({ verdicts: null }), { declared: new Map() });
        expect(unreadable.judgement).toEqual({ kind: 'NOT_JUDGED', reasons: [VERDICTS_UNREADABLE] });
        expect(unreadable.level).toBeNull();
        expect(new Set(unreadable.cells.map((c) => c.verdictState))).toEqual(new Set(['UNANSWERED']));
        expect(one(agent({ verdicts: null }), { sources: null }).judgement).toEqual({ kind: 'NOT_JUDGED', reasons: [SOURCES_UNREADABLE, VERDICTS_UNREADABLE] });
    });

    it('classifies every source kind, and only the register as reporting on other sources\' agents', () => {
        expect(Object.entries(CROSS_AGENT_VERDICT_SOURCE).filter(([, cross]) => cross).map(([kind]) => kind)).toEqual(['inflect-register']);
    });
});

describe('the bar', () => {
    it('is H2 for a read-only agent and H3 otherwise, unknown reach included', () => {
        expect(harnessMatrixBarFor('READ_ONLY')).toBe('H2');
        expect(harnessMatrixBarFor('WRITE_OR_EXTERNAL')).toBe('H3');
        expect(harnessMatrixBarFor('UNKNOWN')).toBe('H3');
        expect(harnessBarStatusOf('H2', 'READ_ONLY')).toBe('AT_BAR');
        expect(harnessBarStatusOf('H2', 'UNKNOWN')).toBe('BELOW_BAR');
        expect(harnessBarStatusOf(null, 'READ_ONLY')).toBe('NOT_JUDGED');
    });

    it('a judged agent below its bar counts as a shortfall; one at it does not', () => {
        const at = one(agent({ verdicts: [...H1, ...H2].map((c) => v(c, true)) }));
        expect([at.level, at.barStatus, at.countsAsShortfall]).toEqual(['H2', 'AT_BAR', false]);
        const below = one(agent({ reach: 'UNKNOWN' }));
        expect([below.level, below.bar, below.barStatus, below.countsAsShortfall]).toEqual(['H0', 'H3', 'BELOW_BAR', true]);
    });

    it('an unregistered automated identity is held to no bar, and says where it would stand', () => {
        const row = one(agent({ registeredAgentId: null, linkBasis: null, unregisteredIdentity: true, modelSigns: [] }));
        expect(row.classification).toBe('UNREGISTERED_IDENTITY');
        expect([row.barStatus, row.heldToBar, row.countsAsShortfall]).toEqual(['BELOW_BAR', false, false]);
    });

    it('classifies a principal as registered, a shadow agent or an unregistered identity', () => {
        expect(one(agent()).classification).toBe('REGISTERED');
        expect(one(agent()).registration).toEqual({ ref: 'agt_1', basis: 'REPORT' });
        const shadow = one(agent({ registeredAgentId: null, linkBasis: null }));
        expect([shadow.classification, shadow.heldToBar, shadow.registration]).toEqual(['SHADOW_AGENT', true, { ref: null, basis: null }]);
    });
});

describe('row order: worst first', () => {
    const rank = (discoveredId: string, level: HarnessMatrixRowRank['level'], barStatus: HarnessMatrixRowRank['barStatus']): HarnessMatrixRowRank => ({ discoveredId, level, barStatus });

    it('not judged, then below the bar, then at it; the lowest level first; then by id, by code unit', () => {
        const rows = [
            rank('a-at-h3', 'H3', 'AT_BAR'),
            rank('b-at-h2', 'H2', 'AT_BAR'),
            rank('c-below-h1', 'H1', 'BELOW_BAR'),
            rank('Z-below-h1', 'H1', 'BELOW_BAR'),
            rank('d-below-h0', 'H0', 'BELOW_BAR'),
            rank('z-not-judged', null, 'NOT_JUDGED'),
            rank('e-not-judged', null, 'NOT_JUDGED'),
        ];
        expect([...rows].sort(compareHarnessMatrixRows).map((r) => r.discoveredId)).toEqual([
            'e-not-judged',
            'z-not-judged',
            'd-below-h0',
            'Z-below-h1',
            'c-below-h1',
            'b-at-h2',
            'a-at-h3',
        ]);
    });

    it('orders a built row the same way, and an unregistered identity among those below the bar', () => {
        const model = buildHarnessMatrix({
            agents: [
                agent({ discoveredId: 'b', verdicts: [...H1, ...H2].map((c) => v(c, true)) }),
                agent({ discoveredId: 'a', registeredAgentId: null, linkBasis: null, unregisteredIdentity: true, modelSigns: [] }),
                agent({ discoveredId: 'c', discoveredVia: ['code'] }),
            ],
            sources: [{ kind: 'entra-sp', status: 'COMPLETE' }],
        });
        expect([...model.rows].sort(compareHarnessMatrixRows).map((r) => r.discoveredId)).toEqual(['c', 'a', 'b']);
    });

    it('a level the ladder does not know sorts as the lowest', () => {
        const unknown = { discoveredId: 'b', level: 'H9', barStatus: 'BELOW_BAR' } as unknown as HarnessMatrixRowRank;
        expect(compareHarnessMatrixRows(unknown, rank('a', 'H1', 'BELOW_BAR'))).toBeLessThan(0);
    });
});

describe('the population: zero is never complete', () => {
    it('an empty scan is EMPTY, whatever its sources say', () => {
        const model = buildHarnessMatrix({ agents: [], sources: [{ kind: 'entra-sp', status: 'COMPLETE' }] });
        expect(model.rows).toEqual([]);
        expect(model.population).toEqual({ agentCount: 0, judgedCount: 0, notJudgedCount: 0, completeness: 'EMPTY' });
    });

    it('COMPLETE needs at least one source, every one read in full, readable sources and an agent', () => {
        expect(harnessMatrixCompleteness([{ kind: 'entra-sp', status: 'COMPLETE' }], 1)).toBe('COMPLETE');
        expect(harnessMatrixCompleteness([], 1)).toBe('INCOMPLETE');
        expect(harnessMatrixCompleteness(null, 1)).toBe('INCOMPLETE');
        expect(harnessMatrixCompleteness([{ kind: 'entra-sp', status: 'COMPLETE' }, { kind: 'code', status: 'INCOMPLETE' }], 1)).toBe('INCOMPLETE');
        expect(harnessMatrixCompleteness(null, 0)).toBe('EMPTY');
    });

    it('counts the judged and the not judged', () => {
        const model = buildHarnessMatrix({
            agents: [agent(), agent({ discoveredId: 'code:x', discoveredVia: ['code'] })],
            sources: [{ kind: 'entra-sp', status: 'COMPLETE' }],
        });
        expect(model.population).toEqual({ agentCount: 2, judgedCount: 1, notJudgedCount: 1, completeness: 'COMPLETE' });
        expect(model.rows.map((r) => r.discoveredId)).toEqual([ID, 'code:x']);
    });
});

describe('a /4 scan, as the planner gives it', () => {
    const PRIOR: PriorHarnessState = {
        previousLevels: new Map(),
        registeredAgentIds: new Set(['agt_registered_1']),
        acceptedShortfalls: new Set(),
        intakeClaims: new Map(),
        openOrphanCredentials: new Set(),
        onRecordAsAgent: new Set(),
        spendingAuthority: new Map(),
    };

    it('takes the planner\'s agents as they are, and agrees with the planner on every level', () => {
        const body = validV4ReportBody() as HarnessReportBody;
        const plan = planHarnessScan(body, PRIOR);
        const model = buildHarnessMatrix({ agents: plan.agents, sources: body.population.sources });
        expect(model.rows).toHaveLength(body.agents.length);
        for (const [i, row] of model.rows.entries()) {
            if (row.judgement.kind !== 'JUDGED') continue;
            expect([row.discoveredId, row.level, row.blockingNextRung]).toEqual([plan.agents[i].discoveredId, plan.agents[i].level, plan.agents[i].blockingNextRung]);
            expect(row.classification === 'UNREGISTERED_IDENTITY').toBe(plan.agents[i].unregisteredIdentity);
        }
        const paying = model.rows.find((r) => r.discoveredId === PAYING_AGENT_ID)!;
        expect(paying.paymentCapabilities).toEqual([{ protocol: 'x402', library: 'x402-fetch', at: PAYING_AGENT_PAYMENT_AT }]);
        expect(paying.modelSigns).toContain('FOUND_IN_CODE');
        // `[]` is a code read that saw no payment client; `null` is not reported. Neither is rewritten.
        expect(model.rows.map((r) => r.paymentCapabilities === null ? 'null' : r.paymentCapabilities.length === 0 ? '[]' : 'seen')).toEqual(
            plan.agents.map((a) => (a.paymentCapabilities === null ? 'null' : a.paymentCapabilities.length === 0 ? '[]' : 'seen')),
        );
    });

    it('carries a name hint as given, and none when none was given', () => {
        expect(one(agent({ nameHint: { text: 'Support bot', basis: 'DECLARED' } })).nameHint).toEqual({ text: 'Support bot', basis: 'DECLARED' });
        expect(one(agent()).nameHint).toBeNull();
    });
});

describe('safe in a browser bundle', () => {
    /** Each import of a source file: its specifier, and whether it brings anything at run time. */
    function importsOf(file: string): { readonly spec: string; readonly runtime: boolean }[] {
        const source = ts.createSourceFile(file, readFileSync(resolve(SRC, file), 'utf8'), ts.ScriptTarget.ES2022, false);
        const found: { spec: string; runtime: boolean }[] = [];
        for (const statement of source.statements) {
            if ((ts.isImportDeclaration(statement) || ts.isExportDeclaration(statement)) && statement.moduleSpecifier && ts.isStringLiteral(statement.moduleSpecifier)) {
                let runtime: boolean;
                if (ts.isImportDeclaration(statement)) {
                    const clause = statement.importClause;
                    const named = clause?.namedBindings;
                    runtime =
                        clause === undefined ||
                        (!clause.isTypeOnly &&
                            (clause.name !== undefined ||
                                (named !== undefined && (ts.isNamespaceImport(named) || named.elements.some((e) => !e.isTypeOnly)))));
                } else {
                    runtime = !statement.isTypeOnly;
                }
                found.push({ spec: statement.moduleSpecifier.text, runtime });
            }
        }
        // A dynamic import or require would be a run-time import this walk cannot follow.
        const text = source.getFullText();
        expect([file, /\brequire\s*\(|\bimport\s*\(/.test(text)]).toEqual([file, false]);
        return found;
    }

    it('imports nothing outside packages/contract/src, and no Node built-in', () => {
        const imports = importsOf('harness-matrix-model.ts');
        expect(imports.length).toBeGreaterThan(0);
        const builtins = new Set([...builtinModules, ...builtinModules.map((m) => `node:${m}`)]);
        for (const { spec } of imports) {
            expect([spec, spec.startsWith('./') && !spec.slice(2).includes('/')]).toEqual([spec, true]);
            expect([spec, builtins.has(spec)]).toEqual([spec, false]);
            expect(() => readFileSync(resolve(SRC, `${spec.slice(2)}.ts`))).not.toThrow();
        }
    });

    it('brings only the ladder at run time, and the ladder brings nothing', () => {
        expect(importsOf('harness-matrix-model.ts').filter((i) => i.runtime).map((i) => i.spec)).toEqual(['./harness-ladder']);
        expect(importsOf('harness-ladder.ts')).toEqual([]);
    });
});
