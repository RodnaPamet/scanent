/**
 * The difference between two runs.
 *
 * The rule that matters most is held first: absence concludes something only
 * on a full read. An agent missing from the new run is GONE when every source
 * it was found through was read in full, and NOT SEEN otherwise; an orphan
 * credential or a finding is CLOSED only on positive evidence. A diff that
 * found nothing and could not compare everything is never "the same".
 */
import type { HarnessReportBodyV3 } from '@scanent/contract/harness-contract';
import { ALL_HARNESS_CRITERIA } from '@scanent/contract/harness-ladder';

import { DIFF_SCHEMA, diffExitCode, DiffRefused, diffResults, TOOL_EVIDENCE_OLDER_RULE, type ResultsDiff } from '../src/diff/diff';
import { renderDiffText } from '../src/render/diff-text';
import { terminalJson, terminalLine } from '../src/render/escape';
import { stableJson } from '../src/render/results-json';
import { scoreReportLocally } from '../src/results/score';
import type { LocalResults } from '../src/results/types';
import { fullRow, HASH, input, inventoryOf, META, standaloneBody, withSource } from './helpers/fixtures';
import { ALPHA, BRAVO, laterBody, plainResults } from './helpers/results';

const score = (body: HarnessReportBodyV3, inventory = false): LocalResults =>
    scoreReportLocally(input(body, { inventory: inventory ? inventoryOf([fullRow(ALPHA)]) : null }));

const next = (change?: (b: HarnessReportBodyV3) => HarnessReportBodyV3): LocalResults => score(laterBody(change));

const without = (id: string) => (b: HarnessReportBodyV3): HarnessReportBodyV3 => ({ ...b, agents: b.agents.filter((a) => a.discoveredId !== id) });

const UNBOUND = [{ ref: 'entra://sp/unused/password/1', sourceKind: 'entra-sp' as const }];

/** Every H1 criterion observed met, so the agent is H1 on observation alone. */
const h1Observed = (b: HarnessReportBodyV3): HarnessReportBodyV3 => ({
    ...b,
    agents: b.agents.map((a) =>
        a.discoveredId !== ALPHA
            ? a
            : { ...a, verdicts: [...a.verdicts, ...ALL_HARNESS_CRITERIA.filter((c) => c.startsWith('H1.')).map((criterion) => ({ criterion, met: true, evidence: 'register:row' }))] },
    ),
});

function expectNothing(diff: ResultsDiff): void {
    expect(diff.sources).toEqual([]);
    expect(diff.agents).toEqual({ added: [], gone: [], notSeen: [] });
    expect(diff.levels).toEqual([]);
    expect(diff.criteria).toEqual([]);
    expect(diff.attributes).toEqual([]);
    expect(diff.orphanCredentials).toEqual([]);
    expect(diff.findings).toEqual([]);
}

describe('the same estate, scanned again', () => {
    it('is SAME, exit 0, with nothing listed and nothing left unconcluded', () => {
        const diff = diffResults(plainResults(), next());
        expectNothing(diff);
        expect(diff).toMatchObject({ schema: DIFF_SCHEMA, outcome: 'SAME', notConcluded: [], warnings: [], summary: { differences: 0, notConcluded: 0 } });
        expect(diffExitCode(diff)).toBe(0);
        expect(diff.old).toMatchObject({ scanId: 'acme-20261103T033000Z-0a1b2c3d', complete: true, agentCount: 2, inventorySha256: null, signerPinned: true });
        expect(diff.new.asOf).toBe('2026-11-04T03:30:00.000Z');
        const text = renderDiffText(diff);
        expect(text.startsWith('scanent diff: No difference, and every comparison could be made.\n0 differences; 0 comparisons not concluded.\n')).toBe(true);
        expect(text).not.toContain('Not concluded');
        expect(text.endsWith('\n')).toBe(true);
    });
});

describe('completeness is compared first', () => {
    it.each([
        ['NOW_INCOMPLETE', standaloneBody(), laterBody((b) => withSource(b, 'mcp', 'TIME_BOX')), 'mcp was read in full and is now incomplete (- -> TIME_BOX)'],
        ['NOW_COMPLETE', withSource(standaloneBody(), 'mcp', 'TIME_BOX'), laterBody(), 'mcp was incomplete and is now read in full (TIME_BOX -> -)'],
        [
            'REASON_CHANGED',
            withSource(standaloneBody(), 'mcp', 'TIME_BOX'),
            laterBody((b) => withSource(b, 'mcp', 'AUTH_FAILED')),
            'mcp is still incomplete, for a different reason (TIME_BOX -> AUTH_FAILED)',
        ],
        [
            'ADDED',
            standaloneBody(),
            laterBody((b) => ({ ...b, population: { sources: [...b.population.sources, { kind: 'vault' as const, status: 'COMPLETE' as const, rows: 0 }] } })),
            'vault is new in this run',
        ],
        [
            'NO_LONGER_READ',
            standaloneBody(),
            laterBody((b) => ({ ...b, population: { sources: b.population.sources.filter((s) => s.kind !== 'mcp') } })),
            'mcp is no longer listed',
        ],
    ] as const)('%s', (change, before, after, line) => {
        const diff = diffResults(score(before), score(after));
        expect(diff.sources.map((s) => s.change)).toEqual([change]);
        expect(diff.outcome).toBe('DIFFERENT');
        const text = renderDiffText(diff);
        expect(text).toContain(`  ${line}`);
        expect(text.indexOf('Completeness')).toBeLessThan(text.indexOf(line));
        const later = ['Agents', 'Levels', 'Criteria', 'Findings'].map((h) => text.indexOf(`\n${h}`)).filter((i) => i >= 0);
        for (const i of later) expect(text.indexOf('\nCompleteness')).toBeLessThan(i);
    });
});

describe('agents', () => {
    it('one the new run found and the old did not is NEW', () => {
        const diff = diffResults(score(without(BRAVO)(standaloneBody())), next());
        expect(diff.agents).toEqual({ added: [BRAVO], gone: [], notSeen: [] });
        expect(renderDiffText(diff)).toContain(`  new        ${BRAVO}`);
        expect(diffExitCode(diff)).toBe(1);
    });

    it('one missing from the new run is GONE when every source it was found through was read in full', () => {
        const diff = diffResults(plainResults(), next(without(BRAVO)));
        expect(diff.agents).toEqual({ added: [], gone: [BRAVO], notSeen: [] });
        expect(diff.outcome).toBe('DIFFERENT');
        expect(renderDiffText(diff)).toContain(`  gone       ${BRAVO}`);
    });

    it.each([
        ['was not read in full', (b: HarnessReportBodyV3) => withSource(without(BRAVO)(b), 'entra-sp', 'TIME_BOX'), [{ kind: 'entra-sp', status: 'INCOMPLETE' }]],
        [
            'was not listed',
            (b: HarnessReportBodyV3) => ({ ...without(ALPHA)(without(BRAVO)(b)), population: { sources: b.population.sources.filter((s) => s.kind !== 'entra-sp') } }),
            [{ kind: 'entra-sp', status: 'ABSENT' }],
        ],
    ] as const)('one missing from the new run is NOT SEEN, never gone, when its source %s', (words, change, unread) => {
        const diff = diffResults(plainResults(), next(change));
        expect(diff.agents.gone).toEqual([]);
        const entry = diff.agents.notSeen.find((a) => a.discoveredId === BRAVO);
        expect(entry).toEqual({ discoveredId: BRAVO, unread, differentScanner: false, differentEstate: false, newScanEmpty: words === 'was not listed' });
        expect(diff.notConcluded).toContain(`AGENT_NOT_SEEN:${BRAVO}`);
        const lines = renderDiffText(diff).split('\n').filter((l) => l.includes(BRAVO));
        expect(lines.some((l) => l.includes(`not seen   ${BRAVO}  (entra-sp ${words}; nothing is concluded)`))).toBe(true);
        // Nothing said about that agent uses the words for a concluded absence.
        for (const line of lines) expect(line).not.toMatch(/\bgone\b|\bclosed\b/i);
    });

    it('an agent found through no source proves nothing by its absence', () => {
        const prev = plainResults();
        const odd: LocalResults = { ...prev, agents: prev.agents.map((a) => (a.discoveredId === BRAVO ? { ...a, discoveredVia: [] } : a)) };
        const diff = diffResults(odd, next(without(BRAVO)));
        expect(diff.agents.gone).toEqual([]);
        expect(diff.agents.notSeen).toEqual([{ discoveredId: BRAVO, unread: [], differentScanner: false, differentEstate: false, newScanEmpty: false }]);
        expect(renderDiffText(diff)).toContain('it was found through no listed source');
    });
});

describe('levels are compared only where both runs judged the agent', () => {
    it('LEVEL_UP when the level rose, and the observed level is compared apart', () => {
        const diff = diffResults(plainResults(), score(laterBody(), true));
        expect(diff.levels).toEqual([{ discoveredId: ALPHA, change: 'LEVEL_UP', from: 'H0', to: 'H1', reasons: [] }]);
        expect(diff.warnings).toEqual(['INVENTORY_DIFFERS']);
        const text = renderDiffText(diff);
        expect(text).toContain(`  ${ALPHA}: level up, H0 -> H1`);
        expect(text).toContain('INVENTORY_DIFFERS: the two runs were scored against different inventories');
        expect(text).toMatch(/new: scan .*\n {5}complete, 2 agents, inventory sha256:[0-9a-f]{64}, signer pinned/);
        expect(text).toMatch(/old: scan .*\n {5}complete, 2 agents, inventory none, signer pinned/);
    });

    it('LEVEL_DOWN and OBSERVED_LEVEL_DOWN when what a source observed is no longer there', () => {
        const diff = diffResults(score(h1Observed(standaloneBody())), next());
        expect(diff.levels).toEqual([
            { discoveredId: ALPHA, change: 'LEVEL_DOWN', from: 'H1', to: 'H0', reasons: [] },
            { discoveredId: ALPHA, change: 'OBSERVED_LEVEL_DOWN', from: 'H1', to: 'H0', reasons: [] },
        ]);
        const up = diffResults(plainResults(), next(h1Observed));
        expect(up.levels.map((l) => l.change)).toEqual(['LEVEL_UP', 'OBSERVED_LEVEL_UP']);
        expect(renderDiffText(up)).toContain('level on observation alone up, H0 -> H1');
    });

    it('NOW_NOT_JUDGED carries the reasons and no level; the agent\'s cells are reported, not concluded', () => {
        const diff = diffResults(plainResults(), next((b) => withSource({ ...b, agents: b.agents.map((a) => ({ ...a, verdicts: [] })) }, 'entra-sp', 'TIME_BOX')));
        expect(diff.levels).toEqual([
            { discoveredId: ALPHA, change: 'NOW_NOT_JUDGED', from: null, to: null, reasons: ['SOURCE_INCOMPLETE:entra-sp:TIME_BOX'] },
            { discoveredId: BRAVO, change: 'NOW_NOT_JUDGED', from: null, to: null, reasons: ['SOURCE_INCOMPLETE:entra-sp:TIME_BOX'] },
        ]);
        expect(diff.criteria).toEqual([
            {
                discoveredId: ALPHA,
                criterion: 'H2.credential_bound',
                from: { state: 'EVIDENCED', basis: 'OBSERVED' },
                to: { state: 'UNANSWERED', basis: null },
                concluded: false,
            },
        ]);
        expect(diff.notConcluded).toEqual(
            expect.arrayContaining(['SCAN_INCOMPLETE:new', `AGENT_NOT_JUDGED:${ALPHA}`, `AGENT_NOT_JUDGED:${BRAVO}`, `CRITERION_NOT_CONCLUDED:${ALPHA}:H2.credential_bound`]),
        );
        const text = renderDiffText(diff);
        expect(text).toContain(`${ALPHA}: was judged and is now not judged; no level is compared (SOURCE_INCOMPLETE:entra-sp:TIME_BOX)`);
        expect(text).toContain('Criteria reported, not concluded (the agent was not judged in one of the runs)');
        expect(text).toContain(`${ALPHA} H2.credential_bound: EVIDENCED/OBSERVED -> UNANSWERED`);
        expect(text).not.toMatch(/\nCriteria\n/);
    });

    it('NOW_JUDGED carries the old reasons', () => {
        const diff = diffResults(score(withSource(standaloneBody(), 'entra-sp', 'TIME_BOX')), next());
        expect(diff.levels.map((l) => [l.discoveredId, l.change, l.from, l.to])).toEqual([
            [ALPHA, 'NOW_JUDGED', null, null],
            [BRAVO, 'NOW_JUDGED', null, null],
        ]);
        expect(diff.levels[0].reasons).toEqual(['SOURCE_INCOMPLETE:entra-sp:TIME_BOX']);
    });

    it('an agent not judged in either run has no level entry, and the diff is not "the same"', () => {
        const incomplete = (b: HarnessReportBodyV3) => withSource(b, 'entra-sp', 'TIME_BOX');
        const diff = diffResults(score(incomplete(standaloneBody())), next(incomplete));
        expectNothing(diff);
        expect(diff.outcome).toBe('SAME_AS_FAR_AS_COMPARED');
        expect(diffExitCode(diff)).toBe(3);
        expect(diff.notConcluded).toEqual(['SCAN_INCOMPLETE:old', 'SCAN_INCOMPLETE:new', `AGENT_NOT_JUDGED:${ALPHA}`, `AGENT_NOT_JUDGED:${BRAVO}`]);
        const text = renderDiffText(diff);
        expect(text).toContain('No difference was found, but not every comparison could be made. This is not a statement that nothing changed.');
        expect(text).toContain(`\nNot concluded\n  SCAN_INCOMPLETE:old\n  SCAN_INCOMPLETE:new\n  AGENT_NOT_JUDGED:${ALPHA}\n`);
        expect(text).toContain('INCOMPLETE, 2 agents');
    });

    it('a new agent that is not judged is listed as new and as not concluded', () => {
        const diff = diffResults(score(without(BRAVO)(standaloneBody())), next((b) => withSource(b, 'entra-sp', 'TIME_BOX')));
        expect(diff.agents.added).toEqual([BRAVO]);
        expect(diff.notConcluded).toContain(`AGENT_NOT_JUDGED:${BRAVO}`);
    });
});

describe('criteria, reach, bar, shortfall and registration', () => {
    it('a cell whose state or basis changed is listed, for a judged agent as concluded', () => {
        const diff = diffResults(plainResults(), score(laterBody(), true));
        const declared = diff.criteria.filter((c) => c.discoveredId === ALPHA);
        expect(declared.map((c) => c.criterion)).toEqual(['H1.registered', 'H1.owner', 'H1.axes_declared', 'H1.tier_scored_fresh']);
        for (const c of declared) expect(c).toMatchObject({ from: { state: 'UNANSWERED', basis: null }, to: { state: 'EVIDENCED', basis: 'DECLARED' }, concluded: true });
        expect(diff.attributes).toContainEqual({ discoveredId: ALPHA, attribute: 'registration', from: 'NONE', to: 'DECLARED_INVENTORY' });
        expect(renderDiffText(diff)).toContain(`${ALPHA} H1.owner: UNANSWERED -> EVIDENCED/DECLARED`);
    });

    it('a basis that changed with the state unchanged is a change', () => {
        const diff = diffResults(score(laterBodyAt('2026-11-02T00:00:00.000Z', h1Observed), false), score(laterBody(), true));
        const cell = diff.criteria.find((c) => c.criterion === 'H1.owner');
        expect(cell).toMatchObject({ from: { state: 'EVIDENCED', basis: 'OBSERVED' }, to: { state: 'EVIDENCED', basis: 'DECLARED' } });
    });

    it('reach, bar and shortfall changes are listed', () => {
        const readOnly = (b: HarnessReportBodyV3): HarnessReportBodyV3 => ({
            ...b,
            agents: b.agents.map((a) => (a.discoveredId === BRAVO ? { ...a, tools: a.tools.map((t) => ({ ...t, readOnlyHint: true, pinned: true, manifestHash: HASH })) } : a)),
        });
        const diff = diffResults(plainResults(), next(readOnly));
        expect(diff.attributes).toEqual([
            { discoveredId: BRAVO, attribute: 'bar', from: 'H3', to: 'H2' },
            { discoveredId: BRAVO, attribute: 'reach', from: 'WRITE_OR_EXTERNAL', to: 'READ_ONLY' },
        ]);
        const prev = plainResults();
        const atBar: LocalResults = {
            ...next(),
            agents: next().agents.map((a) => (a.discoveredId === ALPHA && a.judgement.state === 'JUDGED' ? { ...a, judgement: { ...a.judgement, shortfall: false } } : a)),
        };
        expect(diffResults(prev, atBar).attributes).toEqual([{ discoveredId: ALPHA, attribute: 'shortfall', from: 'yes', to: 'no' }]);
        expect(renderDiffText(diffResults(prev, atBar))).toContain(`${ALPHA} shortfall: yes -> no`);
    });
});

describe('orphan credentials', () => {
    const withUnbound = (b: HarnessReportBodyV3): HarnessReportBodyV3 => ({ ...b, unboundCredentials: UNBOUND });

    it('OPENED when the new run concluded one the old did not hold', () => {
        const diff = diffResults(plainResults(), next(withUnbound));
        expect(diff.orphanCredentials).toEqual([{ ref: UNBOUND[0].ref, sourceKind: 'entra-sp', change: 'OPENED', why: null }]);
        // The finding is compared here, not a second time under findings.
        expect(diff.findings).toEqual([]);
        expect(renderDiffText(diff)).toContain(`  opened     ${UNBOUND[0].ref} (entra-sp)`);
    });

    it('CLOSED when its source was read in full and no longer sees it unbound', () => {
        const diff = diffResults(score(withUnbound(standaloneBody())), next());
        expect(diff.orphanCredentials).toEqual([{ ref: UNBOUND[0].ref, sourceKind: 'entra-sp', change: 'CLOSED', why: null }]);
        expect(renderDiffText(diff)).toContain(`  closed     ${UNBOUND[0].ref} (entra-sp)`);
        expect(diffExitCode(diff)).toBe(1);
    });

    it.each([
        ['STILL_SEEN_UNBOUND', (b: HarnessReportBodyV3) => withSource(withUnbound(b), 'entra-sp', 'TIME_BOX')],
        ['SOURCE_INCOMPLETE', (b: HarnessReportBodyV3) => withSource(b, 'entra-sp', 'TIME_BOX')],
        ['SOURCE_ABSENT', (b: HarnessReportBodyV3) => ({ ...b, agents: [], population: { sources: b.population.sources.filter((s) => s.kind !== 'entra-sp') } })],
    ] as const)('NOT_CONCLUDED (%s), never closed, when the new run could not have seen it go', (why, change) => {
        const diff = diffResults(score(withUnbound(standaloneBody())), next(change));
        expect(diff.orphanCredentials).toEqual([{ ref: UNBOUND[0].ref, sourceKind: 'entra-sp', change: 'NOT_CONCLUDED', why }]);
        expect(diff.notConcluded).toContain(`ORPHAN_NOT_CONCLUDED:entra-sp:${UNBOUND[0].ref}`);
        const lines = renderDiffText(diff).split('\n').filter((l) => l.includes(UNBOUND[0].ref));
        expect(lines.some((l) => l.includes(`no longer reported, not concluded   ${UNBOUND[0].ref} (entra-sp)  (${why})`))).toBe(true);
        for (const line of lines) expect(line).not.toMatch(/\bgone\b|\bclosed\b/i);
    });
});

describe('findings close only on positive evidence', () => {
    const changes = (diff: ResultsDiff) => diff.findings.map((f) => [f.code, f.change, f.why]);

    it('a finding the new run raised is OPENED, with its title', () => {
        const diff = diffResults(score(without(BRAVO)(standaloneBody())), next());
        expect(changes(diff)).toEqual([
            ['SHADOW_AGENT', 'OPENED', null],
            ['UNPINNED_WRITE_TOOL', 'OPENED', null],
            ['HARNESS_SHORTFALL', 'OPENED', null],
        ]);
        expect(diff.findings[0]).toMatchObject({ discoveredId: BRAVO, sourceRef: `SHADOW_AGENT:${BRAVO}`, title: `Shadow agent ${BRAVO}` });
    });

    it('an agent\'s findings are not closed by the agent being gone or not seen', () => {
        const gone = diffResults(plainResults(), next(without(BRAVO)));
        expect(changes(gone)).toEqual([
            ['SHADOW_AGENT', 'NOT_CONCLUDED', 'AGENT_GONE'],
            ['UNPINNED_WRITE_TOOL', 'NOT_CONCLUDED', 'AGENT_GONE'],
            ['HARNESS_SHORTFALL', 'NOT_CONCLUDED', 'AGENT_GONE'],
        ]);
        const notSeen = diffResults(plainResults(), next((b) => withSource(without(BRAVO)(b), 'entra-sp', 'TIME_BOX')));
        expect(notSeen.findings.filter((f) => f.discoveredId === BRAVO).map((f) => f.why)).toEqual(['AGENT_NOT_SEEN', 'AGENT_NOT_SEEN', 'AGENT_NOT_SEEN']);
        expect(renderDiffText(gone)).toContain(`no longer reported, not concluded   SHADOW_AGENT SHADOW_AGENT:${BRAVO}  (AGENT_GONE)`);
    });

    it('a shortfall is CLOSED for a judged agent, and not concluded for one that is no longer judged', () => {
        const base = next();
        const dropShortfall = (r: LocalResults): LocalResults => ({ ...r, findings: r.findings.filter((f) => !(f.code === 'HARNESS_SHORTFALL' && f.discoveredId === ALPHA)) });
        expect(changes(diffResults(plainResults(), dropShortfall(base)))).toEqual([['HARNESS_SHORTFALL', 'CLOSED', null]]);
        // The planner drops the shortfall of an agent it cannot judge: that closes nothing.
        const notJudged = diffResults(plainResults(), next((b) => withSource(b, 'entra-sp', 'TIME_BOX')));
        expect(notJudged.findings.filter((f) => f.code === 'HARNESS_SHORTFALL').map((f) => [f.change, f.why])).toEqual([
            ['NOT_CONCLUDED', 'AGENT_NOT_JUDGED'],
            ['NOT_CONCLUDED', 'AGENT_NOT_JUDGED'],
        ]);
    });

    it('a shadow finding is closed by a declared registration only on a complete scan, and by a register link on any', () => {
        const declared = diffResults(plainResults(), score(laterBody(), true));
        expect(declared.findings.filter((f) => f.code === 'SHADOW_AGENT')).toEqual([expect.objectContaining({ discoveredId: ALPHA, change: 'CLOSED' })]);
        const partial = diffResults(plainResults(), score(laterBody((b) => withSource(b, 'mcp', 'TIME_BOX')), true));
        expect(partial.findings.find((f) => f.code === 'SHADOW_AGENT')).toMatchObject({ change: 'NOT_CONCLUDED', why: 'SCAN_INCOMPLETE' });

        const strip = (r: LocalResults, basis: 'NONE' | 'OBSERVED_REGISTER'): LocalResults => ({
            ...r,
            agents: r.agents.map((a) => (a.discoveredId === ALPHA ? { ...a, registration: { basis, ref: basis === 'NONE' ? null : 'agt_alpha' } } : a)),
            findings: r.findings.filter((f) => !(f.code === 'SHADOW_AGENT' && f.discoveredId === ALPHA)),
        });
        const incomplete = next((b) => withSource(b, 'mcp', 'TIME_BOX'));
        expect(diffResults(plainResults(), strip(incomplete, 'OBSERVED_REGISTER')).findings.find((f) => f.code === 'SHADOW_AGENT')).toMatchObject({ change: 'CLOSED' });
        expect(diffResults(plainResults(), strip(next(), 'NONE')).findings.find((f) => f.code === 'SHADOW_AGENT')).toMatchObject({
            change: 'NOT_CONCLUDED',
            why: 'AGENT_NOT_REGISTERED',
        });
    });

    it('an unpinned-tool finding is closed only when every source was read in full', () => {
        const pinned = (b: HarnessReportBodyV3): HarnessReportBodyV3 => ({
            ...b,
            agents: b.agents.map((a) => (a.discoveredId === BRAVO ? { ...a, tools: a.tools.map((t) => ({ ...t, pinned: true, manifestHash: HASH })) } : a)),
        });
        expect(diffResults(plainResults(), next(pinned)).findings).toEqual([expect.objectContaining({ code: 'UNPINNED_WRITE_TOOL', change: 'CLOSED' })]);
        const dropped = (r: LocalResults): LocalResults => ({ ...r, findings: r.findings.filter((f) => f.code !== 'UNPINNED_WRITE_TOOL') });
        const partial = diffResults(plainResults(), dropped(next((b) => withSource(b, 'mcp', 'TIME_BOX'))));
        expect(partial.findings.find((f) => f.code === 'UNPINNED_WRITE_TOOL')).toMatchObject({ change: 'NOT_CONCLUDED', why: 'SCAN_INCOMPLETE' });
    });

    it('EMPTY_SCAN closes when the new run found agents', () => {
        const diff = diffResults(score({ ...standaloneBody(), agents: [] }), next());
        expect(diff.findings.find((f) => f.code === 'EMPTY_SCAN')).toMatchObject({ change: 'CLOSED', discoveredId: null });
        expect(diff.agents.added).toEqual([ALPHA, BRAVO]);
    });

    it('INCOMPLETE_SOURCE closes when that source is read in full, and not when it is no longer listed', () => {
        const before = score(withSource(standaloneBody(), 'mcp', 'TIME_BOX'));
        expect(diffResults(before, next()).findings.find((f) => f.code === 'INCOMPLETE_SOURCE')).toMatchObject({ change: 'CLOSED' });
        const unlisted = next((b) => ({ ...b, population: { sources: b.population.sources.filter((s) => s.kind !== 'mcp') } }));
        expect(diffResults(before, unlisted).findings.find((f) => f.code === 'INCOMPLETE_SOURCE')).toMatchObject({ change: 'NOT_CONCLUDED', why: 'SOURCE_ABSENT' });
        const still: LocalResults = { ...next((b) => withSource(b, 'mcp', 'TIME_BOX')) };
        const dropped: LocalResults = { ...still, findings: still.findings.filter((f) => f.code !== 'INCOMPLETE_SOURCE') };
        expect(diffResults(before, dropped).findings.find((f) => f.code === 'INCOMPLETE_SOURCE')).toMatchObject({ change: 'NOT_CONCLUDED', why: 'SOURCE_INCOMPLETE' });
    });

    it('a finding about the scan, of a kind with no rule of its own, closes only on a complete scan', () => {
        const prev = plainResults();
        const extra: LocalResults = {
            ...prev,
            findings: [...prev.findings, { code: 'LEVEL_DROP', sourceRef: 'LEVEL_DROP:x', severity: 'LOW', type: 'OBSERVATION', discoveredId: null, title: 't', description: 'd' }],
        };
        expect(diffResults(extra, next()).findings).toEqual([expect.objectContaining({ sourceRef: 'LEVEL_DROP:x', change: 'CLOSED' })]);
        expect(diffResults(extra, next((b) => withSource(b, 'mcp', 'TIME_BOX'))).findings.find((f) => f.sourceRef === 'LEVEL_DROP:x')).toMatchObject({
            change: 'NOT_CONCLUDED',
            why: 'SCAN_INCOMPLETE',
        });
        const empty: LocalResults = { ...extra, findings: [{ ...extra.findings[extra.findings.length - 1], code: 'EMPTY_SCAN', sourceRef: 'EMPTY_SCAN:x' }] };
        const stillEmpty: LocalResults = { ...next((b) => ({ ...b, agents: [] })), findings: [] };
        expect(diffResults(empty, stillEmpty).findings).toEqual([expect.objectContaining({ change: 'NOT_CONCLUDED', why: 'NO_AGENTS' })]);
    });
});

describe('review: what a run could not have shown closes nothing', () => {
    const noTools = (b: HarnessReportBodyV3): HarnessReportBodyV3 => ({ ...b, agents: b.agents.map((a) => ({ ...a, tools: [] })) });
    const onlyEntra = (b: HarnessReportBodyV3): HarnessReportBodyV3 => ({ ...b, population: { sources: b.population.sources.filter((s) => s.kind === 'entra-sp') } });

    it('an unpinned-tool finding is not closed by a complete run that no longer lists the source its tools were read from', () => {
        const dropped = next((b) => onlyEntra(noTools(b)));
        // The run is complete: every source it lists was read in full. `mcp` is not one of them.
        expect(dropped.scan.complete).toBe(true);
        const diff = diffResults(plainResults(), dropped);
        expect(diff.findings.find((f) => f.code === 'UNPINNED_WRITE_TOOL')).toMatchObject({ discoveredId: BRAVO, change: 'NOT_CONCLUDED', why: 'SOURCE_ABSENT' });
        expect(diff.notConcluded).toContain(`FINDING_NOT_CONCLUDED:UNPINNED_WRITE_TOOL:${BRAVO}`);
        const text = renderDiffText(diff);
        expect(text).toContain(`no longer reported, not concluded   UNPINNED_WRITE_TOOL UNPINNED_WRITE_TOOL:${BRAVO}  (SOURCE_ABSENT)`);
        expect(text).not.toMatch(/closed +UNPINNED_WRITE_TOOL/);
        // With `mcp` listed and read in full, the same absence is evidence.
        expect(diffResults(plainResults(), next(noTools)).findings.find((f) => f.code === 'UNPINNED_WRITE_TOOL')).toMatchObject({ change: 'CLOSED' });
    });

    it('a tool defined in code is judged by the code source, and one served over MCP is not closed by it', () => {
        const viaCode = (b: HarnessReportBodyV3): HarnessReportBodyV3 => ({
            ...b,
            population: { sources: [{ kind: 'code', status: 'COMPLETE', rows: 2 }] },
            // A `code://` server is a tool the agent's code defines: the `code` read is its evidence.
            agents: b.agents.map((a) => ({ ...a, discoveredVia: ['code'], tools: a.tools.map((t) => ({ ...t, server: `code://example/agent.py#${t.name}` })) })),
        });
        const before = score(viaCode(standaloneBody()));
        expect(before.findings.some((f) => f.code === 'UNPINNED_WRITE_TOOL')).toBe(true);
        const closed = diffResults(before, next((b) => noTools(viaCode(b))));
        expect(closed.findings.find((f) => f.code === 'UNPINNED_WRITE_TOOL')).toMatchObject({ change: 'CLOSED' });
        // The agent was found through `entra-sp` before: where its tools were is `mcp`, in either run.
        const moved = diffResults(plainResults(), next((b) => noTools(viaCode(b))));
        expect(moved.findings.find((f) => f.code === 'UNPINNED_WRITE_TOOL')).toMatchObject({ change: 'NOT_CONCLUDED', why: 'SOURCE_ABSENT' });
    });

    describe('tool-evidence sources: an unpinned write tool is closed only on the sources its tools were read from', () => {
        /** Found only in code, holding one tool served over MCP: the case `discoveredVia` cannot see. */
        const codeAgentWithMcpTool = (b: HarnessReportBodyV3): HarnessReportBodyV3 => ({
            ...b,
            population: { sources: [{ kind: 'code', status: 'COMPLETE', rows: 2 }, { kind: 'mcp', status: 'COMPLETE', rows: 1 }] },
            agents: b.agents.map((a) => ({ ...a, discoveredVia: ['code'] })),
        });
        const onlyCode = (b: HarnessReportBodyV3): HarnessReportBodyV3 => ({ ...b, population: { sources: [{ kind: 'code', status: 'COMPLETE', rows: 2 }] } });
        const stripMember = (r: LocalResults): LocalResults => ({ ...r, agents: r.agents.map(({ toolEvidenceSources: _dropped, ...a }) => a) });
        const unpinned = (d: ResultsDiff) => d.findings.find((f) => f.code === 'UNPINNED_WRITE_TOOL');

        it('a code-found agent with an https tool, whose new run lists only code, is not closed', () => {
            const before = score(codeAgentWithMcpTool(standaloneBody()));
            expect(before.agents.find((a) => a.discoveredId === BRAVO)?.toolEvidenceSources).toEqual(['code', 'mcp']);
            // The new run read `code` in full and reports no tool. It did not read `mcp`, where the tool was.
            const after = next((b) => onlyCode(noTools(codeAgentWithMcpTool(b))));
            expect(after.scan.complete).toBe(true);
            expect(after.agents.find((a) => a.discoveredId === BRAVO)?.toolEvidenceSources).toEqual(['code']);
            const diff = diffResults(before, after);
            expect(unpinned(diff)).toMatchObject({ change: 'NOT_CONCLUDED', why: 'SOURCE_ABSENT' });
            expect(diff.warnings).not.toContain(TOOL_EVIDENCE_OLDER_RULE);
        });

        it('with the member on both sides and every listed source read in full, it is closed, with no warning', () => {
            const before = score(codeAgentWithMcpTool(standaloneBody()));
            const diff = diffResults(before, next((b) => noTools(codeAgentWithMcpTool(b))));
            expect(unpinned(diff)).toMatchObject({ change: 'CLOSED', why: null });
            expect(diff.warnings).toEqual([]);
        });

        it('a listed tool-evidence source that was not read in full closes nothing', () => {
            const before = score(codeAgentWithMcpTool(standaloneBody()));
            const partial = next((b) => withSource(noTools(codeAgentWithMcpTool(b)), 'mcp', 'TIME_BOX'));
            const dropped: LocalResults = { ...partial, findings: partial.findings.filter((f) => f.code !== 'UNPINNED_WRITE_TOOL') };
            expect(unpinned(diffResults(before, dropped))).toMatchObject({ change: 'NOT_CONCLUDED', why: 'SCAN_INCOMPLETE' });
        });

        it('an older file on one side is decided on the older rule, and the diff says so', () => {
            // The old file predates the member. What it records about the agent is `discoveredVia: [code]`,
            // so the older rule asks for `code` alone; the new side still asks for what it lists.
            const before = stripMember(score(codeAgentWithMcpTool(standaloneBody())));
            const closedOnOlderRule = diffResults(before, next((b) => onlyCode(noTools(codeAgentWithMcpTool(b)))));
            expect(unpinned(closedOnOlderRule)).toMatchObject({ change: 'CLOSED' });
            expect(closedOnOlderRule.warnings).toEqual([TOOL_EVIDENCE_OLDER_RULE]);
            expect(renderDiffText(closedOnOlderRule)).toContain(`${TOOL_EVIDENCE_OLDER_RULE}: one results file was written before agents carried their tool-evidence sources`);
            // The newer side's own list is still held: a new run that lists an `mcp` tool source needs `mcp` read.
            const newerStillHeld = diffResults(stripMember(plainResults()), next((b) => onlyEntra(noTools(b))));
            expect(unpinned(newerStillHeld)).toMatchObject({ change: 'NOT_CONCLUDED', why: 'SOURCE_ABSENT' });
            expect(newerStillHeld.warnings).toEqual([TOOL_EVIDENCE_OLDER_RULE]);
        });

        it('two older files decide exactly as before the member existed, once warned', () => {
            const older = diffResults(stripMember(plainResults()), stripMember(next(noTools)));
            expect(unpinned(older)).toMatchObject({ change: 'CLOSED' });
            expect(older.warnings).toEqual([TOOL_EVIDENCE_OLDER_RULE]);
            // No such finding to decide: nothing fell back, so nothing is warned.
            expect(diffResults(stripMember(plainResults()), stripMember(next())).warnings).toEqual([]);
        });
    });

    it('an empty new run shows no agent as gone and closes no orphan credential, whatever it says it read', () => {
        const withOrphan = score({ ...standaloneBody(), unboundCredentials: UNBOUND });
        const empty = next((b) => ({ ...b, agents: [] }));
        expect(empty.scan.complete).toBe(true);
        const diff = diffResults(withOrphan, empty);
        expect(diff.agents.gone).toEqual([]);
        expect(diff.agents.notSeen).toEqual([
            { discoveredId: ALPHA, unread: [], differentScanner: false, differentEstate: false, newScanEmpty: true },
            { discoveredId: BRAVO, unread: [], differentScanner: false, differentEstate: false, newScanEmpty: true },
        ]);
        expect(diff.notConcluded).toEqual(expect.arrayContaining([`AGENT_NOT_SEEN:${ALPHA}`, `AGENT_NOT_SEEN:${BRAVO}`]));
        expect(diff.orphanCredentials).toEqual([{ ...UNBOUND[0], change: 'NOT_CONCLUDED', why: 'NEW_SCAN_EMPTY' }]);
        expect(diff.findings.find((f) => f.code === 'EMPTY_SCAN')).toMatchObject({ change: 'OPENED' });
        expect(diff.findings.every((f) => f.change !== 'CLOSED')).toBe(true);
        const text = renderDiffText(diff);
        expect(text).toContain(`not seen   ${BRAVO}  (the new run found no agent at all; nothing is concluded)`);
        expect(text).not.toMatch(/\bgone\b|\bclosed\b/);
    });

    it('two estates under one scanner id are compared with a warning, and nothing absent is concluded', () => {
        const renamed = (b: HarnessReportBodyV3): HarnessReportBodyV3 => ({ ...b, agents: b.agents.map((a) => ({ ...a, discoveredId: `${a.discoveredId}-other` })) });
        const elsewhere = scoreReportLocally(input(laterBody(renamed), { meta: { ...META, estate: 'other-estate' } }));
        const withOrphan = score({ ...standaloneBody(), unboundCredentials: UNBOUND });
        const diff = diffResults(withOrphan, elsewhere);
        expect(diff.warnings).toEqual(['ESTATE_DIFFERS']);
        expect(diff.agents.gone).toEqual([]);
        expect(diff.agents.notSeen.map((a) => [a.discoveredId, a.differentEstate])).toEqual([[ALPHA, true], [BRAVO, true]]);
        expect(diff.orphanCredentials).toEqual([expect.objectContaining({ change: 'NOT_CONCLUDED', why: 'DIFFERENT_ESTATE' })]);
        expect(diff.findings.filter((f) => f.change !== 'OPENED').map((f) => [f.change, f.why])).toEqual(
            withOrphan.findings.filter((f) => f.code !== 'ORPHAN_CREDENTIAL').map(() => ['NOT_CONCLUDED', 'DIFFERENT_ESTATE']),
        );
        const text = renderDiffText(diff);
        expect(text).toContain('ESTATE_DIFFERS: the two runs name different estates, so nothing absent from the new run is concluded');
        expect(text).toContain(`not seen   ${ALPHA}  (the runs name different estates; nothing is concluded)`);
        // A side with no estate label (a signed report) says nothing about which estate it is: no warning.
        const unlabelled = scoreReportLocally(input(laterBody(), { meta: { ...META, estate: null } }));
        expect(diffResults(plainResults(), unlabelled).warnings).toEqual([]);
    });

    it('completeness is read from the sources, not from the stored flag', () => {
        const partial = next((b) => withSource(b, 'mcp', 'TIME_BOX'));
        const dropped: LocalResults = { ...partial, findings: partial.findings.filter((f) => f.code !== 'UNPINNED_WRITE_TOOL') };
        const lying: LocalResults = { ...dropped, scan: { ...dropped.scan, complete: true } };
        const diff = diffResults(plainResults(), lying);
        expect(diff.new.complete).toBe(false);
        expect(diff.notConcluded).toContain('SCAN_INCOMPLETE:new');
        expect(diff.findings.find((f) => f.code === 'UNPINNED_WRITE_TOOL')).toMatchObject({ change: 'NOT_CONCLUDED', why: 'SCAN_INCOMPLETE' });
    });
});

describe('review: a diff is read on a terminal', () => {
    const NASTY = 'evil\u001b[2J\u001b[31mRED\u0007\nscanent diff: No difference, and every comparison could be made.\r\u009b31m\u202etxt\u2028x';

    it('a control character in an id, a finding reference or a credential reference is shown, never sent', () => {
        const rename = (r: LocalResults): LocalResults => ({
            ...r,
            agents: r.agents.map((a) => (a.discoveredId === BRAVO ? { ...a, discoveredId: NASTY } : a)),
            findings: [...r.findings, { code: 'LEVEL_DROP', sourceRef: `LEVEL_DROP:${NASTY}`, severity: 'LOW', type: 'OBSERVATION', discoveredId: null, title: NASTY, description: NASTY }],
            estate: { ...r.estate, orphanCredentials: [{ ref: NASTY, sourceKind: 'entra-sp' }] },
        });
        const clean = diffResults(plainResults(), next());
        const diff = diffResults(plainResults(), rename(next()));
        const text = renderDiffText(diff);
        // No control, line-separator or bidirectional character but the line feeds scanent wrote.
        expect(text).not.toMatch(/[^\P{Cc}\n]|[\u2028\u2029\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u);
        const lines = text.split('\n');
        expect(lines.filter((l) => l.startsWith('scanent diff:'))).toEqual(['scanent diff: The two runs differ.']);
        // One line per entry: the id's own line feed adds none.
        const entries = 1 + diff.agents.notSeen.length + diff.orphanCredentials.length + diff.findings.length + diff.notConcluded.length;
        expect(lines.filter((l) => l.includes('evil'))).toHaveLength(entries);
        expect(lines.length).toBeGreaterThan(renderDiffText(clean).split('\n').length);
        // What was there can still be read.
        expect(text).toContain('new        evil\\u{1b}[2J\\u{1b}[31mRED\\u{7}\\u{a}scanent diff: No difference, and every comparison could be made.\\u{d}\\u{9b}31m\\u{202e}txt\\u{2028}x');

        // As JSON the value is the same, and no raw control reaches the terminal.
        const json = terminalJson(stableJson(diff));
        expect(json).not.toMatch(/[^\P{Cc}\n]|[\u2028\u2029\u202a-\u202e]/u);
        expect(JSON.parse(json)).toEqual(diff);
        expect(json).toContain('\\u009b31m\\u202etxt\\u2028x');
        // Text with nothing to escape is unchanged.
        expect(terminalJson(stableJson(clean))).toBe(stableJson(clean));
        expect(terminalLine('agent ü — 名')).toBe('agent ü — 名');
    });
});

describe('what may not be compared', () => {
    it.each([
        ['the new scan is not later', plainResults(), plainResults(), {}, 'NOT_LATER'],
        ['the runs are in the wrong order', next(), plainResults(), {}, 'NOT_LATER'],
        ['a time cannot be read', plainResults(), { ...next(), scan: { ...next().scan, asOf: 'yesterday' } }, {}, 'NOT_LATER'],
        ['the ladder versions differ', plainResults(), { ...next(), ladder: { ...next().ladder, version: `sha256:${'0'.repeat(64)}` } }, {}, 'LADDER_DIFFERS'],
        ['the scanners differ', plainResults(), { ...next(), scan: { ...next().scan, scanner: { ...next().scan.scanner, agentId: 'agt_other' } } }, {}, 'SCANNER_DIFFERS'],
    ] as const)('refuses when %s', (_label, a, b, opts, reason) => {
        let thrown: unknown;
        try {
            diffResults(a as LocalResults, b as LocalResults, opts);
        } catch (err) {
            thrown = err;
        }
        expect(thrown).toBeInstanceOf(DiffRefused);
        expect((thrown as DiffRefused).reason).toBe(reason);
        expect((thrown as DiffRefused).message.length).toBeGreaterThan(20);
    });

    it('different scanners, when allowed, conclude nothing from an absence', () => {
        const other: LocalResults = { ...next(without(BRAVO)), scan: { ...next().scan, scanner: { ...next().scan.scanner, agentId: 'agt_other' } } };
        const withOrphan = score({ ...standaloneBody(), unboundCredentials: UNBOUND });
        const diff = diffResults(withOrphan, other, { allowDifferentScanner: true });
        expect(diff.warnings).toContain('SCANNER_DIFFERS');
        expect(diff.agents.gone).toEqual([]);
        expect(diff.agents.notSeen).toEqual([{ discoveredId: BRAVO, unread: [], differentScanner: true, differentEstate: false, newScanEmpty: false }]);
        expect(diff.orphanCredentials).toEqual([expect.objectContaining({ change: 'NOT_CONCLUDED', why: 'DIFFERENT_SCANNER' })]);
        expect(diff.findings.every((f) => f.change !== 'CLOSED')).toBe(true);
        expect(diff.findings.filter((f) => f.change === 'NOT_CONCLUDED').every((f) => f.why === 'DIFFERENT_SCANNER')).toBe(true);
        const text = renderDiffText(diff);
        expect(text).toContain('the runs are from different scanners; nothing is concluded');
        expect(text).toContain('SCANNER_DIFFERS: the two runs are from different scanners');
    });
});

describe('what each side rests on', () => {
    it('warns when a signer was not pinned or register claims were not verified, and names the side', () => {
        const bare = scoreReportLocally(
            input(laterBody(), { meta: { ...META, estate: null, registerClaimsVerified: false, report: { ...META.report, signerPinned: false } } }),
        );
        const diff = diffResults(plainResults(), bare);
        expect(diff.warnings).toEqual(['SIGNER_NOT_PINNED:new', 'REGISTER_CLAIMS_NOT_VERIFIED:new']);
        expectNothing(diff);
        const text = renderDiffText(diff);
        expect(text).toContain('SIGNER_NOT_PINNED:new: new run: the signed report was verified against the key it carries itself');
        expect(text).toContain('signer not pinned');
    });

    it('the object is plain JSON, and the same pair gives the same text', () => {
        const diff = diffResults(plainResults(), next(without(BRAVO)));
        expect(JSON.parse(stableJson(diff))).toEqual(diff);
        expect(renderDiffText(diffResults(plainResults(), next(without(BRAVO))))).toBe(renderDiffText(diff));
        expect(stableJson(diffResults(plainResults(), next(without(BRAVO))))).toBe(stableJson(diff));
    });

    it('counts one difference and one comparison in the singular', () => {
        const diff = diffResults(score(withSource(standaloneBody(), 'mcp', 'TIME_BOX')), next((b) => withSource(b, 'mcp', 'AUTH_FAILED')));
        expect(renderDiffText(diff)).toContain('1 difference; ');
        const one: ResultsDiff = { ...diff, summary: { differences: 1, notConcluded: 1 } };
        expect(renderDiffText(one)).toContain('1 difference; 1 comparison not concluded.');
        expect(renderDiffText({ ...diff, old: { ...diff.old, agentCount: 1 }, warnings: ['SOMETHING_NEW'] })).toMatch(/1 agent,[\s\S]*SOMETHING_NEW: see the code/);
    });
});

/** A body like `laterBody`'s at a time of the caller's choosing. */
function laterBodyAt(asOf: string, change: (b: HarnessReportBodyV3) => HarnessReportBodyV3): HarnessReportBodyV3 {
    const body = standaloneBody();
    return change({ ...body, scan: { ...body.scan, asOf } });
}
