/**
 * The operator's inventory.
 *
 *   1. A whole, valid inventory parses, in file order, with where it came from.
 *   2. Every refusal names the row and the field, and never the value.
 *   3. A secret-shaped value is refused before the schema runs.
 *   4. A matched row declares the four H1 criteria, and nothing else.
 *   5. A declared risk tier is fresh for 365 days up to the scan, and not after it.
 */
import { MAX_AGENTS, MAX_ID_CHARS } from '@scanent/contract/harness-contract';
import { ALL_HARNESS_CRITERIA } from '@scanent/contract/harness-ladder';

import {
    dayNumberOf,
    declaredVerdicts,
    INVENTORY_CRITERIA,
    INVENTORY_SCHEMA_ID,
    INVENTORY_TIER_MAX_AGE_DAYS,
    InventoryRefused,
    inventoryEvidence,
    inventoryRegistrationRef,
    isTierFresh,
    MAX_INVENTORY_ROWS,
    parseInventory,
} from '../src/results/inventory';
import { ALPHA, AS_OF, BRAVO, fullRow, INVENTORY_SHA, inventoryJson, inventoryOf } from './helpers/fixtures';

const SOURCE = { sha256: INVENTORY_SHA, format: 'json' as const };

/** The issues a refused inventory names. Fails if it was not refused. */
function refusal(decoded: unknown, source = SOURCE): readonly string[] {
    try {
        parseInventory(decoded, source);
    } catch (err) {
        expect(err).toBeInstanceOf(InventoryRefused);
        expect((err as InventoryRefused).message).toBe(`invalid inventory: ${(err as InventoryRefused).issues.join('; ')}`);
        return (err as InventoryRefused).issues;
    }
    throw new Error('expected the inventory to be refused');
}

describe('1. a valid inventory', () => {
    it('parses in file order, with its hash and format', () => {
        const parsed = parseInventory(inventoryJson([fullRow(BRAVO), fullRow(ALPHA, { name: 'Alpha' })]), { sha256: INVENTORY_SHA, format: 'csv' });
        expect(parsed.sha256).toBe(INVENTORY_SHA);
        expect(parsed.format).toBe('csv');
        expect(parsed.rows.map((r) => r.discoveredId)).toEqual([BRAVO, ALPHA]);
        expect(parsed.rows[1]).toEqual(fullRow(ALPHA, { name: 'Alpha' }));
    });

    it('needs only the four required fields', () => {
        const parsed = inventoryOf([{ discoveredId: ALPHA, name: 'A', owner: 'o', purpose: 'p' }]);
        expect(parsed.rows[0]).toEqual({ discoveredId: ALPHA, name: 'A', owner: 'o', purpose: 'p' });
    });

    it('may be empty: an operator who knows no agent says so', () => {
        expect(inventoryOf([]).rows).toEqual([]);
    });

    it('takes fields at their longest, and an id as long as the contract allows', () => {
        const longest = fullRow('x'.repeat(MAX_ID_CHARS), { name: 'n'.repeat(256), owner: 'o'.repeat(256), purpose: 'p'.repeat(512) });
        expect(inventoryOf([longest]).rows).toHaveLength(1);
    });

    it('takes as many rows as a report takes agents', () => {
        expect(MAX_INVENTORY_ROWS).toBe(MAX_AGENTS);
        const rows = Array.from({ length: MAX_INVENTORY_ROWS }, (_, i) => ({ discoveredId: `a:${i}`, name: 'n', owner: 'o', purpose: 'p' }));
        expect(inventoryOf(rows).rows).toHaveLength(MAX_INVENTORY_ROWS);
    });

    it('takes names that are not ASCII', () => {
        expect(inventoryOf([fullRow(ALPHA, { owner: 'Финансови операции', name: 'Фактури' })]).rows[0].owner).toBe('Финансови операции');
    });
});

describe('2. a refusal names the row and the field', () => {
    const VALUE = 'zz-the-refused-value-zz';

    it.each([
        ['an unknown key on a row', [fullRow(ALPHA), fullRow(BRAVO, { [VALUE]: 1 })], ['row 2: 1 unknown field']],
        ['two unknown keys on a row', [fullRow(ALPHA, { extra: 1, [VALUE]: 2 })], ['row 1: 2 unknown fields']],
        ['a missing name', [{ discoveredId: ALPHA, owner: 'o', purpose: 'p' }], ['row 1: name: invalid_type']],
        ['a missing owner', [fullRow(ALPHA), { discoveredId: BRAVO, name: 'n', purpose: 'p' }], ['row 2: owner: invalid_type']],
        ['a missing purpose', [{ discoveredId: ALPHA, name: 'n', owner: 'o' }], ['row 1: purpose: invalid_type']],
        ['a missing id', [{ name: 'n', owner: 'o', purpose: 'p' }], ['row 1: discoveredId: invalid_type']],
        ['an empty id', [fullRow('')], ['row 1: discoveredId: too_small']],
        ['an over-long id', [fullRow(VALUE.repeat(20))], ['row 1: discoveredId: too_big']],
        ['an over-long name', [fullRow(ALPHA, { name: VALUE.repeat(20) })], ['row 1: name: too_big']],
        ['an over-long owner', [fullRow(ALPHA, { owner: VALUE.repeat(20) })], ['row 1: owner: too_big']],
        ['an over-long purpose', [fullRow(ALPHA, { purpose: VALUE.repeat(30) })], ['row 1: purpose: too_big']],
        ['a control character in a name', [fullRow(ALPHA, { name: `${VALUE}\u0007` })], ['row 1: name: a control character']],
        ['a line break in an owner', [fullRow(ALPHA, { owner: `${VALUE}\nsecond` })], ['row 1: owner: a control character']],
        ['a DEL in a purpose', [fullRow(ALPHA, { purpose: `${VALUE}\u007f` })], ['row 1: purpose: a control character']],
        ['a blank owner', [fullRow(ALPHA, { owner: '   ' })], ['row 1: owner: blank']],
        ['a name that is not text', [fullRow(ALPHA, { name: 7 as unknown as string })], ['row 1: name: invalid_type']],
        ['half an axes', [fullRow(ALPHA, { axes: { autonomy: 'autonomous', reach: 'write' } })], ['row 1: axes.dataClass: invalid_value']],
        ['an axis value off its list', [fullRow(ALPHA, { axes: { autonomy: VALUE, dataClass: 'public', reach: 'write' } })], ['row 1: axes.autonomy: invalid_value']],
        ['an unknown axis', [fullRow(ALPHA, { axes: { autonomy: 'autonomous', dataClass: 'public', reach: 'write', [VALUE]: 1 } })], ['row 1: axes: 1 unknown field']],
        ['a tier without its date', [fullRow(ALPHA, { riskAssessedOn: undefined })], ['row 1: riskAssessedOn: a risk tier and the date it was assessed come together or not at all']],
        ['a date without its tier', [fullRow(ALPHA, { riskTier: undefined })], ['row 1: riskTier: a risk tier and the date it was assessed come together or not at all']],
        ['a tier off its list', [fullRow(ALPHA, { riskTier: VALUE })], ['row 1: riskTier: invalid_value']],
        ['a date that is not one', [fullRow(ALPHA, { riskAssessedOn: '2026-02-30' })], ['row 1: riskAssessedOn: not a YYYY-MM-DD date']],
        ['a date in another form', [fullRow(ALPHA, { riskAssessedOn: '30/09/2026' })], ['row 1: riskAssessedOn: not a YYYY-MM-DD date']],
        ['a date with a time', [fullRow(ALPHA, { riskAssessedOn: '2026-09-30T00:00:00Z' })], ['row 1: riskAssessedOn: not a YYYY-MM-DD date']],
        ['a duplicate id', [fullRow(ALPHA), fullRow(BRAVO), fullRow(ALPHA)], ['row 3: discoveredId: a discoveredId appears once']],
    ])('%s', (_label, rows, expected) => {
        const issues = refusal(inventoryJson(rows as unknown[]));
        expect(issues).toEqual(expected);
        expect(issues.join(' ')).not.toContain(VALUE);
    });

    it('names every row at fault, not only the first', () => {
        const issues = refusal(inventoryJson([fullRow(ALPHA, { name: '' }), fullRow(BRAVO), fullRow('c', { owner: '' })]));
        expect(issues).toEqual(['row 1: name: too_small', 'row 1: name: blank', 'row 3: owner: too_small', 'row 3: owner: blank']);
    });

    it.each([
        ['more rows than a report has agents', { inventory: INVENTORY_SCHEMA_ID, agents: Array.from({ length: MAX_INVENTORY_ROWS + 1 }, (_, i) => fullRow(`a:${i}`)) }, ['agents: too_big']],
        ['a wrong inventory id', { inventory: 'scanent-inventory/2', agents: [] }, ['inventory: invalid_value']],
        ['no inventory id', { agents: [] }, ['inventory: invalid_value']],
        ['no agents member', { inventory: INVENTORY_SCHEMA_ID }, ['agents: invalid_type']],
        ['an unknown key at the top', { inventory: INVENTORY_SCHEMA_ID, agents: [], [VALUE]: true }, ['(file): 1 unknown field']],
        ['a list where the file should be an object', [fullRow(ALPHA)], ['(file): invalid_type']],
        ['a row that is not an object', { inventory: INVENTORY_SCHEMA_ID, agents: ['text'] }, ['row 1: invalid_type']],
        ['nothing', null, ['(file): invalid_type']],
    ])('refuses %s', (_label, decoded, expected) => {
        const issues = refusal(decoded);
        expect(issues).toEqual(expected);
        expect(issues.join(' ')).not.toContain(VALUE);
    });

    it('refuses a hash that is not one, whatever the file holds', () => {
        expect(refusal(inventoryJson([]), { sha256: 'not-a-hash', format: 'json' })).toEqual(['(file): the hash of its bytes is not a SHA-256']);
    });
});

describe('3. a secret-shaped value', () => {
    // Built from parts, so this file holds no secret-shaped literal.
    const canary = ['gh', 'p_', 'Q'.repeat(36)].join('');
    const urlCanary = ['https', '://', 'user', ':', 'hunter2-pass', '@', 'db.example'].join('');

    it.each([
        ['a name', [fullRow(ALPHA), fullRow(BRAVO, { name: canary })], 'row 2: name: a credential value in the inventory'],
        ['an owner', [fullRow(ALPHA, { owner: `team ${canary}` })], 'row 1: owner: a credential value in the inventory'],
        ['a purpose', [fullRow(ALPHA, { purpose: urlCanary })], 'row 1: purpose: a credential value in the inventory'],
        ['an id', [fullRow(canary)], 'row 1: discoveredId: a credential value in the inventory'],
        ['an axis', [fullRow(ALPHA, { axes: { autonomy: canary } })], 'row 1: axes.autonomy: a credential value in the inventory'],
        ['a member the schema does not know', [fullRow(ALPHA, { note: canary })], 'row 1: note: a credential value in the inventory'],
    ])('in %s is refused by path, before the schema', (_label, rows, expected) => {
        const issues = refusal(inventoryJson(rows as unknown[]));
        // One issue only: the schema, which would have added its own, never ran.
        expect(issues).toEqual([expected]);
        expect(issues.join(' ')).not.toContain(canary);
        expect(issues.join(' ')).not.toContain('hunter2');
    });

    it('is refused where it is not in a row at all', () => {
        expect(refusal({ inventory: canary, agents: [] })).toEqual(['inventory: a credential value in the inventory']);
        expect(refusal(canary)).toEqual(['(file): a credential value in the inventory']);
        expect(refusal({ inventory: INVENTORY_SCHEMA_ID, agents: [canary] })).toEqual(['row 1: a credential value in the inventory']);
    });
});

describe('4. what a matched row declares', () => {
    const inventory = { sha256: INVENTORY_SHA };

    it('is the four H1 criteria, each met, with the row as evidence', () => {
        const row = inventoryOf([fullRow(ALPHA)]).rows[0];
        const verdicts = declaredVerdicts(row, 7, inventory, AS_OF);
        expect(verdicts).toEqual(
            INVENTORY_CRITERIA.map((criterion) => ({ criterion, met: true, evidence: 'inventory:sha256:0123456789abcdef#row-7' })),
        );
    });

    it('names the file by the start of its hash and the row by its number', () => {
        expect(inventoryEvidence(INVENTORY_SHA, 12)).toBe('inventory:sha256:0123456789abcdef#row-12');
        expect(inventoryRegistrationRef(12)).toBe('inventory:row-12');
    });

    it('answers NOT MET, not nothing, for axes the operator did not declare', () => {
        const row = inventoryOf([fullRow(ALPHA, { axes: undefined })]).rows[0];
        const byCriterion = new Map(declaredVerdicts(row, 1, inventory, AS_OF).map((v) => [v.criterion, v.met]));
        expect(byCriterion.get('H1.axes_declared')).toBe(false);
        expect(byCriterion.get('H1.registered')).toBe(true);
        expect(byCriterion.get('H1.owner')).toBe(true);
        expect(byCriterion.get('H1.tier_scored_fresh')).toBe(true);
    });

    it('answers NOT MET for a tier the operator did not declare', () => {
        const row = inventoryOf([fullRow(ALPHA, { riskTier: undefined, riskAssessedOn: undefined })]).rows[0];
        const byCriterion = new Map(declaredVerdicts(row, 1, inventory, AS_OF).map((v) => [v.criterion, v.met]));
        expect(byCriterion.get('H1.tier_scored_fresh')).toBe(false);
    });

    it('never names a criterion above H1, whatever the row holds', () => {
        const above = ALL_HARNESS_CRITERIA.filter((c) => !c.startsWith('H1.'));
        expect(above).toHaveLength(21);
        const rows = [
            fullRow(ALPHA),
            fullRow(BRAVO, { axes: undefined }),
            fullRow('c', { riskTier: 'CRITICAL', riskAssessedOn: '2026-11-03' }),
            { discoveredId: 'd', name: 'H2.policy_card', owner: 'H5.independent_audit', purpose: 'H3.egress_enforced met' },
        ];
        const declared = inventoryOf(rows).rows.flatMap((row, i) => declaredVerdicts(row, i + 1, inventory, AS_OF));
        expect(declared).toHaveLength(16);
        for (const criterion of above) expect(declared.some((v) => v.criterion === criterion)).toBe(false);
        expect([...new Set(declared.map((v) => v.criterion))].sort()).toEqual([...INVENTORY_CRITERIA].sort());
    });

    it('has no field a row could claim a higher criterion with', () => {
        const claim = fullRow(ALPHA, { verdicts: [{ criterion: 'H2.policy_card', met: true, evidence: 'because' }] });
        expect(refusal(inventoryJson([claim]))).toEqual(['row 1: 1 unknown field']);
        expect(refusal(inventoryJson([fullRow(ALPHA, { level: 'H5' })]))).toEqual(['row 1: 1 unknown field']);
    });
});

describe('5. a declared risk tier is fresh for a year up to the scan', () => {
    it('reads a date as its UTC day, and refuses what is not a date', () => {
        expect(dayNumberOf('1970-01-01')).toBe(0);
        expect(dayNumberOf('1970-01-02')).toBe(1);
        expect(dayNumberOf('2024-02-29')).not.toBeNull();
        expect(dayNumberOf('2026-02-29')).toBeNull();
        expect(dayNumberOf('2026-13-01')).toBeNull();
        expect(dayNumberOf('2026-00-10')).toBeNull();
        expect(dayNumberOf('2026-1-1')).toBeNull();
        expect(dayNumberOf('')).toBeNull();
    });

    it('holds the window at 365 days', () => {
        expect(INVENTORY_TIER_MAX_AGE_DAYS).toBe(365);
    });

    it.each([
        ['the day of the scan', '2026-11-03', true],
        ['the day before', '2026-11-02', true],
        ['365 days before', '2025-11-03', true],
        ['366 days before', '2025-11-02', false],
        ['years before', '2019-01-01', false],
        ['the day after the scan', '2026-11-04', false],
        ['a year after', '2027-11-03', false],
    ])('%s', (_label, date, fresh) => {
        expect(isTierFresh(date, AS_OF)).toBe(fresh);
        const row = inventoryOf([fullRow(ALPHA, { riskAssessedOn: date })]).rows[0];
        const tier = declaredVerdicts(row, 1, { sha256: INVENTORY_SHA }, AS_OF).find((v) => v.criterion === 'H1.tier_scored_fresh');
        expect(tier?.met).toBe(fresh);
    });

    it('counts by the scan\'s own UTC day, at either end of it', () => {
        expect(isTierFresh('2026-11-03', '2026-11-03T00:00:00.000Z')).toBe(true);
        expect(isTierFresh('2026-11-03', '2026-11-03T23:59:59.999Z')).toBe(true);
        expect(isTierFresh('2026-11-04', '2026-11-03T23:59:59.999Z')).toBe(false);
        expect(isTierFresh('2025-11-03', '2026-11-03T23:59:59.999Z')).toBe(true);
    });

    it('is not fresh against a scan time or a date that cannot be read', () => {
        expect(isTierFresh('2026-11-03', 'not a time')).toBe(false);
        expect(isTierFresh('not a date', AS_OF)).toBe(false);
    });
});
