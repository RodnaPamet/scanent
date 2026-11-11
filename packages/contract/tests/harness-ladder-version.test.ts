/**
 * The ladder's version: a hash of what changes a result, and nothing else.
 *
 *   1. It is the pinned value, so a change to the ladder is a diff here too.
 *   2. It is derived from the exported tables, not typed in.
 *   3. Anything that changes a level, a blocking list or a bar changes it; a
 *      display name does not.
 *   4. The signed report did not grow a member to carry it.
 */
import { createHash } from 'crypto';

import { canonicalJson } from '../src/canonical-json';
import { HarnessReportBodyV3Schema, LADDER_VERSION, ladderVersionOf } from '../src/harness-contract';
import { HARNESS_CRITERIA, HARNESS_LEVEL_NAMES, HARNESS_LEVELS, shortfallBarFor } from '../src/harness-ladder';
import { validV3ReportBody } from './helpers/agent-harness-fake-scanner';

const current = () => ({
    levels: [...HARNESS_LEVELS] as string[],
    criteria: Object.fromEntries(Object.entries(HARNESS_CRITERIA).map(([level, ids]) => [level, [...ids] as string[]])),
    bars: {
        'read-only': shortfallBarFor('read-only') as string,
        'write-or-external': shortfallBarFor('write-or-external') as string,
        unknown: shortfallBarFor('unknown') as string,
    },
});

describe('LADDER_VERSION', () => {
    it('is the pinned value', () => {
        // A deliberate change to the ladder changes this literal in the same diff.
        expect(LADDER_VERSION).toBe('sha256:b3aa459c8e48dc7dc7528f117de754cf1be24e53f7ec47c8ac81c471ec28d7ae');
    });

    it('is derived from the exported ladder', () => {
        expect(ladderVersionOf(current())).toBe(LADDER_VERSION);
        // And by a route that does not go through `ladderVersionOf` at all.
        const digest = createHash('sha256').update(canonicalJson(current()), 'utf8').digest('hex');
        expect(LADDER_VERSION).toBe(`sha256:${digest}`);
    });

    it.each([
        ['a criterion moved to another rung', (l: ReturnType<typeof current>) => {
            l.criteria.H3.push(l.criteria.H2.pop()!);
        }],
        ['a criterion added', (l: ReturnType<typeof current>) => {
            l.criteria.H4.push('H4.new_criterion');
        }],
        ['a criterion removed', (l: ReturnType<typeof current>) => {
            l.criteria.H5.pop();
        }],
        ['a criterion renamed', (l: ReturnType<typeof current>) => {
            l.criteria.H1[0] = 'H1.enrolled';
        }],
        ['two criteria reordered on one rung', (l: ReturnType<typeof current>) => {
            l.criteria.H1.reverse();
        }],
        ['a rung added', (l: ReturnType<typeof current>) => {
            l.levels.push('H6');
            l.criteria.H6 = [];
        }],
        ['two rungs reordered', (l: ReturnType<typeof current>) => {
            l.levels.reverse();
        }],
        ['the read-only bar changed', (l: ReturnType<typeof current>) => {
            l.bars['read-only'] = 'H3';
        }],
        ['the write bar changed', (l: ReturnType<typeof current>) => {
            l.bars['write-or-external'] = 'H4';
        }],
        ['the unknown-reach bar changed', (l: ReturnType<typeof current>) => {
            l.bars.unknown = 'H2';
        }],
    ])('changes with %s', (_label, change) => {
        const ladder = current();
        change(ladder);
        expect(ladderVersionOf(ladder)).not.toBe(LADDER_VERSION);
        expect(ladderVersionOf(ladder)).toMatch(/^sha256:[0-9a-f]{64}$/);
    });

    it('does not change with a display name, or with a member that is not the ladder', () => {
        const renamed = { ...current(), names: { ...HARNESS_LEVEL_NAMES, H0: 'Unknown' } };
        expect(ladderVersionOf(renamed)).toBe(LADDER_VERSION);
    });

    it('is in no signed body: the strict schema refuses a ladder member anywhere', () => {
        const body = validV3ReportBody();
        expect(HarnessReportBodyV3Schema.safeParse(body).success).toBe(true);
        const withLadder: unknown[] = [
            { ...body, ladder: LADDER_VERSION },
            { ...body, scan: { ...body.scan, ladder: LADDER_VERSION } },
            { ...body, scan: { ...body.scan, scanner: { ...body.scan.scanner, ladder: LADDER_VERSION } } },
            { ...body, population: { ...body.population, ladder: LADDER_VERSION } },
            { ...body, agents: body.agents.map((a) => ({ ...a, ladder: LADDER_VERSION })) },
        ];
        for (const candidate of withLadder) {
            expect(HarnessReportBodyV3Schema.safeParse(candidate).success).toBe(false);
        }
    });
});
