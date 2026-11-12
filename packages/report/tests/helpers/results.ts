/**
 * Results fixtures for the renderer and diff tests: scored from the bodies of
 * `fixtures.ts`, so every fixture is something the scorer really produces.
 */
import type { HarnessReportBodyV3 } from '@rodnapamet/scanent-contract/harness-contract';

import { scoreReportLocally } from '../../src/results/score';
import type { LocalResults } from '../../src/results/types';
import { ALPHA, BRAVO, fullRow, input, inventoryOf, standaloneBody, withSource } from './fixtures';

/** Two agents, both sources complete, no inventory. */
export function plainResults(): LocalResults {
    return scoreReportLocally(input(standaloneBody()));
}

/** The same estate with an inventory that names `alpha` and one agent the scan did not find. */
export function inventoryResults(): LocalResults {
    return scoreReportLocally(
        input(standaloneBody(), { inventory: inventoryOf([fullRow(ALPHA, { name: 'Invoice triage' }), fullRow('entra:sp:zulu', { name: 'Zulu' })]) }),
    );
}

/** `entra-sp` stopped early: neither agent can be judged. */
export function notJudgedResults(): LocalResults {
    return scoreReportLocally(input(withSource(standaloneBody(), 'entra-sp', 'AUTH_FAILED')));
}

/** A scan that found nothing. */
export function emptyResults(): LocalResults {
    return scoreReportLocally(input({ ...standaloneBody(), agents: [] }));
}

/** A later scan of the same estate by the same scanner, changed by `change`. */
export function laterBody(change: (body: HarnessReportBodyV3) => HarnessReportBodyV3 = (b) => b): HarnessReportBodyV3 {
    const body = standaloneBody();
    return change({ ...body, scan: { ...body.scan, id: 'acme-20261104T033000Z-0a1b2c3e', asOf: '2026-11-04T03:30:00.000Z' } });
}

/**
 * Every string a scanner or an operator controls replaced by `payload`. The
 * ladder's own tables, the schema id and the judgement state are left: they
 * are what the renderers branch on, and they are scanent's, not the estate's.
 */
export function hostile<T>(value: T, payload: string, path: readonly string[] = []): T {
    if (typeof value === 'string') {
        const key = path[path.length - 1];
        if (path[0] === 'schema' || (path[0] === 'ladder' && path[1] !== 'version')) return value;
        if (key === 'state' && path[path.length - 2] === 'judgement') return value;
        return payload as unknown as T;
    }
    if (Array.isArray(value)) return value.map((v, i) => hostile(v, payload, [...path, String(i)])) as unknown as T;
    if (value !== null && typeof value === 'object') {
        return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, hostile(v, payload, [...path, k])])) as T;
    }
    return value;
}

/** A small RFC 4180 reader: records of fields, quotes undoubled. Throws on anything malformed. */
export function parseCsv(text: string): string[][] {
    const records: string[][] = [];
    let i = 0;
    while (i < text.length) {
        const record: string[] = [];
        for (;;) {
            if (text[i] !== '"') throw new Error(`field at ${i} is not quoted`);
            i += 1;
            let field = '';
            for (;;) {
                if (i >= text.length) throw new Error('unterminated field');
                if (text[i] === '"') {
                    if (text[i + 1] === '"') {
                        field += '"';
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                field += text[i];
                i += 1;
            }
            record.push(field);
            if (text[i] === ',') {
                i += 1;
                continue;
            }
            if (text.startsWith('\r\n', i)) {
                i += 2;
                break;
            }
            throw new Error(`unexpected character after a field at ${i}`);
        }
        records.push(record);
    }
    return records;
}

export { ALPHA, BRAVO };
