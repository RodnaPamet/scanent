/**
 * `results.json` — the local results as text.
 *
 * Keys are sorted at every depth and arrays keep their order, so the same
 * results give the same bytes whatever order the scorer built its objects in.
 * Two-space indentation and one trailing newline: the file is meant to be
 * read and compared by people as well as by `scanent diff`.
 */
import type { RunResults } from '../results/types';

function sorted(value: unknown): unknown {
    if (Array.isArray(value)) return value.map(sorted);
    if (value !== null && typeof value === 'object') {
        const obj = value as Record<string, unknown>;
        return Object.fromEntries(
            Object.keys(obj)
                .sort()
                .map((k) => [k, sorted(obj[k])]),
        );
    }
    return value;
}

/** Any JSON value, with sorted keys, indented, ending in a newline. */
export function stableJson(value: unknown): string {
    return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

export function renderResultsJson(results: RunResults): string {
    return stableJson(results);
}
