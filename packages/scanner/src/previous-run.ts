/**
 * THE RUN BEFORE THIS ONE, for the page's "since the previous run" section.
 *
 * The file output already knows its previous run: `latest.json` names it, and
 * this run replaces that pointer only after its own files are in place. So
 * before a run is written, the run `latest.json` names is read back and
 * compared with this one by `scanent diff`'s own rules (`diffResults`). No flag
 * is needed, and nothing outside the output directory is read.
 *
 * What is read is untrusted input, read as `scanent diff` reads it: a pointer
 * whose scan id is not a run directory's name, a run directory that is not a
 * real directory, a file too large, a file that is not a valid results file, or
 * one that holds a secret's shape, is NOT_COMPARED `UNREADABLE`, and the page
 * says so. Two runs the comparison refuses (an earlier ladder, another scanner,
 * a time that is not earlier) are NOT_COMPARED with that rule's name. Reading
 * never stops the run: the comparison is a section of the page, not a
 * condition of writing it.
 */
import { existsSync, lstatSync, readFileSync } from 'fs';
import { join } from 'path';

import { DiffRefused, diffResults } from '@scanent/report/diff/diff';
import { RUN_FILE_NAMES } from '@scanent/report/render/files';
import type { PreviousRun } from '@scanent/report/render/page-data';
import type { LocalResults } from '@scanent/report/results/types';

import { loadDiffSide, MAX_DIFF_INPUT_BYTES } from './diff-command';
import { SCAN_ID_PATTERN } from './file-output';

/** The largest pointer read. `latest.json` is a few hundred bytes. */
const MAX_POINTER_BYTES = 64 * 1024;

export interface PreviousRunDeps {
    /** Read a file, or null when it is absent, not a regular file, or larger than `max`. A TEST SEAM. */
    readonly readFile?: (path: string, max: number) => string | null;
}

function readRegularFile(path: string, max: number): string | null {
    if (!existsSync(path)) return null;
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.size > max) return null;
    return readFileSync(path, 'utf8');
}

/**
 * The run the output directory names as its latest, compared with `current`.
 * Null when the directory holds no pointer: there was no earlier run.
 */
export function previousRunOf(dir: string, current: LocalResults, deps: PreviousRunDeps = {}): PreviousRun | null {
    const read = deps.readFile ?? readRegularFile;
    let pointerText: string | null;
    try {
        pointerText = read(join(dir, 'latest.json'), MAX_POINTER_BYTES);
    } catch {
        return { kind: 'NOT_COMPARED', scanId: null, reason: 'UNREADABLE' };
    }
    if (pointerText === null) return existsSync(join(dir, 'latest.json')) ? { kind: 'NOT_COMPARED', scanId: null, reason: 'UNREADABLE' } : null;
    let scanId: string | null = null;
    try {
        const pointer = JSON.parse(pointerText) as { scanId?: unknown };
        if (typeof pointer.scanId !== 'string' || !SCAN_ID_PATTERN.test(pointer.scanId) || pointer.scanId === current.scan.id) {
            return { kind: 'NOT_COMPARED', scanId: null, reason: 'UNREADABLE' };
        }
        scanId = pointer.scanId;
        const text = read(join(dir, 'runs', scanId, RUN_FILE_NAMES.results), MAX_DIFF_INPUT_BYTES);
        if (text === null) return { kind: 'NOT_COMPARED', scanId, reason: 'UNREADABLE' };
        const parsed = JSON.parse(text) as { schema?: unknown };
        // A results file only: a signed report there would be scored with no inventory, which is not what that run showed.
        if (parsed === null || typeof parsed !== 'object' || parsed.schema !== current.schema) return { kind: 'NOT_COMPARED', scanId, reason: 'UNREADABLE' };
        const previous = loadDiffSide(text, 'old', null);
        return { kind: 'COMPARED', diff: diffResults(previous, current) };
    } catch (err) {
        if (err instanceof DiffRefused) return { kind: 'NOT_COMPARED', scanId, reason: err.reason };
        return { kind: 'NOT_COMPARED', scanId, reason: 'UNREADABLE' };
    }
}
