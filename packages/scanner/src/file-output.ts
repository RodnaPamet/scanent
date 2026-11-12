/**
 * THE FILE OUTPUT — one run, one directory, written whole or not at all.
 *
 *   <dir>/latest.json                 a pointer to the newest run
 *   <dir>/runs/<scanId>/              report.signed.json, results.json,
 *                                     agents.csv, findings.csv, summary.html,
 *                                     manifest.json
 *
 * A run is written under a temporary name and renamed into place, so a reader
 * never opens half a run and a failed write leaves nothing behind. Nothing
 * that exists is ever replaced except the pointer, and that is replaced by a
 * rename. No run is removed unless the configuration sets `retainRuns`: a tool
 * that deletes its own evidence unasked is worse than a volume that fills, and
 * a full volume fails loudly.
 *
 * NOTHING SECRET IS WRITTEN. Before the first byte, the results are walked
 * for a secret-shaped member and each rendered file is checked as one text.
 * A hit refuses the whole run and names the member or the file, never the
 * value (`OutputRefusedLocally`).
 *
 * This is the only module of the scanner that writes a file.
 */
import { createHash } from 'crypto';
import { closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readdirSync, renameSync, rmSync, writeSync } from 'fs';
import { dirname, join } from 'path';

import { looksLikeSecret } from '@rodnapamet/scanent-contract/harness-contract';
import { firstSecretShapedMember } from '@rodnapamet/scanent-contract/harness-findings';
import { renderAgentsCsv, renderFindingsCsv } from '@scanent/report/render/csv';
import { RUN_FILE_NAMES } from '@scanent/report/render/files';
import { renderSummaryHtml } from '@scanent/report/render/html';
import { renderResultsJson, stableJson } from '@scanent/report/render/results-json';
import type { LocalResults } from '@scanent/report/results/types';

/** A scan id as `scan.ts` builds it: `<estate>-<UTC stamp>-<8 hex>`. The only name a run directory takes. */
export const SCAN_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}-(\d{8}T\d{6}Z)-[0-9a-f]{8}$/;

export const RUN_DIR_MODE = 0o750;
export const RUN_FILE_MODE = 0o640;
const STALE_TEMPORARY_MS = 24 * 3_600_000;

/** An output that was not written because something in it has a secret's shape. Paths and file names only. */
export class OutputRefusedLocally extends Error {
    constructor(readonly where: string) {
        super(`output refused: ${where} has the shape of a secret; nothing was written`);
        this.name = 'OutputRefusedLocally';
    }
}

/**
 * The run was written whole and is on disk, but `latest.json` could not be
 * replaced, so the pointer still names an earlier run (or is absent). The run
 * is kept: it is complete evidence, and removing it would lose more than a
 * stale pointer does. The message holds the scan id and a relative path only.
 */
export class PointerNotUpdated extends Error {
    constructor(readonly scanId: string, readonly code: string | null) {
        super(`results written to runs/${scanId}, but latest.json was not updated${code === null ? '' : ` (${code})`}; it does not name this run`);
        this.name = 'PointerNotUpdated';
    }
}

export interface RunFile {
    readonly name: string;
    readonly content: string;
}

/** How each derived file is rendered. A TEST SEAM: production uses the report package's renderers. */
export interface RunRenderers {
    readonly results: (results: LocalResults) => string;
    readonly agents: (results: LocalResults) => string;
    readonly findings: (results: LocalResults) => string;
    readonly summary: (results: LocalResults) => string;
}

const RENDERERS: RunRenderers = {
    results: renderResultsJson,
    agents: renderAgentsCsv,
    findings: renderFindingsCsv,
    summary: renderSummaryHtml,
};

/**
 * Refuse a text or a value that holds a secret's shape. `where` is what the
 * refusal names: a file name, or the output it would have gone to.
 */
export function assertNoSecretShape(value: unknown, where: string): void {
    if (typeof value === 'string') {
        if (looksLikeSecret(value)) throw new OutputRefusedLocally(where);
        return;
    }
    const member = firstSecretShapedMember(value);
    if (member !== null) throw new OutputRefusedLocally(`${where}: ${member}`);
}

/**
 * A file's text as the shape check reads it. A CSV's cells are separate
 * values, and two of them side by side can look like one secret (a URL with a
 * port, then a cell holding an `@`), so the separator between two cells is
 * read as a space. Everything inside a cell is checked as written.
 */
function textAsRead(file: RunFile): string {
    return file.name.endsWith('.csv') ? file.content.replace(/","/g, '" "') : file.content;
}

/**
 * The five files of one run, rendered and checked. The signed report is the
 * bytes `signReport` produced, which it already refused to sign with a
 * secret-shaped member; the four derived files are checked here, first as
 * data and then each as the text that would be written.
 */
export function renderRunFiles(raw: string, results: LocalResults, renderers: RunRenderers = RENDERERS): RunFile[] {
    assertNoSecretShape(results, RUN_FILE_NAMES.results);
    const derived: RunFile[] = [
        { name: RUN_FILE_NAMES.results, content: renderers.results(results) },
        { name: RUN_FILE_NAMES.agents, content: renderers.agents(results) },
        { name: RUN_FILE_NAMES.findings, content: renderers.findings(results) },
        { name: RUN_FILE_NAMES.summary, content: renderers.summary(results) },
    ];
    for (const file of derived) assertNoSecretShape(textAsRead(file), file.name);
    return [{ name: RUN_FILE_NAMES.report, content: raw }, ...derived];
}

export interface FileOutputDeps {
    /** Write one new file. A TEST SEAM: production creates it exclusively, writes, and syncs. */
    readonly writeFile?: (path: string, content: string) => void;
    /** Make one directory, its parent existing. A TEST SEAM: production calls `mkdirSync`, never recursively. */
    readonly mkdir?: (path: string, mode: number) => void;
    readonly now?: () => number;
    readonly renderers?: RunRenderers;
}

/** Write one new file, creating it: a file that exists is refused (`EEXIST`) and left as it was. */
export function writeNewFile(path: string, content: string): void {
    // `wx`: a file that exists is an error, never something to replace.
    const fd = openSync(path, 'wx', RUN_FILE_MODE);
    try {
        writeSync(fd, content, null, 'utf8');
        fsyncSync(fd);
    } finally {
        closeSync(fd);
    }
}

/** Sync a directory's entry list. Best effort: not every file system allows it. */
function syncDirectory(path: string): void {
    try {
        const fd = openSync(path, 'r');
        try {
            fsyncSync(fd);
        } finally {
            closeSync(fd);
        }
    } catch {
        // The rename already happened; a file system that cannot sync a directory still holds it.
    }
}

function isRealDirectory(path: string): boolean {
    try {
        return lstatSync(path).isDirectory();
    } catch {
        return false;
    }
}

/**
 * Make `path` and whichever of its parents are missing, ONE LEVEL AT A TIME.
 * Not `mkdirSync(…, { recursive: true })`: where a file system answers ENOENT
 * for a directory under a parent that exists (procfs does), the recursive form
 * never returns, and a scheduled scanner would stall for good. Made this way,
 * the refusal is thrown and the output fails loudly.
 */
function ensureDirectory(path: string, mkdir: (path: string, mode: number) => void): void {
    const missing: string[] = [];
    let at = path;
    while (!existsSync(at)) {
        missing.unshift(at);
        const parent = dirname(at);
        if (parent === at) break;
        at = parent;
    }
    for (const dir of missing) {
        try {
            mkdir(dir, RUN_DIR_MODE);
        } catch (err) {
            // Another run made it first: fine, when what is there is a directory.
            if ((err as NodeJS.ErrnoException).code !== 'EEXIST' || !isRealDirectory(dir)) throw err;
        }
    }
}

function removeStaleTemporaries(runs: string, now: number): void {
    for (const name of readdirSync(runs)) {
        if (!name.startsWith('.') || !name.endsWith('.tmp') || !SCAN_ID_PATTERN.test(name.slice(1, -4))) continue;
        const path = join(runs, name);
        try {
            const stat = lstatSync(path);
            if (stat.isDirectory() && now - stat.mtimeMs > STALE_TEMPORARY_MS) rmSync(path, { recursive: true, force: true });
        } catch {
            // Another run removed it first.
        }
    }
}

/**
 * Remove the oldest runs beyond `retainRuns`. Only a real directory whose
 * name is a scan id and that holds a manifest is ever removed, and never the
 * run just written.
 */
export function applyRetention(dir: string, retainRuns: number, keep: string): string[] {
    const runs = join(dir, 'runs');
    const candidates = readdirSync(runs)
        .filter((name) => SCAN_ID_PATTERN.test(name) && isRealDirectory(join(runs, name)) && existsSync(join(runs, name, RUN_FILE_NAMES.manifest)))
        .map((name) => ({ name, stamp: (SCAN_ID_PATTERN.exec(name) as RegExpExecArray)[1] }))
        // Newest first, by the UTC stamp in the name; the name breaks a tie.
        .sort((a, b) => (a.stamp === b.stamp ? (a.name < b.name ? 1 : -1) : a.stamp < b.stamp ? 1 : -1));
    const removed: string[] = [];
    for (const { name } of candidates.slice(retainRuns)) {
        if (name === keep) continue;
        rmSync(join(runs, name), { recursive: true, force: true });
        removed.push(name);
    }
    return removed;
}

export interface WrittenRun {
    readonly scanId: string;
    /** Relative to the output directory: `runs/<scanId>`. */
    readonly dir: string;
    readonly files: readonly string[];
    readonly removedRuns: readonly string[];
}

/**
 * Write one run. Throws, having written nothing that remains, when a file
 * would hold a secret's shape, when the run already exists, or when the file
 * system refuses the run. One failure leaves something behind, and says so:
 * when the run is in place and only the pointer could not be replaced, the run
 * stays and `PointerNotUpdated` names it.
 */
export function writeRun(
    output: { readonly dir: string; readonly retainRuns?: number },
    run: { readonly raw: string; readonly results: LocalResults },
    deps: FileOutputDeps = {},
): WrittenRun {
    const scanId = run.results.scan.id;
    if (!SCAN_ID_PATTERN.test(scanId)) throw new Error('the scan id is not a safe directory name; nothing was written');
    const now = (deps.now ?? Date.now)();
    const write = deps.writeFile ?? writeNewFile;

    // Everything is rendered and checked before the first byte is written.
    const files = renderRunFiles(run.raw, run.results, deps.renderers);
    const manifest: RunFile = {
        name: RUN_FILE_NAMES.manifest,
        content: stableJson({
            manifest: 'scanent-run/1',
            scanId,
            files: files.map((f) => ({
                name: f.name,
                bytes: Buffer.byteLength(f.content, 'utf8'),
                sha256: createHash('sha256').update(f.content, 'utf8').digest('hex'),
            })),
        }),
    };

    const runs = join(output.dir, 'runs');
    ensureDirectory(runs, deps.mkdir ?? ((path, mode) => mkdirSync(path, { mode })));
    // A `runs` that is a link is somebody else's directory: nothing is written through it.
    if (!isRealDirectory(runs)) throw new Error('runs is not a directory of this output; nothing was written');
    removeStaleTemporaries(runs, now);
    const target = join(runs, scanId);
    // A rename onto an empty directory would replace it, so the check is made here.
    if (existsSync(target)) throw new Error(`run ${scanId} already exists; nothing was replaced`);
    const temporary = join(runs, `.${scanId}.tmp`);
    mkdirSync(temporary, { mode: RUN_DIR_MODE });
    const pointerTemporary = join(output.dir, `latest.json.${scanId}.tmp`);
    try {
        for (const file of [...files, manifest]) write(join(temporary, file.name), file.content);
        renameSync(temporary, target);
        syncDirectory(runs);
    } catch (err) {
        rmSync(temporary, { recursive: true, force: true });
        throw err;
    }
    // The pointer: the one thing that is replaced, and by a rename.
    try {
        rmSync(pointerTemporary, { force: true });
        write(
            pointerTemporary,
            stableJson({
                scanId,
                dir: `runs/${scanId}`,
                asOf: run.results.scan.asOf,
                complete: run.results.scan.complete,
                agentCount: run.results.estate.agentCount,
            }),
        );
        renameSync(pointerTemporary, join(output.dir, 'latest.json'));
        syncDirectory(output.dir);
    } catch (err) {
        rmSync(pointerTemporary, { force: true });
        const code = (err as NodeJS.ErrnoException | null)?.code;
        throw new PointerNotUpdated(scanId, typeof code === 'string' && /^[A-Z0-9_]{1,32}$/.test(code) ? code : null);
    }
    const removedRuns = output.retainRuns === undefined ? [] : applyRetention(output.dir, output.retainRuns, scanId);
    return { scanId, dir: `runs/${scanId}`, files: [...files, manifest].map((f) => f.name), removedRuns };
}
