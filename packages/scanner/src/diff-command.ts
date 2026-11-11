/**
 * `scanent diff <old> <new>` — what changed between two runs.
 *
 * Each argument is a file. What it is is decided by its content, never its
 * name: a `results.json` (parsed with the strict results schema), or a signed
 * report (verified, then scored with no inventory). Both sides are then local
 * results, and `@scanent/report` compares them.
 *
 * A signed report is verified against `--trust-key` when one is given, and
 * otherwise against the key the report itself carries. The second shows that
 * the report was not altered, not who signed it, and the output says so.
 *
 * Nothing is fetched and nothing is written but the comparison, to stdout.
 * Exit codes: 0 no difference; 1 a difference; 2 a usage or input error;
 * 3 no difference found, but not every comparison could be made.
 */
import { createHash } from 'crypto';
import { readFileSync, statSync } from 'fs';

import { harnessKeyFingerprint, verifyAndParseHarnessReport, type HarnessReportBody } from '@scanent/contract/harness-contract';
import { firstSecretShapedMember, type HarnessSourceKind } from '@scanent/contract/harness-findings';
import { diffExitCode, DiffRefused, diffResults } from '@scanent/report/diff/diff';
import { renderDiffText } from '@scanent/report/render/diff-text';
import { stableJson } from '@scanent/report/render/results-json';
import { LocalResultsSchema } from '@scanent/report/results/schema';
import { scoreReportLocally } from '@scanent/report/results/score';
import { RESULTS_SCHEMA, type LocalResults } from '@scanent/report/results/types';

import { CRITERION_READERS } from './criterion-readers';
import { assertNoSecretShape, OutputRefusedLocally } from './file-output';

export const DIFF_USAGE = 'usage: scanent diff <old> <new> [--format text|json] [--trust-key <hex>] [--allow-different-scanner]';

/** The largest file `diff` reads. A results file of the largest report fits several times over. */
export const MAX_DIFF_INPUT_BYTES = 64 * 1024 * 1024;

/** An input that cannot be compared. The message names the side and the rule, never a value from the file. */
export class DiffInputError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'DiffInputError';
    }
}

export interface DiffIo {
    readonly stdout: (text: string) => void;
    readonly stderr: (text: string) => void;
    /** A TEST SEAM: production reads the file system. */
    readonly readFile?: (path: string) => string;
}

function readCapped(path: string): string {
    if (statSync(path).size > MAX_DIFF_INPUT_BYTES) throw new Error('too large');
    return readFileSync(path, 'utf8');
}

/** One side of a comparison, from a results file or a signed report. */
export function loadDiffSide(raw: string, side: 'old' | 'new', trustKey: string | null): LocalResults {
    let parsed: unknown;
    try {
        parsed = JSON.parse(raw);
    } catch {
        throw new DiffInputError(`${side}: not JSON`);
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new DiffInputError(`${side}: not a results file or a signed report`);
    const object = parsed as Record<string, unknown>;

    if (object.schema === RESULTS_SCHEMA) {
        const secretAt = firstSecretShapedMember(object);
        if (secretAt !== null) throw new DiffInputError(`${side}: ${secretAt} has the shape of a secret; the file is refused`);
        const results = LocalResultsSchema.safeParse(object);
        if (!results.success) {
            const where = results.error.issues.slice(0, 5).map((i) => `${i.path.join('.') || '(root)'}: ${i.code}`);
            throw new DiffInputError(`${side}: not a valid ${RESULTS_SCHEMA} file (${where.join('; ')})`);
        }
        return results.data;
    }

    if ('contract' in object && 'signature' in object) {
        const carried = (object.signature as { signerKey?: unknown } | null)?.signerKey;
        const keys = trustKey !== null ? [trustKey] : typeof carried === 'string' ? [carried] : [];
        const verified = verifyAndParseHarnessReport(raw, keys);
        if (!verified.ok) throw new DiffInputError(`${side}: the signed report was refused (${verified.reason})`);
        const fingerprint = harnessKeyFingerprint(verified.signerKey);
        if (fingerprint === null) throw new DiffInputError(`${side}: the signed report was refused (MALFORMED_SIGNATURE)`);
        const body: HarnessReportBody = verified.body;
        return scoreReportLocally({
            body,
            inventory: null,
            // A report says which sources it read, not which the run configured: the two are the same list.
            readers: { table: CRITERION_READERS, configuredSources: body.population.sources.map((s) => s.kind as HarnessSourceKind) },
            meta: {
                estate: null,
                registerClaimsVerified: false,
                report: { sha256: createHash('sha256').update(raw, 'utf8').digest('hex'), signerKeyFingerprint: fingerprint, signerPinned: trustKey !== null },
            },
        });
    }
    throw new DiffInputError(`${side}: not a results file or a signed report`);
}

interface DiffArgs {
    readonly paths: readonly [string, string];
    readonly format: 'text' | 'json';
    readonly trustKey: string | null;
    readonly allowDifferentScanner: boolean;
}

/** The arguments after `diff`, or null when they are not a valid call. */
export function parseDiffArgs(argv: readonly string[]): DiffArgs | null {
    const paths: string[] = [];
    let format: 'text' | 'json' = 'text';
    let trustKey: string | null = null;
    let allowDifferentScanner = false;
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        if (a === '--allow-different-scanner') allowDifferentScanner = true;
        else if (a === '--format') {
            const v = argv[++i];
            if (v !== 'text' && v !== 'json') return null;
            format = v;
        } else if (a === '--trust-key') {
            const v = argv[++i];
            if (v === undefined || !/^[0-9a-fA-F]{64}$/.test(v)) return null;
            trustKey = v;
        } else if (a.startsWith('--')) return null;
        else paths.push(a);
    }
    return paths.length === 2 ? { paths: [paths[0], paths[1]], format, trustKey, allowDifferentScanner } : null;
}

/** Run `diff` over the arguments after the command name. Returns the exit code. */
export function runDiff(argv: readonly string[], io: DiffIo): number {
    const args = parseDiffArgs(argv);
    if (args === null) {
        io.stderr(`${DIFF_USAGE}\n`);
        return 2;
    }
    const read = io.readFile ?? readCapped;
    try {
        const sides = (['old', 'new'] as const).map((side, i) => {
            let raw: string;
            try {
                raw = read(args.paths[i]);
            } catch {
                throw new DiffInputError(`${side}: the file could not be read`);
            }
            return loadDiffSide(raw, side, args.trustKey);
        });
        const diff = diffResults(sides[0], sides[1], { allowDifferentScanner: args.allowDifferentScanner });
        // The same two checks every output passes: the data, then the text.
        assertNoSecretShape(diff, 'the diff');
        const text = args.format === 'json' ? stableJson(diff) : renderDiffText(diff);
        assertNoSecretShape(text, 'the diff output');
        io.stdout(text);
        return diffExitCode(diff);
    } catch (err) {
        if (err instanceof DiffInputError || err instanceof DiffRefused || err instanceof OutputRefusedLocally) {
            io.stderr(`scanent diff: ${err.message}\n`);
            return 2;
        }
        throw err;
    }
}
