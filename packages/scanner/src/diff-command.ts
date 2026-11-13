/**
 * `scanent diff <old> <new>` — what changed between two runs.
 *
 * Each argument is a file. What it is is decided by its content, never its
 * name: a `results.json` (parsed with the strict results schema: an agent
 * scan's, perhaps with an integrations section, or the integrations scanner's
 * alone), or a signed report of either scanner (verified, then scored: an
 * agent report with no inventory, an integrations report over the default
 * window for "unused"). Both sides are then each scanner's local results, and
 * `@scanent/report` compares them scanner by scanner (`diffRuns`). Two runs of
 * the agent scanner alone are compared exactly as they always were.
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

import { harnessKeyFingerprint, verifyAndParseHarnessReport, type HarnessReportBody } from '@rodnapamet/scanent-contract/harness-contract';
import { HARNESS_CONTRACT_IDS } from '@rodnapamet/scanent-contract/harness-contract-rules';
import { firstSecretShapedMember, type HarnessSourceKind } from '@rodnapamet/scanent-contract/harness-findings';
import { verifyAndParseIntegrationsReport } from '@rodnapamet/scanent-contract/integrations-contract';
import { INTEGRATIONS_CONTRACT_V1 } from '@rodnapamet/scanent-contract/integrations-contract-rules';
import { DEFAULT_UNUSED_DAYS } from '@rodnapamet/scanent-contract/integrations-findings';
import { diffExitCode, DiffRefused, type ResultsDiff } from '@scanent/report/diff/diff';
import { diffRuns, integrationsSideOf, RunsShareNoScanner, type RunDiff, type RunDiffSide } from '@scanent/report/diff/run-diff';
import { renderDiffText } from '@scanent/report/render/diff-text';
import { terminalJson } from '@scanent/report/render/escape';
import { INTEGRATION_RUN_FILE_NAMES } from '@scanent/report/render/files';
import { stableJson } from '@scanent/report/render/results-json';
import { renderRunDiffText } from '@scanent/report/render/run-diff-text';
import { scoreIntegrationsLocally } from '@scanent/report/results/integrations';
import { IntegrationsOnlyResultsSchema, LocalResultsSchema } from '@scanent/report/results/schema';
import { scoreReportLocally } from '@scanent/report/results/score';
import { INTEGRATIONS_ONLY_RESULTS_SCHEMA, RESULTS_SCHEMA, type LocalResults } from '@scanent/report/results/types';

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
    /** How the comparison becomes text. A TEST SEAM: production uses the report package's renderers. */
    readonly render?: (diff: ResultsDiff | RunDiff, format: 'text' | 'json') => string;
}

function renderDiff(diff: ResultsDiff | RunDiff, format: 'text' | 'json'): string {
    if (format === 'json') return terminalJson(stableJson(diff));
    return 'scanners' in diff ? renderRunDiffText(diff) : renderDiffText(diff);
}

function readCapped(path: string): string {
    if (statSync(path).size > MAX_DIFF_INPUT_BYTES) throw new Error('too large');
    return readFileSync(path, 'utf8');
}

/** The agent scanner's side of a comparison, from a results file or a signed report. Refuses a run in which the agent scanner did not run. */
export function loadDiffSide(raw: string, side: 'old' | 'new', trustKey: string | null): LocalResults {
    const run = loadRunSide(raw, side, trustKey);
    if (run.agents === null) throw new DiffInputError(`${side}: the agent scanner did not run in this run`);
    return run.agents;
}

/** One side of a comparison, from a results file or a signed report of either scanner: each scanner's results, or null where it did not run. */
export function loadRunSide(raw: string, side: 'old' | 'new', trustKey: string | null): RunDiffSide {
    try {
        return loadRunSideValue(raw, side, trustKey);
    } catch (err) {
        // A member nested hundreds of thousands deep parses as JSON and
        // overflows the stack of whatever walks it: a refused input, with the
        // exit code of one, not the engine's own message and exit 1.
        if (err instanceof RangeError) throw new DiffInputError(`${side}: nested too deeply`);
        throw err;
    }
}

function loadRunSideValue(raw: string, side: 'old' | 'new', trustKey: string | null): RunDiffSide {
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
        return { agents: results.data, integrations: integrationsSideOf(results.data) };
    }

    if (object.schema === INTEGRATIONS_ONLY_RESULTS_SCHEMA) {
        const secretAt = firstSecretShapedMember(object);
        if (secretAt !== null) throw new DiffInputError(`${side}: ${secretAt} has the shape of a secret; the file is refused`);
        const results = IntegrationsOnlyResultsSchema.safeParse(object);
        if (!results.success) {
            const where = results.error.issues.slice(0, 5).map((i) => `${i.path.join('.') || '(root)'}: ${i.code}`);
            throw new DiffInputError(`${side}: not a valid ${INTEGRATIONS_ONLY_RESULTS_SCHEMA} file (${where.join('; ')})`);
        }
        const r = results.data;
        return { agents: null, integrations: { scan: { id: r.scan.id, asOf: r.scan.asOf, estate: r.scan.estate, scannerAgentId: r.scan.scanner.agentId }, integrations: r.integrations } };
    }

    if (object.contract === INTEGRATIONS_CONTRACT_V1 && 'signature' in object) {
        const carried = (object.signature as { signerKey?: unknown } | null)?.signerKey;
        const keys = trustKey !== null ? [trustKey] : typeof carried === 'string' ? [carried] : [];
        const verified = verifyAndParseIntegrationsReport(raw, keys);
        if (!verified.ok) throw new DiffInputError(`${side}: the signed integrations report was refused (${verified.reason})`);
        const body = verified.body;
        // A signed report does not carry the window "unused" was judged over: the default is used, and a results file says its own.
        const integrations = scoreIntegrationsLocally({
            body,
            unusedDays: DEFAULT_UNUSED_DAYS,
            report: { file: INTEGRATION_RUN_FILE_NAMES.report, sha256: createHash('sha256').update(raw, 'utf8').digest('hex') },
        });
        return { agents: null, integrations: { scan: { id: body.scan.id, asOf: body.scan.asOf, estate: null, scannerAgentId: body.scan.scanner.agentId }, integrations } };
    }

    if ('contract' in object && 'signature' in object) {
        const carried = (object.signature as { signerKey?: unknown } | null)?.signerKey;
        const keys = trustKey !== null ? [trustKey] : typeof carried === 'string' ? [carried] : [];
        const verified = verifyAndParseHarnessReport(raw, keys);
        if (!verified.ok) throw new DiffInputError(`${side}: the signed report was refused (${verified.reason})`);
        const fingerprint = harnessKeyFingerprint(verified.signerKey);
        if (fingerprint === null) throw new DiffInputError(`${side}: the signed report was refused (MALFORMED_SIGNATURE)`);
        const body: HarnessReportBody = verified.body;
        const agents = scoreReportLocally({
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
        return { agents, integrations: null };
    }
    // A file that names another schema, or none, is named for what it is and is
    // never half-read: its members may mean something else in that schema. Only
    // an id of this family is repeated; any other text is the file's own.
    if ('schema' in object) {
        const named = typeof object.schema === 'string' && /^scanent-results(-integrations)?\/\d{1,4}$/.test(object.schema) ? JSON.stringify(object.schema) : 'a schema this version does not know';
        throw new DiffInputError(`${side}: the file names ${named} as its schema; this version reads ${RESULTS_SCHEMA} and ${INTEGRATIONS_ONLY_RESULTS_SCHEMA}`);
    }
    throw new DiffInputError(
        `${side}: the file names no schema; this version reads ${RESULTS_SCHEMA} and ${INTEGRATIONS_ONLY_RESULTS_SCHEMA} files and signed ${HARNESS_CONTRACT_IDS.join(', ')} and ${INTEGRATIONS_CONTRACT_V1} reports`,
    );
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
            return loadRunSide(raw, side, args.trustKey);
        });
        const diff = diffRuns(sides[0], sides[1], { allowDifferentScanner: args.allowDifferentScanner });
        // The same two checks every output passes: the data, then the text.
        assertNoSecretShape(diff, 'the diff');
        const text = (io.render ?? renderDiff)(diff, args.format);
        assertNoSecretShape(text, 'the diff output');
        io.stdout(text);
        return diffExitCode(diff);
    } catch (err) {
        if (err instanceof DiffInputError || err instanceof DiffRefused || err instanceof RunsShareNoScanner || err instanceof OutputRefusedLocally) {
            io.stderr(`scanent diff: ${err.message}\n`);
            return 2;
        }
        throw err;
    }
}
