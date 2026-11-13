/**
 * WHERE ONE RUN'S RESULTS GO.
 *
 * Three outputs, each at most once: `file` (the run's files under a
 * directory), `stdout` (the signed report and a newline, exactly what
 * `--dry-run` has always printed) and `inflect` (the signed report posted to
 * the tenant's ingest).
 *
 * A configuration written before outputs existed has an `inflect` block and
 * no `outputs`, and means what it always meant: post. `resolveOutputs` is
 * where that is decided, and where the two flags are applied.
 *
 * Delivery order is file, stdout, inflect: what stays in the estate is
 * written before anything leaves it. Each output is attempted whatever
 * happened to the others, and a run is delivered only when every one was.
 */
import type { HarnessReportBodyV4 } from '@rodnapamet/scanent-contract/harness-contract';
import type { ParsedInventory } from '@scanent/report/results/inventory';

import type { OutputConfig, ScannerConfig } from './config';
import { OutputRefusedLocally, PointerNotUpdated, writeRun, type FileOutputDeps } from './file-output';
import { loadConfiguredInventory, scoreScanLocally } from './local-results';
import { ingestTarget, postSignedReport, runScan, type ScanDeps } from './scan';

export type OutputKind = OutputConfig['kind'];

const DELIVERY_ORDER: readonly OutputKind[] = ['file', 'stdout', 'inflect'];

/** A command line that names no way to deliver, or names one wrongly. Exit code 2, before anything is read. */
export class OutputsError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'OutputsError';
    }
}

export const NOWHERE_TO_DELIVER = 'nowhere to deliver: configure outputs, or pass --out or --dry-run';

function isAbsoluteCleanPath(v: string): boolean {
    return v.length <= 1024 && v.startsWith('/') && !v.split('/').includes('..') && ![...v].some((ch) => ch.charCodeAt(0) < 0x20);
}

/**
 * The outputs in effect for one run, in delivery order.
 *
 *   1. the configuration's `outputs`; absent, `inflect` when the block exists;
 *   2. `--out <dir>` sets the file output's directory, adding one if needed;
 *   3. `--dry-run` removes `inflect` and adds `stdout`: post nothing, print
 *      the report;
 *   4. nothing left is an error.
 */
export function resolveOutputs(
    config: Pick<ScannerConfig, 'outputs' | 'inflect'>,
    flags: { readonly out?: string | null; readonly dryRun?: boolean } = {},
): OutputConfig[] {
    let outputs: OutputConfig[] = config.outputs !== undefined ? [...config.outputs] : config.inflect !== undefined ? [{ kind: 'inflect' }] : [];
    const out = flags.out ?? null;
    if (out !== null) {
        if (!isAbsoluteCleanPath(out)) throw new OutputsError('--out takes an absolute path with no .. segment');
        const existing = outputs.find((o) => o.kind === 'file');
        outputs = [...outputs.filter((o) => o.kind !== 'file'), { ...existing, kind: 'file', dir: out }];
    }
    if (flags.dryRun === true) {
        outputs = outputs.filter((o) => o.kind !== 'inflect');
        if (!outputs.some((o) => o.kind === 'stdout')) outputs.push({ kind: 'stdout' });
    }
    if (outputs.length === 0) throw new OutputsError(NOWHERE_TO_DELIVER);
    return [...outputs].sort((a, b) => DELIVERY_ORDER.indexOf(a.kind) - DELIVERY_ORDER.indexOf(b.kind));
}

export interface DeliverDeps extends ScanDeps {
    readonly outputs: readonly OutputConfig[];
    /** Where the `stdout` output writes. A TEST SEAM: production writes to the process's stdout. */
    readonly stdout?: (text: string) => void;
    readonly file?: FileOutputDeps;
    /** How the inventory is loaded. A TEST SEAM: production reads the configured file. */
    readonly loadInventory?: (config: ScannerConfig) => ParsedInventory | null;
}

export interface DeliveryResult {
    /** True only when every output in effect was delivered. */
    readonly ok: boolean;
    readonly delivered: readonly { readonly kind: OutputKind; readonly ok: boolean }[];
    readonly scan: { readonly raw: string; readonly body: HarnessReportBodyV4 };
}

/** What a failed output is logged as: our own refusals in full (they hold paths only), anything else by its name and code. */
function failureOf(err: unknown): string {
    if (err instanceof OutputRefusedLocally || err instanceof PointerNotUpdated) return err.message;
    if (err instanceof Error) {
        const code = (err as NodeJS.ErrnoException).code;
        return typeof code === 'string' ? `${err.name} ${code}` : err.name;
    }
    return 'unknown';
}

/**
 * One run: scan once, then deliver to every output in effect.
 *
 * What stops the run BEFORE any source is read: a missing ingest key when the
 * `inflect` output is in effect, and an inventory that is configured and
 * cannot be loaded. After the scan, an output that fails is logged and the
 * others are still attempted.
 */
export async function scanAndDeliver(deps: DeliverDeps): Promise<DeliveryResult> {
    const { config, env, log } = deps;
    const kinds = deps.outputs.map((o) => o.kind);
    const target = kinds.includes('inflect') ? ingestTarget(config, env) : null;
    // Loaded whenever it is configured, so a broken inventory is found on the
    // first run and not on the day somebody adds the file output.
    const inventory = (deps.loadInventory ?? loadConfiguredInventory)(config);

    const scan = await runScan(deps);
    const delivered: { kind: OutputKind; ok: boolean }[] = [];
    for (const output of [...deps.outputs].sort((a, b) => DELIVERY_ORDER.indexOf(a.kind) - DELIVERY_ORDER.indexOf(b.kind))) {
        let ok = false;
        try {
            if (output.kind === 'file') {
                const results = scoreScanLocally({ config, raw: scan.raw, body: scan.body, inventory, sourceNotes: scan.sourceNotes });
                const written = writeRun(output, { raw: scan.raw, results }, deps.file);
                log.info('results written', { scan: written.scanId, dir: written.dir, files: written.files.length, removedRuns: written.removedRuns.length });
                ok = true;
            } else if (output.kind === 'stdout') {
                (deps.stdout ?? ((text) => void process.stdout.write(text)))(`${scan.raw}\n`);
                ok = true;
            } else {
                // `target` is set whenever this output is in effect.
                ok = (await postSignedReport(deps, target ?? ingestTarget(config, env), scan)).ok;
            }
        } catch (err) {
            log.error('output failed', { output: output.kind, scan: scan.body.scan.id, error: failureOf(err) });
        }
        delivered.push({ kind: output.kind, ok });
    }
    return { ok: delivered.every((d) => d.ok), delivered, scan };
}
