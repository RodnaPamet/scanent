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
 *
 * Which scanners run follows from the sources configured. The file and stdout
 * outputs carry every report the run made; the `inflect` output posts each
 * report to the tenant's ingest for it: the agent report with `apiKeyEnv`, the
 * integrations report with `integrationsApiKeyEnv`. With no key for the
 * integrations report it is not posted, and the log says so once. The
 * configuration refuses an `inflect` output that would post nothing.
 */
import type { ParsedInventory } from '@scanent/report/results/inventory';

import type { OutputConfig, ScannerConfig } from './config';
import { OutputRefusedLocally, PointerNotUpdated, writeRun, type FileOutputDeps } from './file-output';
import { loadConfiguredInventory, scoreIntegrationsOnlyLocally, scoreScanLocally } from './local-results';
import { previousIntegrationsOf, previousRunOf } from './previous-run';
import { inflectTargets, postToInflect, runScanAll, type RunScan, type ScanDeps } from './scan';

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
    /** Each scanner's part of the run; null for a scanner that did not run. */
    readonly scan: RunScan;
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
 * `inflect` output is in effect (the agent report's when an agent source is
 * configured; the integrations report's when its variable is named and an
 * integrations source is configured), and an inventory that is configured and
 * cannot be loaded. After the scan, an output that fails is logged and the
 * others are still attempted.
 */
export async function scanAndDeliver(deps: DeliverDeps): Promise<DeliveryResult> {
    const { config, env, log } = deps;
    const kinds = deps.outputs.map((o) => o.kind);
    const targets = kinds.includes('inflect') ? inflectTargets(config, env) : null;
    // Loaded whenever it is configured, so a broken inventory is found on the
    // first run and not on the day somebody adds the file output.
    const inventory = (deps.loadInventory ?? loadConfiguredInventory)(config);

    const scan = await runScanAll(deps);
    const agents = scan.agents;
    const delivered: { kind: OutputKind; ok: boolean }[] = [];
    for (const output of [...deps.outputs].sort((a, b) => DELIVERY_ORDER.indexOf(a.kind) - DELIVERY_ORDER.indexOf(b.kind))) {
        let ok = false;
        try {
            if (output.kind === 'file') {
                const integrations = scan.integrations;
                if (agents !== null) {
                    const results = scoreScanLocally({
                        config,
                        raw: agents.raw,
                        body: agents.body,
                        inventory,
                        sourceNotes: agents.sourceNotes,
                        ...(integrations === null ? {} : { integrations }),
                    });
                    // The run the directory names as its latest, read before this one replaces the pointer.
                    const previous = previousRunOf(output.dir, results);
                    const integrationsPrevious =
                        results.integrations === undefined
                            ? undefined
                            : previousIntegrationsOf(output.dir, {
                                  scan: { id: results.scan.id, asOf: results.scan.asOf, estate: results.scan.estate, scannerAgentId: results.scan.scanner.agentId },
                                  integrations: results.integrations,
                              });
                    const written = writeRun(
                        output,
                        {
                            raw: agents.raw,
                            results,
                            previous,
                            ...(integrations === null ? {} : { integrationsRaw: integrations.raw }),
                            ...(integrationsPrevious === undefined ? {} : { integrationsPrevious }),
                        },
                        deps.file,
                    );
                    log.info('results written', { scan: written.scanId, dir: written.dir, files: written.files.length, removedRuns: written.removedRuns.length });
                } else if (integrations !== null) {
                    const results = scoreIntegrationsOnlyLocally({ config, integrations });
                    const integrationsPrevious = previousIntegrationsOf(output.dir, {
                        scan: { id: results.scan.id, asOf: results.scan.asOf, estate: results.scan.estate, scannerAgentId: results.scan.scanner.agentId },
                        integrations: results.integrations,
                    });
                    const written = writeRun(output, { results, integrationsRaw: integrations.raw, integrationsPrevious }, deps.file);
                    log.info('results written', { scan: written.scanId, dir: written.dir, files: written.files.length, removedRuns: written.removedRuns.length });
                }
                ok = true;
            } else if (output.kind === 'stdout') {
                // One signed report per line: the agent report first, as it has always been printed.
                const print = deps.stdout ?? ((text) => void process.stdout.write(text));
                if (agents !== null) print(`${agents.raw}\n`);
                if (scan.integrations !== null) print(`${scan.integrations.raw}\n`);
                ok = true;
            } else {
                // `targets` is set whenever this output is in effect. Each report to its own ingest, with its own key.
                ok = (await postToInflect(deps, targets ?? inflectTargets(config, env), scan)).ok;
            }
        } catch (err) {
            log.error('output failed', { output: output.kind, scan: scan.scanId, error: failureOf(err) });
        }
        delivered.push({ kind: output.kind, ok });
    }
    return { ok: delivered.every((d) => d.ok), delivered, scan };
}
