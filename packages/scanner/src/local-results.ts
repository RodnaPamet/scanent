/**
 * FROM ONE SCAN TO ITS LOCAL RESULTS.
 *
 * The scorer (`@scanent/report`) is pure: it is handed everything. This module
 * is where the scanner supplies what only it holds: the hash of the signed
 * report's bytes, the fingerprint of the key that signed it, which readers the
 * run configured, and the operator's inventory, if the configuration names one.
 *
 * Scoring happens AFTER signing, over the same body that was signed, so the
 * local results and the signed report describe one scan. Nothing here changes
 * the report, and nothing the inventory says enters it.
 */
import { createHash } from 'crypto';

import { harnessKeyFingerprint, type HarnessReportBody } from '@scanent/contract/harness-contract';
import type { ParsedInventory } from '@scanent/report/results/inventory';
import { scoreReportLocally } from '@scanent/report/results/score';
import type { LocalResults } from '@scanent/report/results/types';

import type { ScannerConfig } from './config';
import { configuredSourceKinds, CRITERION_READERS } from './criterion-readers';
import { loadInventoryFile, type InventoryFileDeps } from './inventory-file';

/**
 * The inventory a configuration names, or null when it names none. Throws
 * `InventoryRefused` for a file that is missing or refused: call it BEFORE any
 * source is read, so a run never scores against an inventory it could not load.
 */
export function loadConfiguredInventory(config: Pick<ScannerConfig, 'inventory'>, deps: InventoryFileDeps = {}): ParsedInventory | null {
    return config.inventory === undefined ? null : loadInventoryFile(config.inventory.path, deps);
}

/** The key a serialised report carries in its signature, or null when it carries none. */
function signerKeyOf(raw: string): string | null {
    let parsed: unknown;
    try {
        parsed = JSON.parse(raw);
    } catch {
        return null;
    }
    const signature = (parsed as { signature?: { signerKey?: unknown } } | null)?.signature;
    return typeof signature?.signerKey === 'string' ? signature.signerKey : null;
}

/**
 * Score the scan this run just took. `raw` and `body` are `runScan`'s: the
 * serialised signed report and the body it carries. The register claims are
 * this run's own read and the signer is this scanner's own key, so both are
 * stated as verified.
 */
export function scoreScanLocally(scan: {
    readonly config: Pick<ScannerConfig, 'estate' | 'sources'>;
    readonly raw: string;
    readonly body: HarnessReportBody;
    readonly inventory: ParsedInventory | null;
}): LocalResults {
    const signerKey = signerKeyOf(scan.raw);
    const fingerprint = signerKey === null ? null : harnessKeyFingerprint(signerKey);
    if (fingerprint === null) throw new Error('the signed report carries no Ed25519 signer key');
    return scoreReportLocally({
        body: scan.body,
        inventory: scan.inventory,
        readers: { table: CRITERION_READERS, configuredSources: configuredSourceKinds(scan.config) },
        meta: {
            estate: scan.config.estate,
            registerClaimsVerified: true,
            report: {
                sha256: createHash('sha256').update(scan.raw, 'utf8').digest('hex'),
                signerKeyFingerprint: fingerprint,
                signerPinned: true,
            },
        },
    });
}
