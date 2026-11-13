/**
 * THE SCANNERS OF ONE SCANENT — which source kind belongs to which scanner.
 *
 * A scanner is a set of source kinds, a report contract, a planner and a
 * section of the outputs (`docs/design/scanners.md`). The platform (the wire,
 * the declared surface, the signing key, the outputs) is one; each scanner adds
 * its sources. Which scanners a run runs follows from the sources it is
 * configured with: each kind belongs to exactly one scanner, so a product read
 * by two scanners is two kinds.
 *
 * Every scanner whose sources are configured writes one signed report, with
 * the same key and the same scan id. The agent scanner's report keeps its
 * contract and its file name, so nothing that reads it today changes.
 */
import { HARNESS_CONTRACT_V4, SOURCE_KINDS_V3 } from '@rodnapamet/scanent-contract/harness-contract-rules';
import { INTEGRATIONS_CONTRACT_V1, INTEGRATIONS_SOURCE_KINDS, type IntegrationsSourceKind } from '@rodnapamet/scanent-contract/integrations-contract-rules';
import { INTEGRATION_RUN_FILE_NAMES, RUN_FILE_NAMES } from '@scanent/report/render/files';

import type { SourceKind } from './source';

export const SCANNERS = ['agents', 'integrations'] as const;
export type ScannerId = (typeof SCANNERS)[number];

/** Every source kind a configuration may name, the agent scanner's first. */
export const ALL_SOURCE_KINDS = [...SOURCE_KINDS_V3, ...INTEGRATIONS_SOURCE_KINDS] as const;
export type ScannerSourceKind = SourceKind | IntegrationsSourceKind;

/** The scanner each source kind belongs to. A `Record`, so a kind added without one does not compile. */
export const SCANNER_OF_SOURCE: Readonly<Record<ScannerSourceKind, ScannerId>> = Object.freeze({
    'entra-sp': 'agents',
    'okta-app': 'agents',
    vault: 'agents',
    mcp: 'agents',
    runtime: 'agents',
    cicd: 'agents',
    'inflect-register': 'agents',
    code: 'agents',
    'gcp-sa': 'agents',
    'entra-integrations': 'integrations',
});

/** Each scanner's report contract. */
export const SCANNER_CONTRACT: Readonly<Record<ScannerId, string>> = Object.freeze({
    agents: HARNESS_CONTRACT_V4,
    integrations: INTEGRATIONS_CONTRACT_V1,
});

/** Each scanner's signed report, as a run's file output names it. The agent scanner's keeps its name. */
export const SCANNER_REPORT_FILE: Readonly<Record<ScannerId, string>> = Object.freeze({
    agents: RUN_FILE_NAMES.report,
    integrations: INTEGRATION_RUN_FILE_NAMES.report,
});

/** Each scanner in words, for the documents. */
export const SCANNER_TITLE: Readonly<Record<ScannerId, string>> = Object.freeze({
    agents: 'The agent scanner',
    integrations: 'The integrations scanner',
});

export function isAgentSourceKind(kind: string): kind is SourceKind {
    return (SOURCE_KINDS_V3 as readonly string[]).includes(kind);
}

export function isIntegrationsSourceKind(kind: string): kind is IntegrationsSourceKind {
    return (INTEGRATIONS_SOURCE_KINDS as readonly string[]).includes(kind);
}
