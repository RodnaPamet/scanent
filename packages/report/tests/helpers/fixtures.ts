/**
 * Fixtures for the local-results tests: a reader table, report bodies of an
 * estate with no register, and inventories.
 */
import { HARNESS_CONTRACT_V3 } from '@rodnapamet/scanent-contract/harness-contract-rules';
import type { HarnessReportBodyV3 } from '@rodnapamet/scanent-contract/harness-contract';
import type { HarnessSourceKind } from '@rodnapamet/scanent-contract/harness-findings';
import { ALL_HARNESS_CRITERIA, type HarnessCriterionId } from '@rodnapamet/scanent-contract/harness-ladder';

import { INVENTORY_SCHEMA_ID, parseInventory, type ParsedInventory } from '../../src/results/inventory';
import type { CriterionReaders, ReaderKind, ScoreInput, ScoreMeta } from '../../src/results/types';

const REGISTER_AND_INVENTORY: readonly ReaderKind[] = ['inflect-register', 'inventory'];

/**
 * A reader table of the shape the scanner holds: the register reads H1 to H3,
 * the inventory H1, identity sources two H2 criteria, `code` reports NOT MET
 * only, and nothing reads H4 or H5.
 */
export const TEST_READERS: CriterionReaders = Object.fromEntries(
    ALL_HARNESS_CRITERIA.map((criterion): [HarnessCriterionId, CriterionReaders[HarnessCriterionId]] => {
        if (criterion.startsWith('H1.')) return [criterion, { reportedBy: REGISTER_AND_INVENTORY, metBy: REGISTER_AND_INVENTORY }];
        if (criterion === 'H2.credential_bound' || criterion === 'H2.grant_kind_declared') {
            return [criterion, { reportedBy: ['entra-sp', 'gcp-sa', 'inflect-register'], metBy: ['entra-sp', 'gcp-sa', 'inflect-register'] }];
        }
        if (criterion === 'H2.tools_allowlisted') return [criterion, { reportedBy: ['inflect-register', 'code'], metBy: ['inflect-register'] }];
        if (criterion.startsWith('H2.') || criterion.startsWith('H3.')) {
            return [criterion, { reportedBy: ['inflect-register'], metBy: ['inflect-register'] }];
        }
        return [criterion, { reportedBy: [], metBy: [] }];
    }),
) as CriterionReaders;

export const META: ScoreMeta = {
    estate: 'acme',
    registerClaimsVerified: true,
    report: { sha256: 'a'.repeat(64), signerKeyFingerprint: 'b'.repeat(64), signerPinned: true },
};

export const INVENTORY_SHA = `${'0123456789abcdef'.repeat(4)}`;

export const AS_OF = '2026-11-03T03:30:00.000Z';
export const HASH = `sha256:${'a'.repeat(64)}`;

export const ALPHA = 'entra:sp:alpha';
export const BRAVO = 'entra:sp:bravo';

/**
 * An estate with no register: two service principals read from Entra, and the
 * MCP servers. `alpha` holds a credential of its own and read-only tools;
 * `bravo` holds an unpinned write tool.
 */
export function standaloneBody(): HarnessReportBodyV3 {
    return {
        contract: HARNESS_CONTRACT_V3,
        scan: { id: 'acme-20261103T033000Z-0a1b2c3d', asOf: AS_OF, scanner: { agentId: 'agt_scanner', version: '0.1.0', manifestHash: HASH } },
        population: {
            sources: [
                { kind: 'entra-sp', status: 'COMPLETE', rows: 2 },
                { kind: 'mcp', status: 'COMPLETE', rows: 1 },
            ],
        },
        agents: [
            {
                discoveredId: BRAVO,
                discoveredVia: ['entra-sp'],
                registeredAgentId: null,
                owner: null,
                credentials: [],
                tools: [{ server: 'https://mcp.internal.example/crm', name: 'update_opportunity', manifestHash: null, pinned: false, readOnlyHint: false }],
                skills: [],
                verdicts: [],
            },
            {
                discoveredId: ALPHA,
                discoveredVia: ['entra-sp'],
                registeredAgentId: null,
                owner: { kind: 'user', id: 'usr_alpha_owner', source: 'entra-owner' },
                credentials: [{ ref: 'entra://sp/alpha/password/1', ageDays: 3, expires: true, boundToAgent: true, grant: 'unknown' }],
                tools: [{ server: 'https://mcp.internal.example/crm', name: 'list_accounts', manifestHash: HASH, pinned: true, readOnlyHint: true }],
                skills: [],
                verdicts: [{ criterion: 'H2.credential_bound', met: true, evidence: 'entra-sp:servicePrincipals/alpha#credentials' }],
            },
        ],
        findings: [],
        unboundCredentials: [],
    };
}

/** The same body with one source's status replaced. */
export function withSource<B extends { population: { sources: { kind: string; status: string; reason?: string; rows: number }[] } }>(
    body: B,
    kind: HarnessSourceKind,
    reason: string | null,
): B {
    const sources = body.population.sources.map((s) =>
        s.kind !== kind ? s : reason === null ? { kind, status: 'COMPLETE', rows: s.rows } : { kind, status: 'INCOMPLETE', reason, rows: s.rows },
    );
    return { ...body, population: { sources } } as B;
}

export interface RowInput {
    discoveredId: string;
    name?: string;
    owner?: string;
    purpose?: string;
    axes?: unknown;
    riskTier?: unknown;
    riskAssessedOn?: unknown;
    [extra: string]: unknown;
}

/** A row with every field, for the id given. */
export function fullRow(discoveredId: string, over: Partial<RowInput> = {}): RowInput {
    return {
        discoveredId,
        name: 'Invoice triage',
        owner: 'finance-operations',
        purpose: 'Sorts incoming invoices into queues',
        axes: { autonomyLevel: 2, dataAccessScope: 'WRITE_TENANT_DATA', reversibility: 'COMPENSABLE', provenance: 'FIRST_PARTY' },
        riskTier: 'MODERATE',
        riskAssessedOn: '2026-09-30',
        ...over,
    };
}

export function inventoryJson(rows: readonly unknown[]): unknown {
    return { inventory: INVENTORY_SCHEMA_ID, agents: rows };
}

export function inventoryOf(rows: readonly unknown[], format: 'json' | 'csv' = 'json'): ParsedInventory {
    return parseInventory(inventoryJson(rows), { sha256: INVENTORY_SHA, format });
}

export function input(
    body: ScoreInput['body'],
    opts: { inventory?: ParsedInventory | null; configuredSources?: readonly HarnessSourceKind[]; meta?: ScoreMeta } = {},
): ScoreInput {
    return {
        body,
        inventory: opts.inventory ?? null,
        readers: {
            table: TEST_READERS,
            configuredSources: opts.configuredSources ?? (body.population.sources.map((s) => s.kind) as HarnessSourceKind[]),
        },
        meta: opts.meta ?? META,
    };
}
