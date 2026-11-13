/**
 * LOCAL RESULTS — what one scan means to somebody with no tenant.
 *
 * `LocalResults` is the content of `results.json`: every agent the scan found,
 * its level on the harness ladder where one can be stated, the findings the
 * contract's planner derives, and what this run could not have seen. It is a
 * function of the signed report body, the operator's inventory and a few facts
 * the caller holds (`ScoreMeta`), and of nothing else: it holds no clock
 * reading of its own, so the same inputs give the same value.
 *
 * Three things it never does:
 *
 *   • STATE A LEVEL FOR AN AGENT IT CANNOT JUDGE. An agent whose sources were
 *     not read in full carries `judgement.state: 'NOT_JUDGED'` and the reasons,
 *     and no level, bar or shortfall member at all.
 *   • PASS A DECLARATION OFF AS AN OBSERVATION. What the operator's inventory
 *     says is under `declared` and `basis: 'DECLARED'`, and `observedLevel` is
 *     the level with every declared verdict removed.
 *   • LEAVE AN ABSENCE TO BE READ AS A FAILURE. `coverage` and each cell's
 *     `readable` say which criteria no configured reader could have answered.
 *
 * Types and the schema ids, and two one-line guards over them.
 */
import type { HarnessFindingCode, HarnessSourceKind, IntakeConflict, ModelSign, StoredReach } from '@rodnapamet/scanent-contract/harness-findings';
import type { CriterionState, HarnessCriterionId, HarnessLevel } from '@rodnapamet/scanent-contract/harness-ladder';
import type { HarnessPaymentCapability, HarnessReportBody } from '@rodnapamet/scanent-contract/harness-contract';

import type { CriterionReaders, HarnessMatrixCoverage, VerdictBasis } from '@rodnapamet/scanent-contract/harness-matrix-model';
import type { ApplicationOrigin, ConsentType, OwnerKind, SignInReadState } from '@rodnapamet/scanent-contract/integrations-contract-rules';
import type { IntegrationFindingCode, IntegrationNotConcludedWhy } from '@rodnapamet/scanent-contract/integrations-findings';
import type { PermissionClass } from '@rodnapamet/scanent-contract/integrations-scopes';

import type { ParsedInventory } from './inventory';

/** The id `results.json` names itself by. A change of shape is a new id. */
export const RESULTS_SCHEMA = 'scanent-results/1';

/**
 * What can report a verdict (a source kind, or the operator's inventory), and
 * for each criterion which readers can report it at all and which can report it
 * MET: the contract's table model owns both, and the scanner holds the table.
 */
export type { CriterionReaders, ReaderKind } from '@rodnapamet/scanent-contract/harness-matrix-model';

/** Facts about the run that the report body does not carry and the scorer cannot derive. */
export interface ScoreMeta {
    /** The configuration's estate label; null when scoring a bare report. */
    readonly estate: string | null;
    /**
     * Whether the report's `registeredAgentId` claims were read from the
     * register by this run. False when scoring a report this run did not build:
     * the claims are then trusted, and the results say so.
     */
    readonly registerClaimsVerified: boolean;
    readonly report: {
        /** SHA-256 (hex) of the bytes of the signed report. */
        readonly sha256: string;
        /** `harnessKeyFingerprint` of the key the report carries. */
        readonly signerKeyFingerprint: string;
        /** False when the signature was checked against the key the report itself carries. */
        readonly signerPinned: boolean;
    };
}

export interface ScoreInput {
    /** A body that passed the contract's strict schema: the one that was signed. */
    readonly body: HarnessReportBody;
    /** The operator's inventory, already parsed; null when none was supplied. */
    readonly inventory: ParsedInventory | null;
    readonly readers: {
        readonly table: CriterionReaders;
        /** The source kinds this run was configured to read (the inventory is added when one is supplied). */
        readonly configuredSources: readonly HarnessSourceKind[];
    };
    readonly meta: ScoreMeta;
    /**
     * What the run's own sources said about a read that stopped, beyond the
     * reason the report carries. Absent when the report is scored without the
     * run that made it (`diff`, a report from elsewhere).
     */
    readonly sourceNotes?: readonly SourceNote[];
}

/** One place a source did not read, as the operator would look for it. */
export interface NotReadPlace {
    readonly where: string;
    /** The contract's reason for this place. */
    readonly reason: string;
}

/** A source kind's own account of a read that stopped. */
export interface SourceNote {
    readonly kind: string;
    /** Fixed words from the scanner; null when the source gave none. */
    readonly detail: string | null;
    /** The first places not read; `notReadTotal` counts them all. */
    readonly notRead: readonly NotReadPlace[];
    readonly notReadTotal: number;
}

/** Where an agent's tools are evidenced: a definition in code, or an MCP server's listing. */
export type ToolEvidenceSourceKind = 'code' | 'mcp';
export type RegistrationBasis = 'NONE' | 'DECLARED_INVENTORY' | 'OBSERVED_REGISTER';
export type EstateRegistrationBasis = 'NONE' | 'INVENTORY' | 'INFLECT_REGISTER' | 'BOTH';
/** Where a cell's verdict came from, and why a criterion was not readable: the table model's words. */
export type { UnreadableWhy, VerdictBasis } from '@rodnapamet/scanent-contract/harness-matrix-model';
export type UnboundNotConcludedWhy = 'OWN_SOURCE_INCOMPLETE' | 'IDENTITY_SOURCE_INCOMPLETE';

/**
 * What a scan read that suggests a principal runs a model, and the type of
 * one: the contract's own (`MODEL_SIGNS` in `harness-findings`), re-exported.
 * A credential's NAME is not one: a secret called after a model provider is a
 * guess about what holds it.
 */
export { MODEL_SIGNS, type ModelSign } from '@rodnapamet/scanent-contract/harness-findings';

/**
 * A finding the local results carry. Every code is the contract planner's:
 * UNREGISTERED_IDENTITY, once raised here alone, is the planner's own since
 * the contract carried it, so a tenant and a standalone run class a principal
 * the same way. The local results rewrite some descriptions (who could have
 * named the agent, what this run could not read) and never a code.
 */
export type LocalFindingCode = HarnessFindingCode;

/**
 * One place an agent's code calls a payment client, as `/4` reports it: the
 * protocol, the library and the `code://` locator of the call. Never an
 * amount, a wallet or a key.
 */
export type LocalPaymentCapability = HarnessPaymentCapability;

export interface LocalSourceResult {
    readonly kind: HarnessSourceKind;
    readonly status: 'COMPLETE' | 'INCOMPLETE';
    /** The contract's reason; null when COMPLETE. */
    readonly reason: string | null;
    readonly rows: number;
    /** Agents discovered via this kind. */
    readonly agents: number;
    /**
     * Why the read stopped, in the scanner's fixed words. Present only for an
     * INCOMPLETE source of a run that scored its own scan.
     */
    readonly detail?: string;
    /** The first places that were not read, where the source can name them. */
    readonly notRead?: readonly NotReadPlace[];
    /** Every place not read, counted; at least `notRead.length`. */
    readonly notReadTotal?: number;
}

export interface LocalCriterionCell {
    readonly criterion: HarnessCriterionId;
    readonly state: CriterionState;
    /** Where the collapsed verdict came from; null when the criterion is unanswered. */
    readonly basis: VerdictBasis | null;
    readonly evidence: string | null;
    /** Whether any reader this run configured could have reported the criterion met. */
    readonly readable: boolean;
}

export type LocalJudgement =
    | {
          readonly state: 'JUDGED';
          /** Observed and declared verdicts together. */
          readonly level: HarnessLevel;
          /** Declared verdicts removed. */
          readonly observedLevel: HarnessLevel;
          readonly bar: HarnessLevel;
          readonly shortfall: boolean;
          readonly blockingNextRung: readonly HarnessCriterionId[];
          /** `OTHER_SOURCE_INCOMPLETE:<kind>`, one per incomplete source that does not bear on this agent. */
          readonly caveats: readonly string[];
      }
    | {
          readonly state: 'NOT_JUDGED';
          /** `SOURCE_INCOMPLETE:<kind>:<reason>` and `VERDICT_SOURCE_INCOMPLETE:<kind>:<reason>`. Never empty. */
          readonly reasons: readonly string[];
      };

export interface LocalAgentResult {
    readonly discoveredId: string;
    readonly discoveredVia: readonly HarnessSourceKind[];
    /**
     * Every source that must have been read in full before this agent's report
     * is evidence that it holds no unpinned write tool: each listed tool's own
     * (`code` for a definition in code, `mcp` for a server), and where a tool
     * the report left out would have been. Sorted, never empty.
     *
     * OPTIONAL, because a file written before the member existed has none. A
     * reader that finds it absent falls back to `discoveredVia`, which cannot
     * see a tool served over MCP to an agent found only in code.
     */
    readonly toolEvidenceSources?: readonly ToolEvidenceSourceKind[];
    /** What the operator's inventory says of this agent. `row` is its 1-based position in the file. */
    readonly declared: null | { readonly name: string; readonly owner: string; readonly purpose: string; readonly row: number };
    /** The owner a source read from the estate. */
    readonly observedOwner: null | { readonly kind: 'user' | 'group'; readonly ref: string };
    readonly registration: {
        readonly basis: RegistrationBasis;
        /** `inventory:row-<n>`, or the register's id; null when not registered. */
        readonly ref: string | null;
    };
    readonly judgement: LocalJudgement;
    /**
     * What the scan read that suggests this principal runs a model, in the
     * order of `MODEL_SIGNS`. Empty: nothing did. With no registration, that
     * is an unregistered automated identity, not a shadow agent.
     *
     * OPTIONAL, because a file written before the member existed has none; a
     * reader that finds it absent treats every unregistered principal as a
     * shadow agent, as that file's own findings do.
     */
    readonly modelSigns?: readonly ModelSign[];
    /**
     * Where the agent's code calls a payment client (`/4`). THREE STATES, as
     * the report has them: `null` is NOT REPORTED (a `/2` or `/3` report, or
     * an agent no code read reported); `[]` is a code read that saw no payment
     * client called in the agent's own file, which is what that reader saw and
     * never evidence that the agent cannot pay; entries are what it saw.
     *
     * OPTIONAL, because a file written before the member existed has none; a
     * reader treats it absent as NOT REPORTED.
     */
    readonly paymentCapabilities?: readonly LocalPaymentCapability[] | null;
    readonly reach: StoredReach;
    /** Every criterion, in ladder order. */
    readonly criteria: readonly LocalCriterionCell[];
    readonly counts: {
        readonly credentials: number;
        readonly tools: number;
        readonly writeCapableTools: number;
        readonly unpinnedWriteTools: number;
        /** Null: the report did not say. Zero: it reported none. */
        readonly models: number | null;
    };
}

export interface LocalFinding {
    readonly code: LocalFindingCode;
    readonly sourceRef: string;
    readonly severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    readonly type: 'NONCONFORMITY' | 'OBSERVATION';
    /** The agent the finding is about; null for a finding about the scan or a credential. */
    readonly discoveredId: string | null;
    readonly title: string;
    readonly description: string;
}

export interface LocalResults {
    readonly schema: typeof RESULTS_SCHEMA;
    readonly ladder: {
        readonly version: string;
        readonly levels: readonly HarnessLevel[];
        readonly criteria: Readonly<Record<HarnessLevel, readonly HarnessCriterionId[]>>;
    };
    readonly scan: {
        readonly id: string;
        readonly asOf: string;
        readonly estate: string | null;
        readonly contract: string;
        readonly scanner: { readonly agentId: string; readonly version: string; readonly manifestHash: string };
        /** `isScanComplete`: every listed source read in full, and at least one listed. */
        readonly complete: boolean;
        readonly registerClaimsVerified: boolean;
    };
    readonly report: ScoreMeta['report'];
    readonly inventory: null | {
        readonly provenance: 'DECLARED_BY_OPERATOR';
        readonly sha256: string;
        readonly format: 'json' | 'csv';
        readonly rows: number;
        readonly matched: number;
        /** Declared by the operator and not found by this scan. Never "gone". */
        readonly unmatched: readonly string[];
    };
    readonly sources: readonly LocalSourceResult[];
    /** What this run could have evidenced: the table model's coverage, over the readers it configured. */
    readonly coverage: HarnessMatrixCoverage;
    readonly estate: {
        /** No agents at all: `EMPTY_SCAN`, a finding and never a clean result. */
        readonly empty: boolean;
        readonly agentCount: number;
        readonly judgedCount: number;
        readonly notJudgedCount: number;
        /** Judged agents only. */
        readonly byLevel: Readonly<Record<HarnessLevel, number>>;
        /** Judged agents below their bar. An unregistered automated identity is held to none, and is not counted. */
        readonly shortfallCount: number;
        readonly registrationBasis: EstateRegistrationBasis;
        /** Not registered, and showing a sign of a model. */
        readonly shadowAgents: readonly string[];
        /**
         * Not registered, and showing no sign of a model: listed, raised as a
         * finding of their own, and not held to the agent bar. OPTIONAL, for a
         * file written before the member existed: there, every unregistered
         * principal is in `shadowAgents`.
         */
        readonly unregisteredIdentities?: readonly string[];
        /**
         * Agents whose code calls a payment client (`/4`), sorted. Empty when
         * none was seen, which says nothing about the agents no code read
         * reported. OPTIONAL, for a file written before the member existed.
         */
        readonly payingAgents?: readonly string[];
        readonly orphanCredentials: readonly { readonly ref: string; readonly sourceKind: string }[];
        /** Seen unbound, and the planner could not open a finding. */
        readonly unboundNotConcluded: readonly {
            readonly ref: string;
            readonly sourceKind: string;
            readonly why: UnboundNotConcludedWhy;
        }[];
        /**
         * Two registrations of one agent that disagree. Always empty from the
         * local scorer: an inventory row carries no register id, so an agent in
         * both the register and the inventory is an overlap, not a conflict.
         */
        readonly registrationConflicts: readonly IntakeConflict[];
    };
    /** Sorted by `discoveredId`, by code unit. */
    readonly agents: readonly LocalAgentResult[];
    /** In the planner's order. */
    readonly findings: readonly LocalFinding[];
    /**
     * The integrations scanner's results: present only when the run configured
     * an integrations source. OPTIONAL, so a file of an agents-only run, and
     * every file written before the member existed, is read as it was written.
     */
    readonly integrations?: LocalIntegrationsResults;
}

// ── The integrations scanner ──

/**
 * The id `results.json` names itself by for a run in which only the
 * integrations scanner ran. A run of the agent scanner (with or without the
 * integrations scanner) writes `RESULTS_SCHEMA`, whose agent members are
 * required: a run with no agent scan has none to give, and a file that left
 * them empty would read as an agent scan that found nothing. So it is another
 * shape, and another id.
 */
export const INTEGRATIONS_ONLY_RESULTS_SCHEMA = 'scanent-results-integrations/1';

/** The scanners one run ran, in the order the platform lists them. */
export type RunScanners = readonly ('agents' | 'integrations')[];

/** `results.json` of a run in which the integrations scanner ran and the agent scanner did not. */
export interface IntegrationsOnlyResults {
    readonly schema: typeof INTEGRATIONS_ONLY_RESULTS_SCHEMA;
    /** Always `['integrations']`: stated, so no reader takes the absent agent members for an empty agent scan. */
    readonly scanners: readonly ['integrations'];
    readonly scan: {
        readonly id: string;
        readonly asOf: string;
        readonly estate: string | null;
        readonly scanner: { readonly agentId: string; readonly version: string; readonly manifestHash: string };
    };
    readonly signer: {
        /** `harnessKeyFingerprint` of the key the report carries. */
        readonly keyFingerprint: string;
        /** False when the signature was checked against the key the report itself carries. */
        readonly pinned: boolean;
    };
    readonly integrations: LocalIntegrationsResults;
}

/** What one run's `results.json` holds: an agent scan's results (perhaps with an integrations section), or the integrations scanner's alone. */
export type RunResults = LocalResults | IntegrationsOnlyResults;

/** Whether a run's results are an agent scan's. */
export function isAgentResults(r: RunResults): r is LocalResults {
    return r.schema === RESULTS_SCHEMA;
}

/** The integrations section of a run's results, wherever it is; undefined when the integrations scanner did not run. */
export function integrationsOf(r: RunResults): LocalIntegrationsResults | undefined {
    return r.integrations;
}

/** One integrations source, as the local results show it. */
export interface LocalIntegrationsSource {
    readonly kind: string;
    readonly status: 'COMPLETE' | 'INCOMPLETE';
    /** The contract's reason; null when COMPLETE. */
    readonly reason: string | null;
    readonly rows: number;
    /** Applications reported from this source. */
    readonly applications: number;
    readonly signInActivity: { readonly status: SignInReadState; readonly reason: string | null; readonly rows: number | null };
    /** Why a read stopped, in the scanner's fixed words; only for a source of this run that did not read everything. */
    readonly detail?: string;
}

/** One permission an application holds, as the planner classed it. */
export interface LocalApplicationPermission {
    readonly via: 'DELEGATED' | 'APPLICATION';
    readonly resourceAppId: string | null;
    /** The scope or app role's name; null when the read could not resolve the role. */
    readonly name: string | null;
}

export interface LocalApplicationResult {
    readonly id: string;
    readonly sourceKind: string;
    readonly appId: string | null;
    /** As the directory holds it; null when it was absent or withheld. */
    readonly displayName: string | null;
    readonly origin: ApplicationOrigin;
    /** Null: the read could not tell. */
    readonly publisherVerified: boolean | null;
    /** Null: not read. Empty: read, and it has none. */
    readonly owners: readonly { readonly kind: OwnerKind; readonly id: string }[] | null;
    readonly delegatedGrants: {
        readonly read: boolean;
        readonly grants: readonly {
            readonly resourceAppId: string | null;
            readonly consentType: ConsentType;
            readonly principalCount: number | null;
            readonly scopes: readonly string[];
            readonly unreadableScopes: number;
        }[];
    };
    readonly applicationPermissions: {
        readonly read: boolean;
        readonly permissions: readonly { readonly resourceAppId: string | null; readonly roleId: string; readonly name: string | null }[];
    };
    /** HIGH: a high-privilege grant was seen. NOT_HIGH: every grant was read, every one known, none high. */
    readonly privilege: 'HIGH' | 'NOT_HIGH' | 'NOT_CONCLUDED';
    /** The classes its high-privilege grants reach, in the table's order. */
    readonly classes: readonly PermissionClass[];
    readonly highPermissions: readonly LocalApplicationPermission[];
    /** Permissions the classification table does not know: never called high, never called low. */
    readonly unknownPermissions: readonly LocalApplicationPermission[];
    readonly signIn: { readonly read: boolean; readonly lastSeen: string | null; readonly daysSince: number | null };
    readonly usage: 'USED' | 'UNUSED' | 'NOT_CONCLUDED';
    readonly credentials: number;
}

export interface LocalIntegrationFinding {
    readonly code: IntegrationFindingCode;
    readonly sourceRef: string;
    readonly severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    /** The application it is about; null for a finding about a source. */
    readonly applicationId: string | null;
    readonly title: string;
    readonly description: string;
}

export interface LocalIntegrationsResults {
    /** The integrations report's contract. */
    readonly contract: string;
    readonly report: {
        /** The file it is written as, beside `report.signed.json`. */
        readonly file: string;
        /** SHA-256 (hex) of the bytes of the signed integrations report. */
        readonly sha256: string;
    };
    /** Every source read in full, and no sign-in read stopped part way, and at least one source. */
    readonly complete: boolean;
    /** The window "unused" was planned over, as the configuration set it. */
    readonly unusedDays: number;
    readonly sources: readonly LocalIntegrationsSource[];
    /** Sorted by `id`. */
    readonly applications: readonly LocalApplicationResult[];
    /** In the planner's order. */
    readonly findings: readonly LocalIntegrationFinding[];
    /** What could not be concluded, and why. Never empty when something was not read. */
    readonly notConcluded: readonly {
        readonly code: IntegrationFindingCode;
        readonly applicationId: string | null;
        readonly sourceKind: string;
        readonly why: IntegrationNotConcludedWhy;
    }[];
    /** Every permission name the classification table does not know, once per API. */
    readonly unknownPermissions: readonly { readonly resourceAppId: string | null; readonly name: string }[];
    readonly counts: {
        readonly applications: number;
        readonly highPrivilege: number;
        readonly unverifiedPublisher: number;
        readonly noOwner: number;
        readonly unused: number;
    };
}
