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
 * Types and the schema id: nothing else runs from this module.
 */
import type { HarnessFindingCode, HarnessSourceKind, IntakeConflict, StoredReach } from '@scanent/contract/harness-findings';
import type { CriterionState, HarnessCriterionId, HarnessLevel } from '@scanent/contract/harness-ladder';
import type { HarnessReportBody } from '@scanent/contract/harness-contract';

import type { ParsedInventory } from './inventory';

/** The id `results.json` names itself by. A change of shape is a new id. */
export const RESULTS_SCHEMA = 'scanent-results/1';

/** What can report a verdict: a source kind, or the operator's inventory. */
export type ReaderKind = HarnessSourceKind | 'inventory';

/**
 * For each criterion, the readers that report a verdict about it at all
 * (`reportedBy`) and the ones that can report it MET (`metBy`, a subset). A
 * reader that can only say NOT MET (the `code` source) evidences a failure and
 * never a pass, so it does not make a criterion readable.
 *
 * The table itself belongs to whoever owns the readers: the scanner holds it
 * and holds it to its sources by test. The scorer only consumes it.
 */
export type CriterionReaders = Readonly<
    Record<HarnessCriterionId, { readonly reportedBy: readonly ReaderKind[]; readonly metBy: readonly ReaderKind[] }>
>;

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
}

export type RegistrationBasis = 'NONE' | 'DECLARED_INVENTORY' | 'OBSERVED_REGISTER';
export type EstateRegistrationBasis = 'NONE' | 'INVENTORY' | 'INFLECT_REGISTER' | 'BOTH';
export type VerdictBasis = 'OBSERVED' | 'DECLARED';
export type UnreadableWhy = 'NO_READER' | 'READER_NOT_CONFIGURED';
export type UnboundNotConcludedWhy = 'OWN_SOURCE_INCOMPLETE' | 'IDENTITY_SOURCE_INCOMPLETE';

export interface LocalSourceResult {
    readonly kind: HarnessSourceKind;
    readonly status: 'COMPLETE' | 'INCOMPLETE';
    /** The contract's reason; null when COMPLETE. */
    readonly reason: string | null;
    readonly rows: number;
    /** Agents discovered via this kind. */
    readonly agents: number;
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
    readonly code: HarnessFindingCode;
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
    readonly coverage: {
        /** The highest level this run could have stated for any agent. */
        readonly reachableLevel: HarnessLevel;
        readonly unreadable: readonly {
            readonly criterion: HarnessCriterionId;
            readonly why: UnreadableWhy;
            /** The readers that could report it met; empty for `NO_READER`. */
            readonly readers: readonly ReaderKind[];
        }[];
    };
    readonly estate: {
        /** No agents at all: `EMPTY_SCAN`, a finding and never a clean result. */
        readonly empty: boolean;
        readonly agentCount: number;
        readonly judgedCount: number;
        readonly notJudgedCount: number;
        /** Judged agents only. */
        readonly byLevel: Readonly<Record<HarnessLevel, number>>;
        /** Judged agents below their bar. */
        readonly shortfallCount: number;
        readonly registrationBasis: EstateRegistrationBasis;
        readonly shadowAgents: readonly string[];
        readonly orphanCredentials: readonly { readonly ref: string; readonly sourceKind: string }[];
        /** Seen unbound, and the planner could not open a finding. */
        readonly unboundNotConcluded: readonly {
            readonly ref: string;
            readonly sourceKind: string;
            readonly why: UnboundNotConcludedWhy;
        }[];
        readonly registrationConflicts: readonly IntakeConflict[];
    };
    /** Sorted by `discoveredId`, by code unit. */
    readonly agents: readonly LocalAgentResult[];
    /** In the planner's order. */
    readonly findings: readonly LocalFinding[];
}
