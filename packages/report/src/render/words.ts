/**
 * THE WORDS OF THE RESULTS — one table of fixed text for every rendering.
 *
 * `summary.html` (its static sections and its interactive view) and
 * `report.pdf` say the same thing about the same scan in the same words.
 * Every label and every sentence that stands for a code is kept here, keyed by
 * the code, so two surfaces cannot word one state two ways. A value the tables
 * do not know falls back to a fixed neutral entry: scanned data never becomes a
 * label.
 */
import { HARNESS_LEVEL_NAMES, type HarnessLevel } from '@rodnapamet/scanent-contract/harness-ladder';
import { HARNESS_MATRIX_CELL_STATES, type HarnessMatrixCellState, type HarnessMatrixRow } from '@rodnapamet/scanent-contract/harness-matrix-model';

/** How one of the table model's seven cell states is shown. */
export interface CellStyle {
    readonly code: string;
    readonly cls: string;
    /** The full meaning, which every surface shows beside or instead of the code. */
    readonly text: string;
    /** A short name, for a filter or a chart. */
    readonly label: string;
}

/** A `Record`, so a state added to the model is a compile error here. */
export const CELL_STYLE: Readonly<Record<HarnessMatrixCellState, CellStyle>> = {
    EVIDENCED: { code: 'E', cls: 'c-e', label: 'Evidenced', text: 'Evidenced: a source observed it' },
    DECLARED: { code: 'D', cls: 'c-d', label: 'Declared', text: 'Evidenced on what the operator declared in the inventory, not observed' },
    MET_UNEVIDENCED: { code: 'M', cls: 'c-m', label: 'Met, no evidence', text: 'Reported met without evidence; counts as not met' },
    NOT_MET: { code: 'N', cls: 'c-n', label: 'Not met', text: 'Not met: a source saw it fail' },
    NOT_MET_DECLARED: { code: 'n', cls: 'c-n', label: 'Not met, declared', text: 'Not met on what the operator declared in the inventory; no source saw it fail' },
    UNANSWERED: { code: '·', cls: 'c-u', label: 'Unanswered', text: 'Unanswered: a configured reader could have reported it and none did; counts as not met' },
    NOT_READABLE: { code: '–', cls: 'c-x', label: 'Not readable', text: 'Not readable: nothing this run was configured to read could have reported it; counts as not met' },
};

/** In the table model's order. */
export const LEGEND: readonly CellStyle[] = HARNESS_MATRIX_CELL_STATES.map((state) => CELL_STYLE[state]);

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;
export const SEVERITY_CLASS: Readonly<Record<string, string>> = { LOW: 'sev-low', MEDIUM: 'sev-medium', HIGH: 'sev-high', CRITICAL: 'sev-critical' };
export const SEVERITY_ORDER: Readonly<Record<string, number>> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

/** The subject of a finding that names no one agent, by code: a spending finding is about a registration several agents share. */
export const SUBJECT_WITHOUT_AGENT: Readonly<Record<string, string>> = {
    SPENDING_AGENT_UNDECLARED: 'One registration, several agents',
};

export const REACH_TEXT: Readonly<Record<string, string>> = {
    READ_ONLY: 'Read only',
    WRITE_OR_EXTERNAL: 'Write or external',
    UNKNOWN: 'Unknown',
};

export const REGISTRATION_TEXT: Readonly<Record<string, string>> = {
    NONE: 'Not registered',
    DECLARED_INVENTORY: 'Declared by the operator',
    OBSERVED_REGISTER: 'In the Inflect register',
};

export const CLASSIFICATION_TEXT: Readonly<Record<string, string>> = {
    REGISTERED: 'Registered',
    SHADOW_AGENT: 'Shadow agent',
    UNREGISTERED_IDENTITY: 'Unregistered identity',
};

export const ESTATE_REGISTRATION_TEXT: Readonly<Record<string, string>> = {
    NONE: 'Nothing: no inventory was supplied and the Inflect register was not read',
    INVENTORY: 'The operator’s inventory (declared by the operator, not observed)',
    INFLECT_REGISTER: 'The Inflect register',
    BOTH: 'The Inflect register, and the operator’s inventory (declared by the operator)',
};

export const UNREADABLE_TEXT: Readonly<Record<string, string>> = {
    NO_READER: 'No reader in scanent reports this criterion',
    READER_NOT_CONFIGURED: 'A reader exists; this run did not configure it',
};

export const UNBOUND_TEXT: Readonly<Record<string, string>> = {
    OWN_SOURCE_INCOMPLETE: 'The source that listed it was not read in full',
    IDENTITY_SOURCE_INCOMPLETE: 'A source that could name the agent it is bound to was not read in full',
};

export const MODEL_SIGN_TEXT: Readonly<Record<string, string>> = {
    FOUND_IN_CODE: 'found in agent code',
    FOUND_IN_RUNTIME: 'found in a tracing system',
    FOUND_ON_MCP_SERVER: 'found on an MCP server',
    LISTS_A_TOOL: 'lists a tool',
    LISTS_A_MODEL: 'lists a model endpoint',
};

export const BASIS_TEXT: Readonly<Record<string, string>> = {
    OBSERVED: 'Observed: a source reported it',
    DECLARED: 'Declared by the operator in the inventory; no source observed it',
};

/** Where an agent stands against its bar, in the words every surface uses. */
export const STANDING_TEXT = {
    AT_BAR: 'At bar',
    BELOW_BAR: 'Below bar',
    NOT_JUDGED: 'Not judged',
    NO_BAR: 'Held to no bar',
} as const;

export type Standing = keyof typeof STANDING_TEXT;

/**
 * A row's standing, from the table model: an unregistered automated identity
 * is held to no bar, so it is never "below" one, whatever its level.
 */
export function standingOf(row: Pick<HarnessMatrixRow, 'barStatus' | 'heldToBar' | 'countsAsShortfall'>): Standing {
    if (row.barStatus === 'NOT_JUDGED') return 'NOT_JUDGED';
    if (!row.heldToBar) return 'NO_BAR';
    return row.countsAsShortfall ? 'BELOW_BAR' : 'AT_BAR';
}

/** The word for each severity's tile and bar. */
export const SEVERITY_TEXT: Readonly<Record<string, string>> = { CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low' };

export const SOURCE_CHANGE_TEXT: Readonly<Record<string, string>> = {
    NOW_INCOMPLETE: 'was read in full and is now incomplete',
    NOW_COMPLETE: 'was incomplete and is now read in full',
    REASON_CHANGED: 'is still incomplete, for a different reason',
    ADDED: 'is new in this run',
    NO_LONGER_READ: 'is no longer listed',
};

export const LEVEL_CHANGE_TEXT: Readonly<Record<string, string>> = {
    LEVEL_UP: 'level up',
    LEVEL_DOWN: 'level down',
    OBSERVED_LEVEL_UP: 'level on observation alone up',
    OBSERVED_LEVEL_DOWN: 'level on observation alone down',
    NOW_NOT_JUDGED: 'was judged and is now not judged; no level is compared',
    NOW_JUDGED: 'was not judged and is now judged; no level is compared',
};

export const DIFF_OUTCOME_TEXT: Readonly<Record<string, string>> = {
    SAME: 'No difference, and every comparison could be made.',
    DIFFERENT: 'The two runs differ.',
    SAME_AS_FAR_AS_COMPARED: 'No difference was found, but not every comparison could be made. This is not a statement that nothing changed.',
};

export const DIFF_WARNING_TEXT: Readonly<Record<string, string>> = {
    INVENTORY_DIFFERS: 'The two runs were scored against different inventories (or one had none), so declared criteria and registrations show as changes',
    SCANNER_DIFFERS: 'The two runs are from different scanners, so nothing absent from the new run is concluded',
    ESTATE_DIFFERS: 'The two runs name different estates, so nothing absent from the new run is concluded',
    SIGNER_NOT_PINNED: 'A signed report was verified against the key it carries itself: integrity, not origin',
    REGISTER_CLAIMS_NOT_VERIFIED: 'A report’s register links are taken as stated, not read by the run that scored it',
    TOOL_EVIDENCE_OLDER_RULE: 'One results file was written before agents carried their tool-evidence sources, so whether an unpinned write tool is closed was decided from where the agent was found',
};

/** Why a previous run was not compared with this one. */
export const PREVIOUS_NOT_COMPARED_TEXT: Readonly<Record<string, string>> = {
    NOT_LATER: 'The run the output directory names as the latest is not earlier than this one',
    LADDER_DIFFERS: 'The two runs were scored on different ladder versions, so their levels cannot be compared',
    SCANNER_DIFFERS: 'The two runs are from different scanners; what one did not see says nothing about the other',
    UNREADABLE: 'The previous run’s results file could not be read as a results file, so nothing was compared',
};

export function fixed(table: Readonly<Record<string, string>>, key: string, fallback: string): string {
    return Object.prototype.hasOwnProperty.call(table, key) ? table[key] : fallback;
}

export function levelName(level: HarnessLevel): string {
    return fixed(HARNESS_LEVEL_NAMES, level, '');
}

export function plural(n: number, one: string, many: string): string {
    return `${n} ${n === 1 ? one : many}`;
}

/** `H2.credential_bound` → `credential bound`: the id's own words, for a column head. */
export function criterionWords(criterion: string): string {
    return criterion.slice(criterion.indexOf('.') + 1).replace(/_/g, ' ');
}

/** A sentence for a judgement reason or caveat code. The code is always shown beside it. */
export function reasonSentence(code: string): string {
    const [head, kind, reason] = code.split(':');
    if (head === 'SOURCE_INCOMPLETE' && kind !== undefined) {
        return reason === 'NOT_LISTED'
            ? `It was found through ${kind}, which the report does not list as a source`
            : `A source it was found through, ${kind}, was not read in full (${reason ?? 'no reason given'})`;
    }
    if (head === 'VERDICT_SOURCE_INCOMPLETE' && kind !== undefined) {
        return `${kind}, which reports on agents other sources find, was not read in full (${reason ?? 'no reason given'})`;
    }
    if (head === 'OTHER_SOURCE_INCOMPLETE' && kind !== undefined) {
        return `Another source, ${kind}, was not read in full; it does not bear on this agent`;
    }
    if (head === 'SOURCES_UNREADABLE') return 'The scan’s sources could not be read back, so nothing is known to have been read in full';
    if (head === 'VERDICTS_UNREADABLE') return 'The agent’s verdicts could not be read back';
    return 'See the code';
}

/**
 * What every rendering says it does not say. The same statements close the
 * PDF and stand beside the interactive view, so a reader of either learns the
 * same limits.
 */
export const CAVEATS: readonly string[] = [
    'A source that was not read in full closes nothing: an agent found through it, or one a verdict source could have reported on, is not judged and has no level.',
    'A criterion nobody answered counts as not met. Unanswered means a configured reader could have reported it and none did; not readable means nothing this run was configured to read could have.',
    'A criterion the operator declared in the inventory is never shown as observed. The level on observation alone is stated beside any level that rests on a declaration.',
    'An unregistered automated identity shows no sign of a model and is held to no bar. The scan cannot show that it runs no model.',
    'A scan that found no agents evidences nothing. It is a finding, never a clean result.',
    'Where code was read and no payment client was seen, that is what the reader saw in the agent’s own file. It is not evidence that the agent cannot pay.',
    'This is derived from the signed report and the operator’s inventory. The signed report is the record.',
];
