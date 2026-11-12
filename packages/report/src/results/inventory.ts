/**
 * THE OPERATOR'S INVENTORY — what somebody with no register says of their agents.
 *
 * Without a register nothing can show an agent is registered or owned, so
 * every agent would read as a shadow agent. The inventory is the operator's own
 * list: an id, a name, an owner, a purpose, and optionally the declared axes
 * and a dated risk tier. The axes and the tiers are the ones Inflect's agent
 * register holds, by the same names and values, so a row says of an agent what
 * a register entry would. Four rules hold it:
 *
 *   • IT MATCHES BY EXACT `discoveredId` AND NOTHING ELSE. No case folding, no
 *     trimming, no prefix, no name. An exact id is the only match that cannot
 *     attach one agent's owner to another.
 *   • EVERYTHING IT SAYS IS DECLARED, NEVER OBSERVED. Its verdicts carry an
 *     `inventory:` evidence reference, and the scorer keeps them apart.
 *   • IT EVIDENCES THE FOUR H1 CRITERIA AND NOTHING ABOVE. The schema has no
 *     field for any other criterion, so no content can claim one.
 *   • A REFUSAL NAMES THE ROW AND THE FIELD, NEVER THE VALUE. The value refused
 *     may be the credential somebody pasted into the wrong cell.
 *
 * PURE: no clock, no file, no hashing. The caller reads the file, hashes its
 * bytes and decodes them (JSON, or CSV into the same row objects); one schema
 * judges both forms.
 */
import { z } from 'zod';

import { MAX_AGENTS, MAX_ID_CHARS } from '@rodnapamet/scanent-contract/harness-contract';
import { firstSecretShapedMember } from '@rodnapamet/scanent-contract/harness-findings';
import type { CriterionVerdict } from '@rodnapamet/scanent-contract/harness-ladder';

/**
 * The id a JSON inventory names itself by. `/2` replaced `/1` when the axes
 * and the risk tiers took the names and values of Inflect's agent register;
 * `/1` is refused, and the refusal says what changed (`RETIRED_INVENTORY_SCHEMAS`).
 */
export const INVENTORY_SCHEMA_ID = 'scanent-inventory/2';

/** A report carries at most this many agents, so an inventory names at most as many. */
export const MAX_INVENTORY_ROWS = MAX_AGENTS;

/**
 * How old a declared risk assessment may be, in whole days before the scan's
 * `asOf`, and still count.
 *
 * THIS WINDOW IS SCANENT'S OWN. Inflect's register has no age limit: there a
 * tier is fresh while the agent's newest completed risk assessment has not been
 * marked stale, and it is marked stale when the agent changes in a way that
 * raises risk after it was assessed. An inventory holds no assessment to
 * compare an agent with, so a date and a window are what it can state.
 */
export const INVENTORY_TIER_MAX_AGE_DAYS = 365;

/**
 * THE FOUR AXES, AS INFLECT'S AGENT REGISTER DECLARES THEM: the same names,
 * the same values, in the same order. All four or none.
 *
 * `autonomyLevel` is a whole number on the register's ladder, 0 (suggests
 * only) to 6 (acts unattended across systems). `dataAccessScope` runs from the
 * least exposing to the most. `reversibility` runs from what can be restored
 * to what cannot be undone. `provenance` is who wrote the agent.
 */
export const INVENTORY_AUTONOMY_LEVEL_MIN = 0;
export const INVENTORY_AUTONOMY_LEVEL_MAX = 6;
export const INVENTORY_DATA_ACCESS_SCOPES = ['NONE', 'READ_METADATA', 'READ_TENANT_DATA', 'WRITE_TENANT_DATA', 'EXTERNAL_EGRESS'] as const;
export const INVENTORY_REVERSIBILITIES = ['REVERSIBLE', 'COMPENSABLE', 'TERMINAL'] as const;
export const INVENTORY_PROVENANCES = ['FIRST_PARTY', 'THIRD_PARTY'] as const;
/** The members of `axes`, in the order the documents and the CSV header give them. */
export const INVENTORY_AXES = ['autonomyLevel', 'dataAccessScope', 'reversibility', 'provenance'] as const;
/** The register's risk tiers, lowest first. */
export const INVENTORY_RISK_TIERS = ['LOW', 'MODERATE', 'HIGH', 'CRITICAL'] as const;

/**
 * Schema ids this version once read and now refuses, each with what changed
 * since. The text is this module's own, so a refusal may repeat it.
 */
export const RETIRED_INVENTORY_SCHEMAS: Readonly<Record<string, string>> = {
    'scanent-inventory/1':
        'the axes are now autonomyLevel (a whole number, 0 to 6), dataAccessScope, reversibility and provenance, '
        + 'in place of autonomy, dataClass and reach, and the risk tier MEDIUM is now MODERATE',
};

/** The four criteria a matched row can evidence. Nothing else, ever. */
export const INVENTORY_CRITERIA = ['H1.registered', 'H1.owner', 'H1.axes_declared', 'H1.tier_scored_fresh'] as const;

const hasControlCharacter = (v: string): boolean =>
    [...v].some((ch) => {
        const code = ch.charCodeAt(0);
        return code < 0x20 || code === 0x7f;
    });

function text(max: number) {
    return z
        .string()
        .min(1)
        .max(max)
        .refine((v) => !hasControlCharacter(v), 'a control character')
        .refine((v) => v.trim().length > 0, 'blank');
}

/** `YYYY-MM-DD` to its day number since the epoch (UTC), or null when it is not a real date. */
export function dayNumberOf(isoDate: string): number | null {
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(isoDate);
    if (m === null) return null;
    const [year, month, day] = [Number(m[1]), Number(m[2]), Number(m[3])];
    const ms = Date.UTC(year, month - 1, day);
    const back = new Date(ms);
    if (back.getUTCFullYear() !== year || back.getUTCMonth() !== month - 1 || back.getUTCDate() !== day) return null;
    return Math.floor(ms / 86_400_000);
}

const InventoryRowSchema = z
    .object({
        /** As the scan reports it. The contract's own bound on an id. */
        discoveredId: z.string().min(1).max(MAX_ID_CHARS),
        name: text(256),
        owner: text(256),
        purpose: text(512),
        axes: z
            .object({
                autonomyLevel: z.number().int().min(INVENTORY_AUTONOMY_LEVEL_MIN).max(INVENTORY_AUTONOMY_LEVEL_MAX),
                dataAccessScope: z.enum(INVENTORY_DATA_ACCESS_SCOPES),
                reversibility: z.enum(INVENTORY_REVERSIBILITIES),
                provenance: z.enum(INVENTORY_PROVENANCES),
            })
            .strict()
            .optional(),
        riskTier: z.enum(INVENTORY_RISK_TIERS).optional(),
        riskAssessedOn: z
            .string()
            .refine((v) => dayNumberOf(v) !== null, 'not a YYYY-MM-DD date')
            .optional(),
    })
    .strict()
    .superRefine((row, ctx) => {
        if ((row.riskTier === undefined) !== (row.riskAssessedOn === undefined)) {
            ctx.addIssue({
                code: 'custom',
                message: 'a risk tier and the date it was assessed come together or not at all',
                path: [row.riskTier === undefined ? 'riskTier' : 'riskAssessedOn'],
            });
        }
    });

export const InventorySchema = z
    .object({
        inventory: z.literal(INVENTORY_SCHEMA_ID),
        agents: z.array(InventoryRowSchema).max(MAX_INVENTORY_ROWS),
    })
    .strict()
    .superRefine((inv, ctx) => {
        const seen = new Set<string>();
        inv.agents.forEach((row, i) => {
            if (seen.has(row.discoveredId)) {
                ctx.addIssue({ code: 'custom', message: 'a discoveredId appears once', path: ['agents', i, 'discoveredId'] });
            }
            seen.add(row.discoveredId);
        });
    });

export type InventoryRow = z.infer<typeof InventoryRowSchema>;

/** An inventory that passed the schema, with where it came from. */
export interface ParsedInventory {
    /** SHA-256 (hex) of the file's bytes, as the caller computed it. */
    readonly sha256: string;
    readonly format: 'json' | 'csv';
    /** In file order. A row's number is its 1-based position here. */
    readonly rows: readonly InventoryRow[];
}

/** An inventory that was refused. `issues` name rows and fields, never values. */
export class InventoryRefused extends Error {
    constructor(readonly issues: readonly string[]) {
        super(`invalid inventory: ${issues.join('; ')}`);
        this.name = 'InventoryRefused';
    }
}

/** `agents[3].axes.provenance` and `['agents', 3, 'axes', 'provenance']` both as `row 4: axes.provenance`. */
function describePath(path: readonly PropertyKey[]): string {
    if (path[0] === 'agents' && typeof path[1] === 'number') {
        const field = path.slice(2).map(String).join('.');
        return field === '' ? `row ${path[1] + 1}` : `row ${path[1] + 1}: ${field}`;
    }
    return path.map(String).join('.') || '(file)';
}

function describeIssue(issue: z.core.$ZodIssue): string {
    const where = describePath(issue.path);
    // An unknown key is content the file's author chose: counted, never named.
    if (issue.code === 'unrecognized_keys') {
        const n = issue.keys.length;
        return `${where}: ${n} unknown field${n === 1 ? '' : 's'}`;
    }
    // A custom message is this module's own fixed text; any other is zod's,
    // and only its code is repeated.
    return `${where}: ${issue.code === 'custom' ? issue.message : issue.code}`;
}

/** A member path from the secret walk, `agents[3].name`, in the same words as a schema refusal. */
function describeSecretPath(path: string): string {
    const m = /^agents\[(\d+)\](?:\.(.+))?$/.exec(path);
    if (m === null) return path === '' ? '(file)' : path;
    return m[2] === undefined ? `row ${Number(m[1]) + 1}` : `row ${Number(m[1]) + 1}: ${m[2]}`;
}

/**
 * Judge a decoded inventory. Refuses a secret-shaped string anywhere BEFORE the
 * schema runs, then the strict schema. Throws `InventoryRefused`; never returns
 * part of an inventory, because scoring against half of one would report known
 * agents as shadow agents.
 */
export function parseInventory(decoded: unknown, source: { readonly sha256: string; readonly format: 'json' | 'csv' }): ParsedInventory {
    if (!/^[0-9a-f]{64}$/.test(source.sha256)) throw new InventoryRefused(['(file): the hash of its bytes is not a SHA-256']);
    const secretAt = firstSecretShapedMember(decoded);
    if (secretAt !== null) {
        throw new InventoryRefused([`${describeSecretPath(secretAt)}: a credential value in the inventory`]);
    }
    const parsed = InventorySchema.safeParse(decoded);
    if (!parsed.success) {
        // A file of another schema, or of none, is told which one this version reads: the rest of
        // its issues would be this schema's rules applied to something else. Only an id of this
        // family is repeated; any other text is the file's own, and an issue never repeats that.
        if (parsed.error.issues.some((i) => i.path.length === 1 && i.path[0] === 'inventory')) {
            const found = (decoded as { inventory?: unknown }).inventory;
            const named = typeof found === 'string' && /^scanent-inventory\/\d{1,4}$/.test(found) ? JSON.stringify(found) : found === undefined ? 'no schema' : 'a schema this version does not know';
            // A retired id is told what changed since: its file is one this scanner wrote the rules for.
            const changed = typeof found === 'string' && Object.hasOwn(RETIRED_INVENTORY_SCHEMAS, found) ? `: ${RETIRED_INVENTORY_SCHEMAS[found]}` : '';
            throw new InventoryRefused([`inventory: the file names ${named}; this version reads ${INVENTORY_SCHEMA_ID}${changed}`]);
        }
        throw new InventoryRefused(parsed.error.issues.map(describeIssue));
    }
    return { sha256: source.sha256, format: source.format, rows: parsed.data.agents };
}

/** The evidence reference of one row: the file by the start of its hash, and the row's number. */
export function inventoryEvidence(sha256: string, rowNumber: number): string {
    return `inventory:sha256:${sha256.slice(0, 16)}#row-${rowNumber}`;
}

/** How a matched row is named as the agent's registration. */
export function inventoryRegistrationRef(rowNumber: number): string {
    return `inventory:row-${rowNumber}`;
}

/** Is a declared assessment date fresh as of the scan? Not after `asOf`, and at most the window before it. */
export function isTierFresh(riskAssessedOn: string, asOf: string): boolean {
    const assessed = dayNumberOf(riskAssessedOn);
    const asOfMs = Date.parse(asOf);
    if (assessed === null || Number.isNaN(asOfMs)) return false;
    const age = Math.floor(asOfMs / 86_400_000) - assessed;
    return age >= 0 && age <= INVENTORY_TIER_MAX_AGE_DAYS;
}

/**
 * The verdicts one matched row declares: exactly the four H1 criteria, each
 * with the row's evidence reference. A missing declaration is NOT MET, not
 * unanswered: the operator was asked and did not say.
 */
export function declaredVerdicts(
    row: InventoryRow,
    rowNumber: number,
    inventory: Pick<ParsedInventory, 'sha256'>,
    asOf: string,
): CriterionVerdict[] {
    const evidence = inventoryEvidence(inventory.sha256, rowNumber);
    const tierFresh = row.riskTier !== undefined && row.riskAssessedOn !== undefined && isTierFresh(row.riskAssessedOn, asOf);
    return [
        { criterion: 'H1.registered', met: true, evidence },
        { criterion: 'H1.owner', met: true, evidence },
        { criterion: 'H1.axes_declared', met: row.axes !== undefined, evidence },
        { criterion: 'H1.tier_scored_fresh', met: tierFresh, evidence },
    ];
}
