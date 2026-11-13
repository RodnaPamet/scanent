/**
 * THE DATA BEHIND `summary.html`'S INTERACTIVE VIEW.
 *
 * The page's script draws, filters and sorts; it decides nothing about what a
 * row says. Every row here is a row of the shared table model
 * (`harnessMatrixOfResults` over `buildHarnessMatrix`), in the model's order
 * (`compareHarnessMatrixRows`, worst first), and every cell is the model's
 * state, written as its index in `HARNESS_MATRIX_CELL_STATES`. Every label the
 * script shows comes from the fixed tables in `words.ts`, carried here.
 *
 * What the script is given is made safe for it here, once:
 *
 *   • every string has its unprintable characters and bidirectional controls
 *     replaced by U+FFFD, as the static page shows them;
 *   • an evidence reference is text. It is given an address to link to only
 *     when it is an absolute https URL with no user information; one that
 *     carries user information is never linked and is shown with that part
 *     replaced by `***` (Inflect's rule for the same field);
 *   • the JSON is written so it cannot end the element it sits in
 *     (`scriptJson`): `<`, `>`, `&`, the quotes a parser could trip on and the
 *     two line separators are escaped.
 *
 * Pure: results in, data out.
 */
import { harnessBarFor } from '@rodnapamet/scanent-contract/harness-findings';
import { HARNESS_LEVEL_NAMES, HARNESS_LEVELS, type HarnessLevel } from '@rodnapamet/scanent-contract/harness-ladder';
import { compareHarnessMatrixRows, HARNESS_MATRIX_CELL_STATES, type HarnessMatrixModel, type HarnessMatrixRow } from '@rodnapamet/scanent-contract/harness-matrix-model';

import type { DiffRefusal, ResultsDiff } from '../diff/diff';
import type { IntegrationsDiff } from '../diff/integrations-diff';
import type { LocalAgentResult, LocalFinding, LocalResults } from '../results/types';
import { isBidiControl } from './escape';
import { RUN_FILE_NAMES } from './files';
import { harnessMatrixOfResults } from './matrix-of-results';
import {
    BASIS_TEXT,
    CAVEATS,
    CELL_STYLE,
    CLASSIFICATION_TEXT,
    DIFF_OUTCOME_TEXT,
    DIFF_WARNING_TEXT,
    ESTATE_REGISTRATION_TEXT,
    fixed,
    LEVEL_CHANGE_TEXT,
    MODEL_SIGN_TEXT,
    PREVIOUS_NOT_COMPARED_TEXT,
    REACH_TEXT,
    reasonSentence,
    REGISTRATION_TEXT,
    SEVERITY_ORDER,
    SEVERITY_TEXT,
    SOURCE_CHANGE_TEXT,
    standingOf,
    STANDING_TEXT,
    UNBOUND_TEXT,
    UNREADABLE_TEXT,
    type Standing,
} from './words';

export const PAGE_DATA_SCHEMA = 'scanent-summary-page/1';

/**
 * The most findings whose full description the page carries. Every finding is
 * listed, with its code, severity, subject and title, so the filters see them
 * all; past this many, most severe first, the description is in
 * `findings.csv` and the page says so.
 */
export const FINDING_DESCRIPTIONS_MAX = 2_500;

/** The most entries each list of the comparison with the previous run carries; each list says how many it holds. */
export const DRIFT_MAX_ROWS = 200;

// ── What a run knows of the run before it ──

export type PreviousNotCompared = DiffRefusal | 'UNREADABLE' | 'NO_AGENT_SCAN';

/** The run the output directory named as the latest before this one, compared or not. */
export type PreviousRun =
    | { readonly kind: 'COMPARED'; readonly diff: ResultsDiff }
    | { readonly kind: 'NOT_COMPARED'; readonly scanId: string | null; readonly reason: PreviousNotCompared };

/**
 * What a page is rendered with besides the results. `previous` absent: the
 * page was rendered outside a run directory, and has no comparison section.
 * `null`: the directory held no earlier run.
 */
export interface SummaryContext {
    readonly previous?: PreviousRun | null;
    /**
     * The same for the integrations scanner: the previous run's integrations
     * compared with this run's. Given only for a run whose integrations scanner
     * ran, so an agents-only page is what it was.
     */
    readonly integrationsPrevious?: IntegrationsPreviousRun | null;
}

/** The previous run's integrations, compared or not. */
export type IntegrationsPreviousRun =
    | { readonly kind: 'COMPARED'; readonly diff: IntegrationsDiff }
    | { readonly kind: 'NOT_COMPARED'; readonly scanId: string | null; readonly reason: DiffRefusal | 'UNREADABLE' | 'NO_INTEGRATIONS_SCAN' };

// ── The data ──

export interface EvidenceRecord {
    /** The reference as shown: user information replaced by `***`. */
    readonly t: string;
    /** An absolute https URL to link to, or null: the reference is shown as text only. */
    readonly h: string | null;
    /** True when user information was replaced. */
    readonly r: boolean;
}

export interface AgentRecord {
    readonly id: string;
    /** The operator's name for it, declared in the inventory; null when none. */
    readonly name: string | null;
    readonly cls: HarnessMatrixRow['classification'];
    readonly reg: LocalAgentResult['registration']['basis'];
    readonly ref: string | null;
    readonly via: readonly string[];
    readonly reach: string;
    readonly judged: boolean;
    readonly level: HarnessLevel | null;
    readonly observed: HarnessLevel | null;
    readonly bar: HarnessLevel;
    readonly standing: Standing;
    /** The model's `barStatus`: where the level stands against the bar its reach carries, held to it or not. */
    readonly barStatus: HarnessMatrixRow['barStatus'];
    readonly blocking: readonly string[] | null;
    /** Not judged: the reasons. Judged: the caveats. Codes. */
    readonly notes: readonly string[];
    /** One digit per criterion, in `criteria` order: the index of the cell's state in `states`. */
    readonly cells: string;
    /** One letter per criterion: `O` observed, `D` declared, `-` no verdict. */
    readonly basis: string;
    /** Pairs: criterion index, then evidence index into `evidence`. */
    readonly ev: readonly number[];
    readonly owner: string | null;
    readonly purpose: string | null;
    readonly observedOwner: { readonly kind: string; readonly ref: string } | null;
    /** Credentials, tools, write-capable tools, unpinned write tools, models (null: not reported). */
    readonly counts: readonly [number, number, number, number, number | null];
    readonly signs: readonly string[] | null;
    /** Null: not reported. Empty: a code read saw no payment client called. */
    readonly pay: readonly { readonly protocol: string; readonly library: string; readonly at: string }[] | null;
}

export interface FindingRecord {
    readonly code: string;
    readonly severity: string;
    /**
     * The finding's reference. Absent when it is `<code>:<agent>`, as most are:
     * at 5,000 agents the repetition alone was a megabyte of the page.
     * `findingRef` reads it either way.
     */
    readonly ref?: string;
    readonly agent: string | null;
    readonly title: string;
    /** Null past `FINDING_DESCRIPTIONS_MAX`: the description is in `findings.csv`. */
    readonly description: string | null;
}

export interface DriftList<T> {
    readonly total: number;
    readonly rows: readonly T[];
}

export type DriftRecord =
    | { readonly kind: 'FIRST' }
    | { readonly kind: 'NOT_COMPARED'; readonly scanId: string | null; readonly reason: string; readonly text: string }
    | {
          readonly kind: 'COMPARED';
          readonly outcome: string;
          readonly outcomeText: string;
          readonly differences: number;
          readonly notConcludedCount: number;
          readonly old: { readonly scanId: string; readonly asOf: string; readonly complete: boolean; readonly agentCount: number };
          readonly warnings: readonly { readonly code: string; readonly text: string }[];
          readonly sources: readonly { readonly kind: string; readonly text: string; readonly from: string | null; readonly to: string | null }[];
          readonly added: DriftList<string>;
          readonly gone: DriftList<string>;
          readonly notSeen: DriftList<{ readonly id: string; readonly why: string }>;
          readonly levels: DriftList<{ readonly id: string; readonly text: string; readonly from: string | null; readonly to: string | null }>;
          readonly attributes: DriftList<{ readonly id: string; readonly attribute: string; readonly from: string; readonly to: string }>;
          readonly criteria: { readonly concluded: number; readonly notConcluded: number };
          readonly findings: DriftList<{ readonly code: string; readonly ref: string; readonly change: string; readonly why: string | null }> & {
              readonly opened: number;
              readonly closed: number;
          };
          readonly orphans: DriftList<{ readonly ref: string; readonly kind: string; readonly change: string; readonly why: string | null }>;
          readonly notConcluded: DriftList<string>;
      };

export interface SummaryPageData {
    readonly schema: typeof PAGE_DATA_SCHEMA;
    readonly scan: {
        readonly id: string;
        readonly asOf: string;
        readonly estate: string | null;
        readonly complete: boolean;
        readonly contract: string;
        readonly scanner: string;
        readonly version: string;
        readonly ladder: string;
    };
    /** The model's: `EMPTY` before anything else. */
    readonly completeness: 'COMPLETE' | 'INCOMPLETE' | 'EMPTY';
    readonly sources: readonly {
        readonly kind: string;
        readonly status: string;
        readonly reason: string | null;
        readonly rows: number;
        readonly agents: number;
        readonly detail: string | null;
        readonly notReadTotal: number;
    }[];
    readonly coverage: {
        readonly reachable: HarnessLevel;
        readonly unreadable: readonly { readonly criterion: string; readonly why: string; readonly readers: readonly string[] }[];
    };
    readonly bars: { readonly readOnly: HarnessLevel; readonly write: HarnessLevel };
    readonly levels: readonly { readonly level: HarnessLevel; readonly name: string }[];
    readonly columns: readonly { readonly level: HarnessLevel; readonly name: string; readonly criteria: readonly string[] }[];
    readonly criteria: readonly string[];
    readonly states: readonly { readonly state: string; readonly code: string; readonly cls: string; readonly label: string; readonly text: string; readonly met: boolean }[];
    readonly estate: {
        readonly agentCount: number;
        readonly judgedCount: number;
        readonly notJudgedCount: number;
        readonly byLevel: Readonly<Record<string, number>>;
        readonly shortfallCount: number;
        readonly shadow: readonly string[];
        /** Null: a results file written before the member. */
        readonly identities: readonly string[] | null;
        readonly paying: readonly string[] | null;
        readonly orphans: readonly { readonly ref: string; readonly kind: string }[];
        readonly unbound: readonly { readonly ref: string; readonly kind: string; readonly why: string }[];
        readonly registration: string;
        readonly registrationBasis: string;
        readonly inventorySupplied: boolean;
    };
    readonly agents: readonly AgentRecord[];
    readonly evidence: readonly EvidenceRecord[];
    readonly findings: readonly FindingRecord[];
    readonly drift: DriftRecord | null;
    /**
     * The sentences that state a verdict about the whole scan, decided here and
     * present only when true: the words reserved for a clean result never sit
     * in the page as text the script merely might show.
     */
    readonly say: {
        readonly status: { readonly tone: 'ok' | 'bad'; readonly strong: string; readonly rest: string };
        /** What an empty findings list says; null when there are findings. */
        readonly noFindings: string | null;
        /** What an empty list of shadow agents or identities says. */
        readonly noneListed: string;
        /** The empty-scan finding's sentences; null when the scan found agents. */
        readonly empty: readonly string[] | null;
    };
    readonly files: Readonly<Record<string, string>>;
    readonly text: {
        readonly reach: Readonly<Record<string, string>>;
        readonly registration: Readonly<Record<string, string>>;
        readonly classification: Readonly<Record<string, string>>;
        readonly standing: Readonly<Record<string, string>>;
        readonly unreadable: Readonly<Record<string, string>>;
        readonly unbound: Readonly<Record<string, string>>;
        readonly signs: Readonly<Record<string, string>>;
        readonly basis: Readonly<Record<string, string>>;
        readonly severity: Readonly<Record<string, string>>;
        readonly reasons: Readonly<Record<string, string>>;
        readonly caveats: readonly string[];
    };
}

// ── Safe text ──

/** A string as the page shows it: unprintable characters and bidirectional controls replaced, as `escapeHtml` does. */
export function printable(value: string): string {
    let out = '';
    for (const ch of value) {
        const code = ch.codePointAt(0) as number;
        const unprintable = code < 0x20 || (code >= 0x7f && code <= 0x9f) || code === 0x2028 || code === 0x2029 || isBidiControl(code);
        out += unprintable && ch !== '\n' && ch !== '\t' ? '�' : ch;
    }
    return out;
}

function printableDeep<T>(value: T): T {
    if (typeof value === 'string') return printable(value) as unknown as T;
    if (Array.isArray(value)) return value.map(printableDeep) as unknown as T;
    if (value !== null && typeof value === 'object') {
        return Object.fromEntries(Object.entries(value).map(([k, v]) => [printable(k), printableDeep(v)])) as T;
    }
    return value;
}

const SCRIPT_JSON_ESCAPES: Readonly<Record<string, string>> = {
    '<': '\\u003c',
    '>': '\\u003e',
    '&': '\\u0026',
    "'": '\\u0027',
    '`': '\\u0060',
    '\u2028': '\\u2028',
    '\u2029': '\\u2029',
};

/**
 * JSON for a `<script type="application/json">` element. Nothing in it can
 * close the element, open a comment, or be read differently by an HTML parser
 * than by `JSON.parse`, which reads each escape back as the character it was.
 */
export function scriptJson(value: unknown): string {
    return JSON.stringify(value).replace(/[<>&'`\u2028\u2029]/g, (ch) => SCRIPT_JSON_ESCAPES[ch]);
}

/** Every URL user information in a reference, wider than a parser's reading on purpose: Inflect's rule. */
const POINTER_USERINFO = /\/\/[^/?#]*@/g;

/** An evidence reference as the page may show it, and the address it may link to. */
export function evidenceRecord(reference: string): EvidenceRecord {
    const trimmed = reference.trim();
    const text = trimmed.replace(POINTER_USERINFO, '//***@');
    const redacted = text !== trimmed;
    let href: string | null = null;
    if (!redacted) {
        try {
            const url = new URL(trimmed);
            if (url.protocol === 'https:' && url.username === '' && url.password === '') href = url.href;
        } catch {
            href = null;
        }
    }
    return { t: text, h: href, r: redacted };
}

// ── The comparison with the previous run ──

function capped<T>(all: readonly T[]): DriftList<T> {
    return { total: all.length, rows: all.slice(0, DRIFT_MAX_ROWS) };
}

function notSeenWhy(a: ResultsDiff['agents']['notSeen'][number]): string {
    if (a.differentScanner) return 'The runs are from different scanners';
    if (a.differentEstate) return 'The runs name different estates';
    if (a.unread.length > 0) return a.unread.map((u) => `${u.kind} ${u.status === 'ABSENT' ? 'was not listed' : 'was not read in full'}`).join('; ');
    if (a.newScanEmpty) return 'This run found no agent at all';
    return 'It was found through no listed source';
}

export function driftRecord(previous: PreviousRun | null): DriftRecord {
    if (previous === null) return { kind: 'FIRST' };
    if (previous.kind === 'NOT_COMPARED') {
        return { kind: 'NOT_COMPARED', scanId: previous.scanId, reason: previous.reason, text: fixed(PREVIOUS_NOT_COMPARED_TEXT, previous.reason, 'Not compared') };
    }
    const d = previous.diff;
    const closure = (change: string): number => d.findings.filter((f) => f.change === change).length;
    return {
        kind: 'COMPARED',
        outcome: d.outcome,
        outcomeText: fixed(DIFF_OUTCOME_TEXT, d.outcome, ''),
        differences: d.summary.differences,
        notConcludedCount: d.summary.notConcluded,
        old: { scanId: d.old.scanId, asOf: d.old.asOf, complete: d.old.complete, agentCount: d.old.agentCount },
        warnings: d.warnings.map((w) => ({ code: w, text: fixed(DIFF_WARNING_TEXT, w.split(':')[0], 'See the code') })),
        sources: d.sources.map((s) => ({ kind: s.kind, text: fixed(SOURCE_CHANGE_TEXT, s.change, s.change), from: s.from.reason, to: s.to.reason })),
        added: capped(d.agents.added),
        gone: capped(d.agents.gone),
        notSeen: capped(d.agents.notSeen.map((a) => ({ id: a.discoveredId, why: notSeenWhy(a) }))),
        levels: capped(d.levels.map((l) => ({ id: l.discoveredId, text: fixed(LEVEL_CHANGE_TEXT, l.change, l.change), from: l.from, to: l.to }))),
        attributes: capped(d.attributes.map((a) => ({ id: a.discoveredId, attribute: a.attribute, from: a.from, to: a.to }))),
        criteria: { concluded: d.criteria.filter((c) => c.concluded).length, notConcluded: d.criteria.filter((c) => !c.concluded).length },
        // Counted over every finding, never over the rows carried.
        findings: { ...capped(d.findings.map((f) => ({ code: f.code, ref: f.sourceRef, change: f.change, why: f.why }))), opened: closure('OPENED'), closed: closure('CLOSED') },
        orphans: capped(d.orphanCredentials.map((c) => ({ ref: c.ref, kind: c.sourceKind, change: c.change, why: c.why }))),
        notConcluded: capped(d.notConcluded),
    };
}

// ── The data ──

const STATE_INDEX = new Map<string, number>(HARNESS_MATRIX_CELL_STATES.map((s, i) => [s, i]));

/** A finding record's reference, carried or implied. */
export function findingRef(f: Pick<FindingRecord, 'code' | 'agent' | 'ref'>): string {
    return f.ref ?? `${f.code}:${f.agent ?? ''}`;
}

/** Findings most severe first, and in the planner's order within a severity. */
export function findingsBySeverity(findings: readonly LocalFinding[]): LocalFinding[] {
    return findings
        .map((f, i): [LocalFinding, number] => [f, i])
        .sort(([a, i], [b, k]) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9) || i - k)
        .map(([f]) => f);
}

/** The interactive view's data, from the results and what the run knew of the run before it. */
export function summaryPageData(r: LocalResults, context: SummaryContext = {}): SummaryPageData {
    const known = BUILT.get(r);
    if (known !== undefined && known.previous === context.previous) return known.data;
    const data = summaryPageDataOf(r, context, harnessMatrixOfResults(r));
    BUILT.set(r, { previous: context.previous, data });
    return data;
}

/**
 * The data last built for a results object, and the previous run it was built
 * with. One run hands the same results to the secret check, the page and the
 * PDF; the data is a function of the two, so it is built once. A WeakMap keyed
 * by the results object, so it holds nothing once the run lets go of them.
 */
const BUILT = new WeakMap<LocalResults, { readonly previous: SummaryContext['previous']; readonly data: SummaryPageData }>();

/** The same, over a table model the caller already built from these results. */
export function summaryPageDataOf(r: LocalResults, context: SummaryContext, model: HarnessMatrixModel): SummaryPageData {
    const byId = new Map(r.agents.map((a) => [a.discoveredId, a]));
    const criteria = model.columns.flatMap((g) => g.criteria);
    const criterionIndex = new Map<string, number>(criteria.map((c, i) => [c, i]));

    const evidence: EvidenceRecord[] = [];
    const evidenceIndex = new Map<string, number>();
    const internEvidence = (ref: string): number => {
        let at = evidenceIndex.get(ref);
        if (at === undefined) {
            at = evidence.length;
            evidence.push(evidenceRecord(ref));
            evidenceIndex.set(ref, at);
        }
        return at;
    };

    const reasons: Record<string, string> = {};
    const rows = [...model.rows].sort(compareHarnessMatrixRows);
    const agents = rows.map((row): AgentRecord => {
        const a = byId.get(row.discoveredId) as LocalAgentResult;
        const notes = row.judgement.kind === 'JUDGED' ? row.judgement.caveats : row.judgement.reasons;
        for (const code of notes) reasons[code] = reasonSentence(code);
        const ev: number[] = [];
        for (const cell of row.cells) {
            if (cell.evidence !== null && cell.evidence.trim() !== '') ev.push(criterionIndex.get(cell.criterion) as number, internEvidence(cell.evidence));
        }
        return {
            id: row.discoveredId,
            name: row.nameHint?.text ?? null,
            cls: row.classification,
            reg: a.registration.basis,
            ref: a.registration.ref,
            via: row.discoveredVia,
            reach: row.reach,
            judged: row.judgement.kind === 'JUDGED',
            level: row.level,
            observed: row.observedLevel,
            bar: row.bar,
            standing: standingOf(row),
            barStatus: row.barStatus,
            blocking: row.blockingNextRung,
            notes,
            cells: row.cells.map((c) => String(STATE_INDEX.get(c.state))).join(''),
            basis: row.cells.map((c) => (c.basis === 'OBSERVED' ? 'O' : c.basis === 'DECLARED' ? 'D' : '-')).join(''),
            ev,
            owner: a.declared?.owner ?? null,
            purpose: a.declared?.purpose ?? null,
            observedOwner: a.observedOwner,
            counts: [a.counts.credentials, a.counts.tools, a.counts.writeCapableTools, a.counts.unpinnedWriteTools, a.counts.models],
            signs: a.modelSigns === undefined ? null : [...a.modelSigns],
            pay: row.paymentCapabilities === null ? null : row.paymentCapabilities.map((p) => ({ protocol: p.protocol, library: p.library, at: p.at })),
        };
    });

    const ordered = findingsBySeverity(r.findings);
    const findings = ordered.map(
        (f, i): FindingRecord => ({
            code: f.code,
            severity: f.severity,
            ...(f.discoveredId !== null && f.sourceRef === `${f.code}:${f.discoveredId}` ? {} : { ref: f.sourceRef }),
            agent: f.discoveredId,
            title: f.title,
            description: i < FINDING_DESCRIPTIONS_MAX ? f.description : null,
        }),
    );

    const e = r.estate;
    const data: SummaryPageData = {
        schema: PAGE_DATA_SCHEMA,
        scan: {
            id: r.scan.id,
            asOf: r.scan.asOf,
            estate: r.scan.estate,
            complete: r.scan.complete,
            contract: r.scan.contract,
            scanner: r.scan.scanner.agentId,
            version: r.scan.scanner.version,
            ladder: r.ladder.version,
        },
        completeness: model.population.completeness,
        sources: r.sources.map((s) => ({
            kind: s.kind,
            status: s.status,
            reason: s.reason,
            rows: s.rows,
            agents: s.agents,
            detail: s.detail ?? null,
            notReadTotal: s.notReadTotal ?? 0,
        })),
        coverage: {
            reachable: r.coverage.reachableLevel,
            unreadable: r.coverage.unreadable.map((u) => ({ criterion: u.criterion, why: u.why, readers: [...u.readers] })),
        },
        bars: { readOnly: harnessBarFor('READ_ONLY'), write: harnessBarFor('WRITE_OR_EXTERNAL') },
        levels: HARNESS_LEVELS.map((level) => ({ level, name: HARNESS_LEVEL_NAMES[level] })),
        columns: model.columns.map((g) => ({ level: g.level, name: g.name, criteria: [...g.criteria] })),
        criteria,
        states: HARNESS_MATRIX_CELL_STATES.map((state) => ({
            state,
            code: CELL_STYLE[state].code,
            cls: CELL_STYLE[state].cls,
            label: CELL_STYLE[state].label,
            text: CELL_STYLE[state].text,
            met: state === 'EVIDENCED' || state === 'DECLARED',
        })),
        estate: {
            agentCount: e.agentCount,
            judgedCount: e.judgedCount,
            notJudgedCount: e.notJudgedCount,
            byLevel: { ...e.byLevel },
            shortfallCount: e.shortfallCount,
            shadow: [...e.shadowAgents],
            identities: e.unregisteredIdentities === undefined ? null : [...e.unregisteredIdentities],
            paying: e.payingAgents === undefined ? null : [...e.payingAgents],
            orphans: e.orphanCredentials.map((c) => ({ ref: c.ref, kind: c.sourceKind })),
            unbound: e.unboundNotConcluded.map((c) => ({ ref: c.ref, kind: c.sourceKind, why: c.why })),
            registration: fixed(ESTATE_REGISTRATION_TEXT, e.registrationBasis, 'Not stated'),
            registrationBasis: e.registrationBasis,
            inventorySupplied: r.inventory !== null,
        },
        agents,
        evidence,
        findings,
        drift: context.previous === undefined ? null : driftRecord(context.previous),
        say: {
            status: r.scan.complete
                ? { tone: 'ok', strong: 'Complete.', rest: 'Every listed source was read in full.' }
                : r.sources.length === 0
                    ? { tone: 'bad', strong: 'Incomplete:', rest: 'the report lists no source, so this scan evidences nothing.' }
                    : { tone: 'bad', strong: 'Incomplete:', rest: `${r.sources.filter((s) => s.status !== 'COMPLETE').length} of ${r.sources.length} sources were not read in full.` },
            noFindings: r.findings.length > 0 ? null : r.scan.complete ? 'No finding was raised.' : 'No finding was raised. The scan is incomplete, so this is not a clean result.',
            noneListed: r.scan.complete ? 'None.' : 'None raised. The scan is incomplete, so this is not a statement that none exist.',
            empty: r.estate.empty
                ? [
                      'This scan found no agents. That is a finding, not a clean result.',
                      'An empty population is what a scanner reading the wrong place, or nothing, looks like. No level is stated for anything.',
                  ]
                : null,
        },
        files: { ...RUN_FILE_NAMES },
        text: {
            reach: REACH_TEXT,
            registration: REGISTRATION_TEXT,
            classification: CLASSIFICATION_TEXT,
            standing: STANDING_TEXT,
            unreadable: UNREADABLE_TEXT,
            unbound: UNBOUND_TEXT,
            signs: MODEL_SIGN_TEXT,
            basis: BASIS_TEXT,
            severity: SEVERITY_TEXT,
            reasons,
            caveats: CAVEATS,
        },
    };
    return printableDeep(data);
}
