/**
 * THE SOURCE INTERFACE — one shape every reader of an estate implements.
 *
 * A source reads one kind of inventory (`okta-app`, `vault`, `code`, …) and returns
 * what it saw of each principal plus how far it got. It never throws for a
 * read that went wrong: it returns `INCOMPLETE` with a named reason, and the
 * scan runner turns an unexpected throw into the same thing. A source that
 * could not be read is reported, never omitted (contract, Sources).
 *
 * What a source may NOT do, by construction rather than by convention:
 *
 *   • Issue anything but a GET to the inventory it reads. It is handed a
 *     `ReadOnlyHttp`, whose only verb is `getJson`; there is no method
 *     parameter to pass. The other requests a source can make are fixed by
 *     the wire: the OAuth token exchange to its identity provider, the MCP
 *     listing (`initialize`, the notification, `tools/list`), and the one
 *     register read (`tools/call` of `get_harness_register`) — see `http.ts`.
 *   • Decide that the agent it found is registered. Only the `inflect-register`
 *     source's `registeredAgentId` reaches the report — the builder drops it
 *     from every other kind: linking a principal to the register is the
 *     register's own record, never a label in the estate being scanned, which
 *     an estate administrator could write to hide a shadow agent.
 *   • Carry a credential value. An observation names a credential by a
 *     `scheme://locator` reference, and the runner refuses to sign a report in
 *     which any string has a secret's shape.
 */
import type { CriterionVerdict } from '@scanent/contract/harness-ladder';
import type {
    HarnessReportAgent,
    INCOMPLETE_REASONS_V2,
    SOURCE_KINDS_V3,
} from '@scanent/contract/harness-contract';

import type { McpListingWire, OpenShellReadWire, ReadOnlyHttp, RegisterReadWire, TokenExchange } from './http';

/** The scanner speaks `inflect-agent-harness/3`: its kinds are `/3`'s, and its reasons `/2`'s, which `/3` keeps. */
export type SourceKind = (typeof SOURCE_KINDS_V3)[number];
export type IncompleteReason = (typeof INCOMPLETE_REASONS_V2)[number];

export type ObservedCredential = HarnessReportAgent['credentials'][number];
export type ObservedOwner = NonNullable<HarnessReportAgent['owner']>;
export type ObservedTool = HarnessReportAgent['tools'][number];
export type ObservedModel = NonNullable<HarnessReportAgent['models']>[number];

/**
 * One tool a source saw a principal use, and — for a source that counts calls —
 * how many calls it counted in the source's window. The report carries the
 * tool. `inflect-agent-harness/2` has a member for the count (`calls`, with
 * `windowDays`); until a follow-up of #3738 fills it, the count reaches the
 * scanner's log as a per-source total and goes no further. A source that reads
 * definitions rather than calls — the `code` source — counts none and leaves
 * `calls` out.
 */
export interface ObservedToolUse {
    readonly tool: ObservedTool;
    readonly calls?: number;
}

/** What one source saw of one principal. Merged across sources by `discoveredId`. */
export interface Observation {
    readonly discoveredId: string;
    readonly owner: ObservedOwner | null;
    readonly credentials: readonly ObservedCredential[];
    /** Only verdicts the source holds evidence for; unanswered counts as no. */
    readonly verdicts: readonly CriterionVerdict[];
    /**
     * Tools the source saw this principal use or bind: the `runtime` source the
     * tools it called, the `code` source the tools its definition binds. An
     * identity provider or a vault does not know an agent's tools, and leaves
     * it out.
     */
    readonly tools?: readonly ObservedToolUse[];
    /** Model endpoints the principal calls, by reference. Only the `code` source reports any today. */
    readonly models?: readonly ObservedModel[];
    /**
     * The register row this principal is, from the `inflect-register` source
     * ONLY: the report builder ignores it from any other kind, because a label in
     * the estate is something the estate's administrator could write.
     */
    readonly registeredAgentId?: string;
}

/** How far one source got, and what it saw on the way. */
export interface SourceRead {
    readonly kind: SourceKind;
    readonly status: 'COMPLETE' | 'INCOMPLETE';
    /** Present exactly when `status` is INCOMPLETE. */
    readonly reason?: IncompleteReason;
    /** Rows read from the inventory, whether or not each became an observation. */
    readonly rows: number;
    /** Principals seen, including on a read that stopped early: what WAS read is real. */
    readonly observations: readonly Observation[];
    /**
     * Credential references this source saw bound to NO principal (`/2`'s
     * `unboundCredentials[]`). A source that reports every credential against
     * the principal it belongs to — Okta's and Key Vault's both do — sees none
     * and leaves this out. The ingest acts on it only when the read was
     * COMPLETE, so a source that stopped early may still list what it saw.
     */
    readonly unboundCredentials?: readonly string[];
    /** The `mcp` source only: each server it read in full. */
    readonly mcpServers?: readonly McpServerRead[];
}

export interface SourceContext {
    /** The moment the scan describes. Ages are measured from it. */
    readonly asOf: Date;
    /**
     * The scan's deadline (epoch ms) and its clock. The wire enforces both on
     * every request; a source that reads no network — the `code` source —
     * checks them itself.
     */
    readonly deadline: number;
    readonly now: () => number;
    /** GET only. The one verb a source has against the inventory it reads. */
    readonly http: ReadOnlyHttp;
    /** The OAuth client-credentials exchange, for a source whose API takes a bearer token. */
    readonly tokens: TokenExchange;
    /** The MCP listing — `initialize`, the initialized notification, `tools/list` — for the `mcp` source. */
    readonly mcp: McpListingWire;
    /** The one register read, for the `inflect-register` source. */
    readonly register: RegisterReadWire;
    /**
     * The OpenShell gateway read — three methods, for the `runtime` kind's
     * OpenShell source. A wire of its own because the gateway speaks gRPC and
     * publishes no REST transcoding, and because `ReadOnlyHttp`'s one-method
     * shape is what makes a source unable to write BY CONSTRUCTION; see
     * `http.ts`.
     */
    readonly openshell: OpenShellReadWire;
}

/**
 * One MCP server the `mcp` source read IN FULL, by its configured URL: the
 * tools it lists, as the report carries them. The report builder replaces a
 * `<key>:*` placeholder another source reported for that URL with these.
 */
export interface McpServerRead {
    readonly label: string;
    readonly url: string;
    /** `sha256:` over the server's whole tool listing: what an estate pins. */
    readonly manifestHash: string;
    readonly tools: readonly ObservedTool[];
}

/** The total of the calls a read's observations counted: what the log line reports for a source that reads tools. */
export function toolCallsOf(read: Pick<SourceRead, 'observations'>): number {
    return read.observations.reduce((sum, o) => sum + (o.tools ?? []).reduce((s, t) => s + (t.calls ?? 0), 0), 0);
}

/** Most pages one source follows. A listing longer than this is reported, not read forever. */
export const MAX_PAGES_PER_SOURCE = 1_000;

/**
 * Follow a paged listing from `first`, yielding each page's items. Every link
 * stays on `origin` (`getJson` refuses one that leaves it) and on the path of
 * `first` (a listing's next page is the same listing), a link seen twice
 * is a loop and so PAGINATION_TORN, and a page that is not the listing's shape
 * is PAGINATION_TORN too — never an empty page silently skipped.
 */
export async function* readPages(
    http: ReadOnlyHttp,
    first: string,
    opts: {
        readonly origin: string;
        readonly headers: Readonly<Record<string, string>>;
        /** The page's items and the next URL, or null when the page is not the listing's shape. */
        readonly parse: (body: unknown, headers: Headers) => { items: readonly unknown[]; next: string | null } | null;
    },
): AsyncGenerator<readonly unknown[]> {
    const seen = new Set<string>();
    let url: string | null = first;
    let pages = 0;
    const listing = pathOf(first);
    while (url !== null) {
        // The next page of a listing is the same listing. A link to another
        // path on the same origin would be a request the scanner never declared
        // (a secret's own URL, an app's client secrets), made with the estate's
        // credential because a response said to: it is refused before it is sent.
        if (pathOf(url) !== listing) throw new SourceReadError('PAGINATION_TORN', 'the listing linked to another path');
        if (seen.has(url)) throw new SourceReadError('PAGINATION_TORN', 'the listing linked back to a page it had served');
        if (pages >= MAX_PAGES_PER_SOURCE) throw new SourceReadError('BYTE_CAP', 'the listing ran past the page cap');
        seen.add(url);
        pages += 1;
        const { body, headers } = await http.getJson(url, { origin: opts.origin, headers: opts.headers });
        const page = opts.parse(body, headers);
        if (page === null) throw new SourceReadError('PAGINATION_TORN', 'a page was not the listing it should be');
        yield page.items;
        url = page.next;
    }
}

/** A URL's path, or null when it is not a URL: `getJson` refuses that one by its own rule. */
function pathOf(url: string): string | null {
    try {
        return new URL(url).pathname;
    } catch {
        return null;
    }
}

export interface HarnessSource {
    readonly kind: SourceKind;
    /** The product behind the kind, e.g. `okta` or `azure-key-vault`. Not reported. */
    readonly product: string;
    read(ctx: SourceContext): Promise<SourceRead>;
    /**
     * The preflight (`scanent doctor`): the smallest reads that show the
     * source can be read, each one a request `read` already makes. Required,
     * so a new source cannot ship without one. It returns what it tried, in
     * order, and stops at the first step that failed; it never throws for a
     * read that went wrong, and it never writes.
     */
    preflight(ctx: SourceContext): Promise<readonly ProbeStep[]>;
}

/** A source read that stopped, with the contract's reason. */
export class SourceReadError extends Error {
    constructor(
        readonly reason: IncompleteReason,
        message: string,
        /** The HTTP status the source answered with, where the wire knows one. Not reported. */
        readonly status?: number,
    ) {
        super(message);
        this.name = 'SourceReadError';
    }
}

/**
 * What a preflight saw of whether the credential can WRITE. Only a declared
 * read can reveal it: nothing is ever written to find out.
 */
export type WriteObservation =
    /** The read showed the grant, and it is read-only. `detail` names what was seen (role or scope names). */
    | { readonly state: 'READ_ONLY'; readonly detail: string }
    /** The read showed a grant that writes. `names` are the roles or scopes, as the product spells them. */
    | { readonly state: 'WRITE'; readonly names: readonly string[]; readonly fix: string }
    /** No declared read shows it. `verify` says what to confirm by hand. */
    | { readonly state: 'NOT_OBSERVABLE'; readonly verify: string };

/** One thing a preflight tried. */
export interface ProbeStep {
    /** `exchange`: a token exchange. `read`: one declared read. `write`: what the reads showed about write access. */
    readonly id: 'exchange' | 'read' | 'write';
    /** A sub-scope, for a source that reads several independent targets: an MCP server's label. */
    readonly scope?: string;
    /** What was asked for, in fixed words: `applications`, `secrets`. Never a URL or a value. */
    readonly what: string;
    /** The host asked, when the step is a request. */
    readonly host?: string;
    readonly outcome: 'ok' | SourceReadError;
    readonly observed?: {
        /** The response's `Date` header, when the read returned one. */
        readonly date?: string | null;
        readonly write?: WriteObservation;
    };
}

/**
 * Collects a preflight's steps. `exchange` and `read` run one request each and
 * record how it went; a failure is recorded and then ends the preflight (or
 * the sub-scope), by throwing `ProbeStopped` for `run` to catch.
 */
export class ProbeLog {
    readonly steps: ProbeStep[] = [];

    constructor(private readonly scope?: string) {}

    private async attempt<T>(id: 'exchange' | 'read', what: string, host: string, fn: () => Promise<T>, dateOf: (value: T) => string | null | undefined): Promise<T> {
        const base = { id, what, host, ...(this.scope === undefined ? {} : { scope: this.scope }) };
        let value: T;
        try {
            value = await fn();
        } catch (err) {
            const outcome = err instanceof SourceReadError ? err : new SourceReadError('UNREACHABLE', 'the probe did not complete');
            this.steps.push({ ...base, outcome });
            throw new ProbeStopped();
        }
        const date = dateOf(value);
        this.steps.push({ ...base, outcome: 'ok', ...(date === undefined ? {} : { observed: { date } }) });
        return value;
    }

    /** One token exchange. */
    exchange<T>(what: string, host: string, fn: () => Promise<T>): Promise<T> {
        return this.attempt('exchange', what, host, fn, () => undefined);
    }

    /** One declared read. The response's `Date` header is kept when `fn` returns headers. */
    read<T>(what: string, host: string, fn: () => Promise<T>): Promise<T> {
        return this.attempt('read', what, host, fn, (value) => {
            const headers = (value as { headers?: unknown } | null)?.headers;
            return headers instanceof Headers ? headers.get('date') : undefined;
        });
    }

    /**
     * One declared read of a LISTING: as `read`, and the answer must be the
     * listing's shape. A 200 that is something else (a sign-in page served as
     * JSON, a proxy's own answer, another API on the same host) is what the
     * scan would report as PAGINATION_TORN, so the preflight fails on it too
     * rather than call a source ready that the first scan cannot read.
     */
    listing<T extends { readonly body: unknown; readonly absent?: true }>(what: string, host: string, fn: () => Promise<T>, isListing: (body: unknown) => boolean): Promise<T> {
        return this.read(what, host, async () => {
            const value = await fn();
            if (value.absent !== true && !isListing(value.body)) throw new SourceReadError('PAGINATION_TORN', 'the answer was not the listing it should be');
            return value;
        });
    }

    /** What the reads showed about write access. Recorded only after every read succeeded. */
    write(observation: WriteObservation): void {
        this.steps.push({ id: 'write', what: 'write access', outcome: 'ok', observed: { write: observation }, ...(this.scope === undefined ? {} : { scope: this.scope }) });
    }

    /** Run a preflight body; a recorded failure ends it quietly, anything else is the reader's own fault and propagates. */
    static async run(body: () => Promise<void>): Promise<void> {
        try {
            await body();
        } catch (err) {
            if (!(err instanceof ProbeStopped)) throw err;
        }
    }
}

/** Thrown by `ProbeLog` after it recorded a failed step: there is nothing further to try. */
export class ProbeStopped extends Error {
    constructor() {
        super('the preflight stopped at a failed step');
        this.name = 'ProbeStopped';
    }
}

/**
 * A source's result from what it collected and how it stopped. `stoppedBy` is
 * null for a read that reached the end. Anything other than a
 * `SourceReadError` is a fault in the reader rather than in the estate, and is
 * still reported as INCOMPLETE — UNREACHABLE, the reason that claims least —
 * because a source the scanner failed to read is a source it did not read.
 */
export function sourceResult(
    kind: SourceKind,
    rows: number,
    observations: readonly Observation[],
    stoppedBy: unknown,
): SourceRead {
    if (stoppedBy === null) return { kind, status: 'COMPLETE', rows, observations };
    const reason: IncompleteReason = stoppedBy instanceof SourceReadError ? stoppedBy.reason : 'UNREACHABLE';
    return { kind, status: 'INCOMPLETE', reason, rows, observations };
}

/** A JSON object: not null, not an array. */
export function isJsonObject(v: unknown): v is Record<string, unknown> {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/** An identifier a source hands back, as it may appear inside a discovered id or a locator. */
export function isPlainId(value: unknown): value is string {
    return typeof value === 'string' && /^[A-Za-z0-9._~-]{1,128}$/.test(value);
}

/** Whole days from `from` to `asOf`, never negative; null when `from` is absent or unparseable. */
export function ageInDays(from: Date | null, asOf: Date): number | null {
    if (from === null || Number.isNaN(from.getTime())) return null;
    return Math.max(0, Math.floor((asOf.getTime() - from.getTime()) / 86_400_000));
}
