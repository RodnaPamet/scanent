/**
 * Posting a signed report to the tenant's ingest — the scanner's only write,
 * and it is to Inflect, never to the estate.
 *
 * Three reports, three routes, one function. The agent report goes to
 * `INGEST_PATH_TEMPLATE`, the integrations report to
 * `INTEGRATIONS_INGEST_PATH_TEMPLATE` and the agent-rules report to
 * `AGENT_RULES_INGEST_PATH_TEMPLATE`, each with its own API key: the tenant
 * gives the three ingests different scopes (`admin:harness_ingest`,
 * `admin:integrations_ingest`, `admin:agent_rules_ingest`), so a key minted
 * for one does not post another.
 *
 * The body is the serialised report, UNCHANGED: the signature covers the
 * canonical form of what is sent, so re-serialising here could only break it.
 * The route is fixed, the base must be https, and a redirect is refused — the
 * request carries the API key.
 *
 * What comes back is reduced to what an operator needs: the status, and on a
 * refusal its CODE (`harness_report_refused: <CODE>`,
 * `third_party_app_report_refused: <CODE>` for the integrations report, or
 * `agent_rules_report_refused: <CODE>` for the agent-rules report), never the
 * body.
 */
import type { FetchLike } from './http';
import { AGENT_RULES_INGEST_PATH_TEMPLATE, INGEST_PATH_TEMPLATE, INTEGRATIONS_INGEST_PATH_TEMPLATE } from './scanner-surface';

/** Which report a post carries. */
export type IngestReport = 'agents' | 'integrations' | 'agent-rules';

/** Per report: its route, the prefix the tenant's refusals carry, and the count a 201 states. */
const INGESTS: Readonly<Record<IngestReport, { readonly path: string; readonly refusal: RegExp; readonly count: 'agentCount' | 'applicationCount' | 'findingCount' }>> = {
    agents: { path: INGEST_PATH_TEMPLATE, refusal: /harness_report_refused: ([A-Z_]+)/, count: 'agentCount' },
    integrations: { path: INTEGRATIONS_INGEST_PATH_TEMPLATE, refusal: /third_party_app_report_refused: ([A-Z_]+)/, count: 'applicationCount' },
    'agent-rules': { path: AGENT_RULES_INGEST_PATH_TEMPLATE, refusal: /agent_rules_report_refused: ([A-Z_]+)/, count: 'findingCount' },
};

export interface PostResult {
    readonly ok: boolean;
    readonly status: number;
    /** The refusal code the ingest named, when it refused. */
    readonly refusal: string | null;
    /** From a 201: whether the ingest derived the scan as complete, and how many agents it holds. */
    readonly complete: boolean | null;
    readonly agentCount: number | null;
}

/** The integrations report's answer: the agent report's, with the applications counted in place of agents. */
export interface IntegrationsPostResult {
    readonly ok: boolean;
    readonly status: number;
    /** The refusal code the ingest named, when it refused (`REPLAY` on a 409). */
    readonly refusal: string | null;
    /** From a 201: whether the ingest derived the scan as complete, and how many applications it holds. */
    readonly complete: boolean | null;
    readonly applicationCount: number | null;
}

/** The agent-rules report's answer: the agent report's, with the findings counted in place of agents. */
export interface AgentRulesPostResult {
    readonly ok: boolean;
    readonly status: number;
    /** The refusal code the ingest named, when it refused (`REPLAY` on a 409). */
    readonly refusal: string | null;
    /** From a 201: whether the ingest derived the scan as complete, and how many findings it raised. */
    readonly complete: boolean | null;
    readonly findingCount: number | null;
}

/** The ingest URL of one report on the base's origin. The agent report's when `report` is not given. */
export function ingestUrl(baseUrl: string, tenantSlug: string, report: IngestReport = 'agents'): string {
    return `${new URL(baseUrl).origin}${INGESTS[report].path.replace('{tenantSlug}', encodeURIComponent(tenantSlug))}`;
}

interface PostOptions {
    readonly baseUrl: string;
    readonly tenantSlug: string;
    readonly apiKey: string;
    readonly raw: string;
    readonly fetchImpl: FetchLike;
    readonly timeoutMs?: number;
}

/** The one post, for either report: the status, the refusal code, and from a 201 the completeness and the count. */
async function post(opts: PostOptions, report: IngestReport): Promise<{ ok: boolean; status: number; refusal: string | null; complete: boolean | null; count: number | null }> {
    const ingest = INGESTS[report];
    const url = ingestUrl(opts.baseUrl, opts.tenantSlug, report);
    if (new URL(url).protocol !== 'https:') throw new Error('the ingest must be reached over https');
    const res = await opts.fetchImpl(url, {
        method: 'POST',
        headers: { Authorization: `Bearer ${opts.apiKey}`, 'Content-Type': 'application/json', Accept: 'application/json' },
        body: opts.raw,
        redirect: 'error',
        signal: AbortSignal.timeout(opts.timeoutMs ?? 60_000),
    });
    let text = '';
    try {
        text = (await res.text()).slice(0, 64 * 1024);
    } catch {
        text = '';
    }
    if (res.status === 201) {
        let body: Record<string, unknown> = {};
        try {
            body = (JSON.parse(text) ?? {}) as Record<string, unknown>;
        } catch {
            body = {};
        }
        const count = body[ingest.count];
        return {
            ok: true,
            status: res.status,
            refusal: null,
            complete: typeof body.complete === 'boolean' ? body.complete : null,
            count: typeof count === 'number' ? count : null,
        };
    }
    const code = ingest.refusal.exec(text)?.[1] ?? null;
    return { ok: false, status: res.status, refusal: code, complete: null, count: null };
}

/** Post the agent report to `INGEST_PATH_TEMPLATE`, with a key holding `admin:harness_ingest`. */
export async function postReport(opts: PostOptions): Promise<PostResult> {
    const { count, ...result } = await post(opts, 'agents');
    return { ...result, agentCount: count };
}

/** Post the integrations report to `INTEGRATIONS_INGEST_PATH_TEMPLATE`, with a key holding `admin:integrations_ingest`. */
export async function postIntegrationsReport(opts: PostOptions): Promise<IntegrationsPostResult> {
    const { count, ...result } = await post(opts, 'integrations');
    return { ...result, applicationCount: count };
}

/** Post the agent-rules report to `AGENT_RULES_INGEST_PATH_TEMPLATE`, with a key holding `admin:agent_rules_ingest`. */
export async function postAgentRulesReport(opts: PostOptions): Promise<AgentRulesPostResult> {
    const { count, ...result } = await post(opts, 'agent-rules');
    return { ...result, findingCount: count };
}
