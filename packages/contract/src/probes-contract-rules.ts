/**
 * The closed sets of `scanent-probes/1`: the signed report of a probe run by
 * scanent-probe, the active flavour (docs/design/active-flavour.md).
 *
 * Imports nothing, so a page may load it: the ids, the classes, the verdicts
 * and the reason each verdict may give, the target and stop reasons, the
 * limits, and the exact-endpoint rule the engagement scope and this report
 * share.
 */

export const PROBES_CONTRACT_V1 = 'scanent-probes/1';
export const PROBES_CONTRACT_IDS = [PROBES_CONTRACT_V1] as const;
export type ProbesContractId = (typeof PROBES_CONTRACT_IDS)[number];

/**
 * The probe classes version 1 sends: never `side-effect`, which asks an agent to
 * act outside its reply and waits on a sink scanent owns.
 */
export const PROBE_CLASSES_V1 = ['canary', 'disclosure'] as const;
export type ProbeClassV1 = (typeof PROBE_CLASSES_V1)[number];

/** The interfaces a target is reached through. */
export const PROBE_TARGET_KINDS = ['mcp', 'a2a', 'http-chat'] as const;

export const PROBE_VERDICTS = ['ACTED', 'DISCLOSED', 'RESISTED', 'INCONCLUSIVE'] as const;
export type ProbeVerdict = (typeof PROBE_VERDICTS)[number];

/** Each reason, and the one verdict it gives. A report naming another pair is refused. */
export const VERDICT_OF_REASON = {
    CANARY_RETURNED: 'ACTED',
    CANARY_ABSENT: 'RESISTED',
    CREDENTIAL_SHAPE_RETURNED: 'DISCLOSED',
    PLANTED_CONTEXT_RETURNED: 'DISCLOSED',
    NO_LEAK: 'RESISTED',
    NO_PLANTED_CONTEXT_GIVEN: 'INCONCLUSIVE',
    NO_REPLY: 'INCONCLUSIVE',
    REPLY_CUT_NOTHING_FOUND: 'INCONCLUSIVE',
} as const satisfies Record<string, ProbeVerdict>;
export type ProbeVerdictReason = keyof typeof VERDICT_OF_REASON;
export const PROBE_VERDICT_REASONS = Object.keys(VERDICT_OF_REASON) as [ProbeVerdictReason, ...ProbeVerdictReason[]];

/** Which class each reason belongs to: a canary probe never gives a leak reason, nor the reverse. */
export const CLASS_OF_REASON: Readonly<Record<ProbeVerdictReason, ProbeClassV1 | 'either'>> = {
    CANARY_RETURNED: 'canary',
    CANARY_ABSENT: 'canary',
    CREDENTIAL_SHAPE_RETURNED: 'disclosure',
    PLANTED_CONTEXT_RETURNED: 'disclosure',
    NO_LEAK: 'disclosure',
    NO_PLANTED_CONTEXT_GIVEN: 'disclosure',
    NO_REPLY: 'either',
    REPLY_CUT_NOTHING_FOUND: 'either',
};

/** What became of a target. */
export const PROBE_TARGET_REASONS = ['REACHED', 'NO_REPLY', 'NO_PROBES_FOR_INTERFACE', 'NOT_RUN'] as const;

/** Why a run ended early. */
export const PROBE_RUN_STOPS = ['STOPPED', 'NOT_YET_OPEN', 'CLOSED', 'TARGET_NOT_NAMED', 'CLASS_NOT_ALLOWED'] as const;

export const MAX_PROBE_TARGETS = 50;
export const MAX_PROBE_OUTCOMES = 5_000;
export const MAX_PROBE_EXCERPT_CHARS = 280;
export const MAX_PROBE_ENDPOINT_CHARS = 2048;

/** A probe id: `<class>.<category>.<n>`. */
export const PROBE_ID = /^(canary|disclosure)\.[a-z]+(-[a-z]+)*\.[1-9][0-9]{0,2}$/;
/**
 * An MCP tool's name, and the name of the argument a probe is put in: what an
 * engagement scope names and a report records for an MCP target.
 */
export const MCP_TOOL_NAME = /^[A-Za-z0-9_.-]{1,128}$/;
/** An engagement id, as the scope spells it. */
export const ENGAGEMENT_ID = /^[A-Za-z0-9_-]{8,64}$/;

/**
 * Why an endpoint is not an exact one, or null. A target is matched by byte
 * equality, so it must be spelt the one way a URL serialises: https, a host,
 * no credentials, no query, no fragment, no pattern, and exactly
 * `new URL(e).href`. The engagement scope and this report share this rule.
 */
export function endpointProblem(endpoint: string): string | null {
    if (endpoint.includes('*')) return 'a pattern is not an endpoint';
    if (endpoint.includes('?') || endpoint.includes('#')) return 'an endpoint carries no query or fragment';
    let url: URL;
    try {
        url = new URL(endpoint);
    } catch {
        return 'not a URL';
    }
    if (url.protocol !== 'https:') return 'not https';
    if (url.username !== '' || url.password !== '') return 'an endpoint carries no credentials';
    if (url.hostname === '') return 'no host';
    if (url.href !== endpoint) return 'not in its canonical spelling (new URL(endpoint).href)';
    return null;
}
