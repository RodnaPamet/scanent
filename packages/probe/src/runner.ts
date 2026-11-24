/**
 * THE RUNNER: sends the catalogue's probes to a scope's targets, and judges
 * each reply (step 5 of docs/design/active-flavour.md).
 *
 * It starts only from a VERIFIED scope, and sends only through the transport
 * it is handed. In this build every transport is a fake agent: the real MCP,
 * A2A and HTTP transports, with their declared request surface, come with the
 * prober's image (step 7).
 *
 * Before EVERY request, in this order:
 *
 *   1. the stop check (a stop file or a signal ends the run at the next request);
 *   2. the scope's gate, read with the clock at that request: a closed or
 *      not-yet-open window stops the whole run; a target or class the scope
 *      does not admit stops it too, because a plan built from the scope cannot
 *      produce one, and a refusal that should be impossible means the plan is
 *      wrong;
 *   3. the rate cap: at least 60000 / ratePerMinute ms since the last request
 *      to the SAME target.
 *
 * Each request carries `X-Scanent-Engagement`, so the target's owner can find
 * the engagement in their logs. A transport that throws or answers nothing is
 * NO_REPLY (INCONCLUSIVE) and the run goes on; no error text is kept, because a
 * transport's error can carry what the target said.
 *
 * Zero is never complete: `concluded` is true only when some probe got a
 * verdict other than INCONCLUSIVE, which needs a target that answered.
 */
import { makeCanary, probesFor, renderProbe, type Probe } from './catalogue';
import { scopeAdmits, type EngagementScope, type ScopeVerifyResult } from './scope';
import { judge, type ProbeOutcome } from './verdict';

/** The header every request carries. */
export const ENGAGEMENT_HEADER = 'X-Scanent-Engagement';

export type ScopeTarget = EngagementScope['targets'][number];

export interface ProbeRequest {
    readonly target: ScopeTarget;
    readonly text: string;
    readonly headers: Readonly<Record<string, string>>;
}

/** Sends one probe and returns the reply, or null when there is none. */
export type ProbeTransport = (request: ProbeRequest) => Promise<string | null>;

export type RunStop = 'STOPPED' | 'NOT_YET_OPEN' | 'CLOSED' | 'TARGET_NOT_NAMED' | 'CLASS_NOT_ALLOWED';

export type TargetReason = 'REACHED' | 'NO_REPLY' | 'NO_PROBES_FOR_INTERFACE' | 'NOT_RUN';

export interface TargetResult {
    readonly endpoint: string;
    readonly kind: ScopeTarget['kind'];
    readonly reached: boolean;
    readonly reason: TargetReason;
}

export interface TargetedOutcome extends ProbeOutcome {
    readonly endpoint: string;
}

export interface PlannedRequest {
    readonly endpoint: string;
    readonly probeId: string;
    readonly probeClass: Probe['class'];
    readonly text: string;
}

export interface ProbeRun {
    readonly engagementId: string;
    readonly scopeDigest: string;
    readonly startedAt: string;
    readonly endedAt: string;
    readonly dryRun: boolean;
    /** Why the run ended early, or null when every planned probe was sent. */
    readonly stopped: RunStop | null;
    readonly targets: readonly TargetResult[];
    readonly outcomes: readonly TargetedOutcome[];
    /** A dry run's requests, never sent. Empty for a real run. */
    readonly planned: readonly PlannedRequest[];
    /** True only when some probe concluded something, which needs a target that answered. */
    readonly concluded: boolean;
}

export interface RunInput {
    readonly scope: Extract<ScopeVerifyResult, { ok: true }>;
    readonly transport: ProbeTransport;
    readonly now: () => number;
    readonly sleep: (ms: number) => Promise<void>;
    readonly shouldStop?: () => boolean;
    /** Markers the estate planted in the agent's instructions, for `planted-context` probes. */
    readonly plantedContext?: readonly string[];
    readonly dryRun?: boolean;
    /** A TEST SEAM: how a canary is made. */
    readonly canary?: () => string;
}

interface PlanItem {
    readonly target: ScopeTarget;
    readonly probe: Probe;
    readonly canary: string | undefined;
    readonly text: string;
}

/** Every request the scope allows, target by target in the scope's order, probes in the catalogue's. */
function planOf(scope: EngagementScope, canary: () => string): { items: PlanItem[]; empty: Set<string> } {
    const items: PlanItem[] = [];
    const empty = new Set<string>();
    const seen = new Set<string>();
    for (const target of scope.targets) {
        const probes = probesFor(scope.classes, target.kind);
        if (probes.length === 0) empty.add(target.endpoint);
        for (const probe of probes) {
            let marker: string | undefined;
            if (probe.class === 'canary') {
                marker = canary();
                // A canary names one probe on one target in one run, or a returned marker names nothing.
                if (seen.has(marker)) throw new Error('a canary was made twice in one run');
                seen.add(marker);
            }
            items.push({ target, probe, canary: marker, text: renderProbe(probe, marker) });
        }
    }
    return { items, empty };
}

/** The requests a run under this scope would send, in order, without sending any: what a dry run shows. */
export function planRequests(scope: EngagementScope, canary: () => string = () => makeCanary()): PlannedRequest[] {
    return planOf(scope, canary).items.map((item) => ({
        endpoint: item.target.endpoint,
        probeId: item.probe.id,
        probeClass: item.probe.class,
        text: item.text,
    }));
}

export async function runProbes(input: RunInput): Promise<ProbeRun> {
    const { scope: verified, transport, now, sleep } = input;
    const scope = verified.scope;
    const shouldStop = input.shouldStop ?? (() => false);
    const startedAt = new Date(now()).toISOString();
    const { items, empty } = planOf(scope, input.canary ?? (() => makeCanary()));
    const headers = Object.freeze({ [ENGAGEMENT_HEADER]: scope.engagementId });
    const minGapMs = 60_000 / scope.ratePerMinute;

    const outcomes: TargetedOutcome[] = [];
    const planned: PlannedRequest[] = [];
    const lastSentAt = new Map<string, number>();
    let stopped: RunStop | null = null;

    for (const item of items) {
        if (input.dryRun) {
            planned.push({ endpoint: item.target.endpoint, probeId: item.probe.id, probeClass: item.probe.class, text: item.text });
            continue;
        }

        if (shouldStop()) {
            stopped = 'STOPPED';
            break;
        }
        const last = lastSentAt.get(item.target.endpoint);
        if (last !== undefined) {
            const wait = last + minGapMs - now();
            if (wait > 0) await sleep(wait);
        }
        // The gate reads the clock AFTER the wait: a wait that crossed the end of the window stops the run.
        const refusal = scopeAdmits(scope, { now: now(), target: item.target.endpoint, probeClass: item.probe.class });
        if (refusal !== null) {
            stopped = refusal;
            break;
        }

        lastSentAt.set(item.target.endpoint, now());
        let reply: string | null;
        try {
            reply = await transport({ target: item.target, text: item.text, headers });
        } catch {
            reply = null;
        }
        const outcome = judge({ probe: item.probe, canary: item.canary, reply, plantedContext: input.plantedContext });
        outcomes.push({ ...outcome, endpoint: item.target.endpoint });
    }

    const targets: TargetResult[] = scope.targets.map((target) => {
        const mine = outcomes.filter((o) => o.endpoint === target.endpoint);
        const base = { endpoint: target.endpoint, kind: target.kind };
        if (empty.has(target.endpoint)) return { ...base, reached: false, reason: 'NO_PROBES_FOR_INTERFACE' };
        if (mine.length === 0) return { ...base, reached: false, reason: 'NOT_RUN' };
        const reached = mine.some((o) => o.reason !== 'NO_REPLY');
        return { ...base, reached, reason: reached ? 'REACHED' : 'NO_REPLY' };
    });

    return {
        engagementId: scope.engagementId,
        scopeDigest: verified.digest,
        startedAt,
        endedAt: new Date(now()).toISOString(),
        dryRun: input.dryRun === true,
        stopped,
        targets,
        outcomes,
        planned,
        // A verdict other than INCONCLUSIVE needs a reply, so it implies a reached target: no run that reached nothing concludes.
        concluded: outcomes.some((o) => o.verdict !== 'INCONCLUSIVE'),
    };
}
