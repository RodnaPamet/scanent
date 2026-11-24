/**
 * The runner (step 5), against fake agents only: what it sends, where, when,
 * how often, and when it stops.
 */
import { PROBES, makeCanary, probesFor } from '../src/catalogue';
import { ENGAGEMENT_HEADER, runProbes, type RunInput } from '../src/runner';
import { verifyEngagementScope } from '../src/scope';
import { signScope } from '../src/scope-sign';
import { PLANTED_MARKER, leaky, obedient, resistant, silent } from './helpers/fake-agents';
import { fakeClock, fakeTransport } from './helpers/fake-transport';
import { END_MS, START, START_MS, makeKey, scopeBody, chatTarget, mcpTarget } from './helpers/scope-keys';

const approver = makeKey();
const prober = makeKey();

const MCP = 'https://mcp.estate.example/mcp';
const CHAT = 'https://chat.estate.example/api/turn';

function verified(overrides: Record<string, unknown> = {}) {
    const raw = signScope(scopeBody(prober, overrides), approver);
    const result = verifyEngagementScope(raw, { trustedScopeKeys: [approver.hex], proberKey: prober.hex });
    if (!result.ok) throw new Error(`scope did not verify: ${result.reason}`);
    return result;
}

const twoTargets = {
    targets: [
        mcpTarget(MCP),
        chatTarget(CHAT),
    ],
};

function setup(agents: Parameters<typeof fakeTransport>[0], scopeOverrides: Record<string, unknown> = twoTargets, at = START_MS) {
    const clock = fakeClock(at);
    const recording = fakeTransport(agents, clock);
    const base: RunInput = {
        scope: verified(scopeOverrides),
        transport: recording.transport,
        now: clock.now,
        sleep: clock.sleep,
        plantedContext: [PLANTED_MARKER],
    };
    return { clock, recording, base };
}

const expectedCount = (classes: ('canary' | 'disclosure')[], kind: 'mcp' | 'a2a' | 'http-chat') => probesFor(classes, kind).length;

describe('a run, target by target', () => {
    it('judges each target by the agent behind it', async () => {
        const { base } = setup({ [MCP]: obedient, [CHAT]: resistant });
        const run = await runProbes(base);
        expect(run.stopped).toBeNull();
        const at = (endpoint: string) => run.outcomes.filter((o) => o.endpoint === endpoint);
        expect(at(MCP).every((o) => o.verdict === 'ACTED' || o.verdict === 'DISCLOSED')).toBe(true);
        expect(at(CHAT).every((o) => o.verdict === 'RESISTED')).toBe(true);
        expect(at(MCP)).toHaveLength(expectedCount(['canary', 'disclosure'], 'mcp'));
        expect(at(CHAT)).toHaveLength(expectedCount(['canary', 'disclosure'], 'http-chat'));
        expect(run.targets).toEqual([
            { endpoint: MCP, kind: 'mcp', reached: true, reason: 'REACHED' },
            { endpoint: CHAT, kind: 'http-chat', reached: true, reason: 'REACHED' },
        ]);
        expect(run.concluded).toBe(true);
        expect(run.engagementId).toBe('eng-2026-12-acme');
        expect(run.scopeDigest).toBe(base.scope.digest);
    });

    it('sends only to the scope\'s endpoints, with the engagement header and no other', async () => {
        const { base, recording } = setup({ [MCP]: leaky, [CHAT]: leaky });
        await runProbes(base);
        expect(recording.requests.length).toBeGreaterThan(0);
        for (const r of recording.requests) {
            expect([MCP, CHAT]).toContain(r.target.endpoint);
            expect(r.headers).toEqual({ [ENGAGEMENT_HEADER]: 'eng-2026-12-acme' });
        }
    });

    it('sends only the scope\'s classes, and only probes for each target\'s interface', async () => {
        const { base, recording } = setup({ [MCP]: obedient, [CHAT]: obedient }, { ...twoTargets, classes: ['disclosure'] });
        const run = await runProbes(base);
        const kindOf = new Map([[MCP, 'mcp'], [CHAT, 'http-chat']] as const);
        for (const o of run.outcomes) {
            const probe = PROBES.find((p) => p.id === o.probeId);
            expect(probe?.class).toBe('disclosure');
            expect(probe?.interfaces).toContain(kindOf.get(o.endpoint as typeof MCP));
        }
        expect(recording.requests).toHaveLength(expectedCount(['disclosure'], 'mcp') + expectedCount(['disclosure'], 'http-chat'));
        expect(run.outcomes).toHaveLength(recording.requests.length);
    });

    it('every interface has probes of each class, so no allowed target goes unprobed', () => {
        // NO_PROBES_FOR_INTERFACE is the runner's answer if the catalogue ever loses one; today it cannot happen.
        for (const kind of ['mcp', 'a2a', 'http-chat'] as const) {
            for (const cls of ['canary', 'disclosure'] as const) expect([kind, cls, expectedCount([cls], kind) > 0]).toEqual([kind, cls, true]);
        }
    });

    it('makes a fresh canary for every canary probe on every target', async () => {
        const { base, recording } = setup({ [MCP]: obedient, [CHAT]: obedient });
        await runProbes(base);
        const halves = recording.requests.map((r) => /scanent-[0-9a-f]{8}/.exec(r.text)?.[0]).filter((h): h is string => h !== undefined);
        expect(halves.length).toBe(expectedCount(['canary'], 'mcp') + expectedCount(['canary'], 'http-chat'));
        expect(new Set(halves).size).toBe(halves.length);
    });

    it('refuses a canary made twice, rather than send a marker that names two probes', async () => {
        const { base } = setup({ [MCP]: obedient, [CHAT]: obedient });
        const fixed = makeCanary();
        await expect(runProbes({ ...base, canary: () => fixed })).rejects.toThrow('a canary was made twice in one run');
    });
});

describe('no reply', () => {
    it('a silent target is not reached, and concludes nothing', async () => {
        const { base } = setup({ [MCP]: silent, [CHAT]: silent });
        const run = await runProbes(base);
        expect(run.targets.map((t) => t.reason)).toEqual(['NO_REPLY', 'NO_REPLY']);
        expect(run.outcomes.every((o) => o.verdict === 'INCONCLUSIVE' && o.reason === 'NO_REPLY')).toBe(true);
        expect(run.concluded).toBe(false);
    });

    it('a transport that throws is NO_REPLY, keeps no error text, and the run goes on', async () => {
        const { base } = setup({ [MCP]: 'throws', [CHAT]: resistant });
        const run = await runProbes(base);
        expect(run.targets.map((t) => t.reason)).toEqual(['NO_REPLY', 'REACHED']);
        expect(JSON.stringify(run)).not.toContain('secret-ish');
        expect(run.concluded).toBe(true);
    });
});

describe('the window, read before every request', () => {
    it('a run before the window sends nothing', async () => {
        const { base, recording } = setup({ [MCP]: obedient, [CHAT]: obedient }, twoTargets, START_MS - 1);
        const run = await runProbes(base);
        expect(run.stopped).toBe('NOT_YET_OPEN');
        expect(recording.requests).toHaveLength(0);
        expect(run.targets.every((t) => t.reason === 'NOT_RUN')).toBe(true);
        expect(run.concluded).toBe(false);
    });

    it('a run that reaches the end of the window stops at its next request', async () => {
        const clock = fakeClock(END_MS - 1);
        const recording = fakeTransport({ [MCP]: obedient, [CHAT]: obedient }, clock, () => clock.advance(1));
        const run = await runProbes({ scope: verified(twoTargets), transport: recording.transport, now: clock.now, sleep: clock.sleep });
        expect(recording.requests).toHaveLength(1);
        expect(run.stopped).toBe('CLOSED');
        expect(run.targets.map((t) => t.reason)).toEqual(['REACHED', 'NOT_RUN']);
    });

    it('a rate wait that crosses the end of the window stops the run before it sends', async () => {
        // One request a minute, starting 30 s before the end: the second request would be after it.
        const clock = fakeClock(END_MS - 30_000);
        const recording = fakeTransport({ [MCP]: obedient }, clock);
        const run = await runProbes({
            scope: verified({ targets: [mcpTarget(MCP)], ratePerMinute: 1 }),
            transport: recording.transport,
            now: clock.now,
            sleep: clock.sleep,
        });
        expect(recording.requests).toHaveLength(1);
        expect(run.stopped).toBe('CLOSED');
    });
});

describe('the rate cap', () => {
    it('keeps each target\'s requests at least 60000 / rate apart, without slowing another target', async () => {
        const { base, recording } = setup({ [MCP]: resistant, [CHAT]: resistant }, { ...twoTargets, ratePerMinute: 30 });
        await runProbes(base);
        for (const endpoint of [MCP, CHAT]) {
            const times = recording.requests.filter((r) => r.target.endpoint === endpoint).map((r) => r.at);
            for (let i = 1; i < times.length; i += 1) expect(times[i] - times[i - 1]).toBeGreaterThanOrEqual(2_000);
        }
        // The first request to the second target is not held back by the first target's last.
        const firstChat = recording.requests.findIndex((r) => r.target.endpoint === CHAT);
        expect(recording.requests[firstChat].at).toBe(recording.requests[firstChat - 1].at);
    });

    it('at the highest rate, half a second apart', async () => {
        const { base, clock } = setup({ [MCP]: resistant }, { targets: [mcpTarget(MCP)], ratePerMinute: 120 });
        await runProbes(base);
        expect(clock.sleeps.length).toBeGreaterThan(0);
        expect(clock.sleeps.every((ms) => ms === 500)).toBe(true);
    });
});

describe('stopping', () => {
    it('a stop asked for mid-run ends it at the next request', async () => {
        let stop = false;
        const clock = fakeClock(START_MS);
        const recording = fakeTransport({ [MCP]: obedient, [CHAT]: obedient }, clock, (n) => {
            if (n === 3) stop = true;
        });
        const run = await runProbes({
            scope: verified(twoTargets),
            transport: recording.transport,
            now: clock.now,
            sleep: clock.sleep,
            shouldStop: () => stop,
        });
        expect(recording.requests).toHaveLength(3);
        expect(run.stopped).toBe('STOPPED');
        expect(run.outcomes).toHaveLength(3);
    });
});

describe('a dry run', () => {
    it('sends nothing, and plans exactly what a real run sends', async () => {
        const dry = setup({ [MCP]: obedient, [CHAT]: obedient });
        const plan = await runProbes({ ...dry.base, dryRun: true });
        expect(dry.recording.requests).toHaveLength(0);
        expect(plan.dryRun).toBe(true);
        expect(plan.outcomes).toEqual([]);
        expect(plan.concluded).toBe(false);

        const real = setup({ [MCP]: obedient, [CHAT]: obedient });
        const run = await runProbes(real.base);
        expect(plan.planned.map((p) => [p.endpoint, p.probeId])).toEqual(run.outcomes.map((o) => [o.endpoint, o.probeId]));
        expect(plan.planned.map((p) => p.endpoint)).toEqual(real.recording.requests.map((r) => r.target.endpoint));
    });

    it('a dry run outside the window still plans: it sends nothing, so it needs no window', async () => {
        const { base } = setup({}, twoTargets, Date.parse(START) - 86_400_000);
        const plan = await runProbes({ ...base, dryRun: true });
        expect(plan.planned.length).toBeGreaterThan(0);
        expect(plan.stopped).toBeNull();
    });
});
