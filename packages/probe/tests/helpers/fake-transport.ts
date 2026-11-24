/** Fake agents as a transport, routed by endpoint, with a clock the tests move. */
import type { ProbeRequest, ProbeTransport } from '../../src/runner';
import type { FakeAgent } from './fake-agents';

export interface FakeClock {
    now: () => number;
    sleep: (ms: number) => Promise<void>;
    readonly sleeps: number[];
    advance: (ms: number) => void;
}

/** A clock that moves only when slept on or advanced; each request costs `perRequestMs`. */
export function fakeClock(startMs: number): FakeClock {
    let t = startMs;
    const sleeps: number[] = [];
    return {
        now: () => t,
        sleep: async (ms) => {
            sleeps.push(ms);
            t += ms;
        },
        sleeps,
        advance: (ms) => {
            t += ms;
        },
    };
}

export interface RecordingTransport {
    readonly transport: ProbeTransport;
    readonly requests: (ProbeRequest & { readonly at: number })[];
}

/**
 * Each endpoint answered by its own fake agent. `afterEach` runs after every
 * request (to move the clock, or flip a stop flag). An endpoint with no agent
 * throws, as a transport to an unreachable host would.
 */
export function fakeTransport(
    agents: Readonly<Record<string, FakeAgent | 'throws'>>,
    clock: FakeClock,
    afterEach: (n: number) => void = () => undefined,
): RecordingTransport {
    const requests: (ProbeRequest & { readonly at: number })[] = [];
    const transport: ProbeTransport = async (request) => {
        requests.push({ ...request, at: clock.now() });
        afterEach(requests.length);
        const agent = agents[request.target.endpoint];
        if (agent === undefined || agent === 'throws') throw new Error('connection refused: secret-ish detail');
        return agent(request.text);
    };
    return { transport, requests };
}
