/**
 * Posting a report — the scanner's only write.
 *
 *   1. The route is fixed, on the origin of the configured base, https only.
 *   2. The request carries the report unchanged, refuses a redirect, and is
 *      abandoned at its timeout.
 *   3. The answer is reduced to a status and, on a refusal, its code: never
 *      the body.
 *
 * Every test injects its own `fetchImpl`; none opens a socket.
 */
import { ingestUrl, postReport } from '../src/post';
import type { FetchLike } from '../src/http';

const RAW = '{"contract":"inflect-agent-harness/3","body":{"a":1},"signature":"00"}';
const base = { baseUrl: 'https://inflect.example.com', tenantSlug: 'acme', apiKey: 'ingest-key', raw: RAW };

function answering(status: number, body: string | (() => Promise<string>)) {
    const calls: { url: string; init: RequestInit }[] = [];
    const fetchImpl: FetchLike = async (url, init) => {
        calls.push({ url, init });
        if (typeof body === 'string') return new Response(status === 204 ? null : body, { status });
        return { status, text: body } as unknown as Response;
    };
    return { calls, fetchImpl };
}

describe('1. the route', () => {
    it('is the ingest path on the base\'s origin, whatever path or query the base carries', () => {
        expect(ingestUrl('https://inflect.example.com/some/path?x=1#y', 'acme')).toBe(
            'https://inflect.example.com/api/t/acme/admin/agents/harness-scans',
        );
        expect(ingestUrl('https://inflect.example.com:8443', 'acme')).toBe('https://inflect.example.com:8443/api/t/acme/admin/agents/harness-scans');
    });

    it('encodes the tenant slug, so it cannot add a path segment or a query', () => {
        expect(ingestUrl('https://inflect.example.com', '../other?x=1')).toBe(
            'https://inflect.example.com/api/t/..%2Fother%3Fx%3D1/admin/agents/harness-scans',
        );
    });

    it('a base that is not a URL is refused', () => {
        expect(() => ingestUrl('inflect.example.com', 'acme')).toThrow('Invalid URL');
    });

    it.each(['http://inflect.example.com', 'http://localhost:3000', 'ftp://inflect.example.com'])(
        'refuses %s before any request: the request carries the API key',
        async (baseUrl) => {
            const { calls, fetchImpl } = answering(201, '{}');
            await expect(postReport({ ...base, baseUrl, fetchImpl })).rejects.toThrow('the ingest must be reached over https');
            expect(calls).toEqual([]);
        },
    );
});

describe('2. the request', () => {
    it('is one POST of the report, byte for byte, with the key as a bearer token', async () => {
        const { calls, fetchImpl } = answering(201, '{"complete":true,"agentCount":3}');
        await postReport({ ...base, fetchImpl });
        expect(calls).toHaveLength(1);
        expect(calls[0].url).toBe('https://inflect.example.com/api/t/acme/admin/agents/harness-scans');
        expect(calls[0].init.method).toBe('POST');
        expect(calls[0].init.body).toBe(RAW);
        expect(calls[0].init.headers).toEqual({ Authorization: 'Bearer ingest-key', 'Content-Type': 'application/json', Accept: 'application/json' });
    });

    it('refuses to follow a redirect, and a redirect the wire refused stops the post', async () => {
        const { calls, fetchImpl } = answering(201, '{}');
        await postReport({ ...base, fetchImpl });
        expect(calls[0].init.redirect).toBe('error');

        // What `fetch` does with `redirect: 'error'` when the server answers 3xx.
        const redirected: FetchLike = async (_url, init) => {
            if (init.redirect === 'error') throw new TypeError('fetch failed: unexpected redirect');
            return new Response('{}', { status: 201 });
        };
        await expect(postReport({ ...base, fetchImpl: redirected })).rejects.toThrow('unexpected redirect');
    });

    it('is abandoned at its timeout', async () => {
        const hanging: FetchLike = (_url, init) =>
            new Promise((_resolve, reject) => {
                init.signal!.addEventListener('abort', () => reject(init.signal!.reason as Error));
            });
        await expect(postReport({ ...base, fetchImpl: hanging, timeoutMs: 5 })).rejects.toMatchObject({ name: 'TimeoutError' });
    });

    it('waits a minute by default, not for ever', async () => {
        const { calls, fetchImpl } = answering(201, '{}');
        const timeout = jest.spyOn(AbortSignal, 'timeout');
        try {
            await postReport({ ...base, fetchImpl });
            await postReport({ ...base, fetchImpl, timeoutMs: 1234 });
            expect(timeout.mock.calls.map(([ms]) => ms)).toEqual([60_000, 1234]);
            expect(calls[0].init.signal).toBeInstanceOf(AbortSignal);
        } finally {
            timeout.mockRestore();
        }
    });

    it('a wire that fails is not reported as a refusal', async () => {
        const down: FetchLike = async () => {
            throw new Error('ECONNREFUSED');
        };
        await expect(postReport({ ...base, fetchImpl: down })).rejects.toThrow('ECONNREFUSED');
    });
});

describe('3. the answer', () => {
    it('a 201 is ok, with what the ingest derived', async () => {
        const { fetchImpl } = answering(201, '{"complete":false,"agentCount":7,"scanId":"ignored"}');
        expect(await postReport({ ...base, fetchImpl })).toEqual({ ok: true, status: 201, refusal: null, complete: false, agentCount: 7 });
    });

    it.each([
        ['a body that is not JSON', 'created'],
        ['an empty body', ''],
        ['members of the wrong type', '{"complete":"yes","agentCount":"7"}'],
        ['a JSON body with neither member', '{}'],
    ])('a 201 with %s is still ok, and claims nothing it was not told', async (_label, body) => {
        const { fetchImpl } = answering(201, body);
        expect(await postReport({ ...base, fetchImpl })).toEqual({ ok: true, status: 201, refusal: null, complete: null, agentCount: null });
    });

    it('a 201 whose body cannot be read is still ok', async () => {
        const { fetchImpl } = answering(201, async () => {
            throw new Error('the connection dropped mid-body');
        });
        expect(await postReport({ ...base, fetchImpl })).toMatchObject({ ok: true, complete: null, agentCount: null });
    });

    it.each([
        [400, '{"error":"harness_report_refused: SIGNATURE"}', 'SIGNATURE'],
        [400, 'harness_report_refused: SECRET_SHAPED_VALUE and more text', 'SECRET_SHAPED_VALUE'],
        [413, 'harness_report_refused: SIZE', 'SIZE'],
    ])('a %i refusal yields its code and nothing else of the body', async (status, body, code) => {
        const { fetchImpl } = answering(status, body);
        expect(await postReport({ ...base, fetchImpl })).toEqual({ ok: false, status, refusal: code, complete: null, agentCount: null });
    });

    it.each([
        [200, '{"complete":true,"agentCount":1}'],
        [204, ''],
        [401, '{"error":"unauthorized"}'],
        [403, 'harness_report_refused: lower-case is not a code'],
        [429, 'slow down'],
        [500, '<html>Internal Server Error</html>'],
    ])('a %i is not ok and names no refusal code', async (status, body) => {
        const { fetchImpl } = answering(status, body);
        expect(await postReport({ ...base, fetchImpl })).toEqual({ ok: false, status, refusal: null, complete: null, agentCount: null });
    });

    it('reads at most 64 KiB of a refusal: a code past that is not found', async () => {
        const padding = ' '.repeat(64 * 1024);
        const early = answering(400, `harness_report_refused: SCHEMA${padding}`);
        expect((await postReport({ ...base, fetchImpl: early.fetchImpl })).refusal).toBe('SCHEMA');
        const late = answering(400, `${padding}harness_report_refused: SCHEMA`);
        expect((await postReport({ ...base, fetchImpl: late.fetchImpl })).refusal).toBeNull();
    });

    it('a refusal whose body cannot be read is a refusal with no code', async () => {
        const { fetchImpl } = answering(502, async () => {
            throw new Error('reset');
        });
        expect(await postReport({ ...base, fetchImpl })).toEqual({ ok: false, status: 502, refusal: null, complete: null, agentCount: null });
    });
});
