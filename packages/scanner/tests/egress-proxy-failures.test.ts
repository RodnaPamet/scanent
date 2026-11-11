/**
 * The egress proxy when the far side fails (#5004 part C): what the scanner is
 * told, and that nothing is left open. Loopback sockets only.
 */
import { createServer as createTcpServer, connect, type AddressInfo, type Server as TcpServer, type Socket } from 'node:net';
import type { Server } from 'node:http';

import { createEgressProxy } from '../src/egress-proxy';
import type { LogFields, ScannerLog } from '../src/log';

const ALLOW = new Set(['inflect.example.com']);
const CONNECT = 'CONNECT inflect.example.com:443 HTTP/1.1\r\nHost: inflect.example.com:443\r\n\r\n';

function recordingLog() {
    const events: [string, string, LogFields | undefined][] = [];
    const at = (level: string) => (msg: string, fields?: LogFields) => void events.push([level, msg, fields]);
    const log: ScannerLog = { info: at('info'), warn: at('warn'), error: at('error') };
    return { log, events };
}

const listen = (server: TcpServer | Server) =>
    new Promise<number>((r) => server.listen(0, '127.0.0.1', () => r((server.address() as AddressInfo).port)));
const closed = (server: TcpServer | Server) => new Promise<void>((r) => server.close(() => r()));

/** Everything the proxy sends until it closes the connection. */
function exchange(port: number, bytes: string): Promise<string> {
    return new Promise((resolve, reject) => {
        const s = connect({ host: '127.0.0.1', port });
        let got = '';
        s.on('data', (d) => (got += d.toString('latin1')));
        s.on('close', () => resolve(got));
        s.on('error', reject);
        s.write(bytes);
    });
}

describe('the egress proxy when the upstream fails', () => {
    const servers: (TcpServer | Server)[] = [];
    afterEach(async () => {
        await Promise.all(servers.splice(0).map(closed));
    });

    /** A closed loopback port: a dial to it is refused. */
    async function closedPort(): Promise<number> {
        const s = createTcpServer();
        const port = await listen(s);
        await closed(s);
        return port;
    }

    it('answers 502 when the allowed host cannot be reached, and says so in its log', async () => {
        const dead = await closedPort();
        const { log, events } = recordingLog();
        const proxy = createEgressProxy({ allow: ALLOW, log, dial: () => connect({ host: '127.0.0.1', port: dead }) });
        servers.push(proxy);
        const got = await exchange(await listen(proxy), CONNECT);
        expect(got).toBe('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
        expect(events).toEqual([['warn', 'egress upstream failed', { host: 'inflect.example.com' }]]);
    });

    it('forwards the bytes that arrived with the CONNECT, then closes both sides when the upstream breaks mid-tunnel', async () => {
        let upstreamSocket: Socket | undefined;
        const received: string[] = [];
        const upstream = createTcpServer((s) => {
            upstreamSocket = s;
            s.on('data', (d) => {
                received.push(d.toString('latin1'));
                s.write('pong');
            });
            s.on('error', () => undefined);
        });
        const upstreamPort = await listen(upstream);
        servers.push(upstream);
        const { log, events } = recordingLog();
        let dialled: Socket | undefined;
        const proxy = createEgressProxy({
            allow: ALLOW,
            log,
            dial: () => (dialled = connect({ host: '127.0.0.1', port: upstreamPort })),
        });
        servers.push(proxy);
        const proxyPort = await listen(proxy);

        const client = connect({ host: '127.0.0.1', port: proxyPort });
        let got = '';
        const ended = new Promise<void>((r) => client.on('close', () => r()));
        client.on('error', () => undefined);
        const ponged = new Promise<void>((r) =>
            client.on('data', (d) => {
                got += d.toString('latin1');
                if (got.endsWith('pong')) r();
            }),
        );
        client.write(`${CONNECT}ping`);
        await ponged;
        expect(got).toBe('HTTP/1.1 200 Connection Established\r\n\r\npong');
        expect(received.join('')).toBe('ping');

        // The upstream fails after the tunnel opened: no status line is written
        // into what is by then a TLS stream; the client is simply closed.
        dialled!.destroy(new Error('reset'));
        await ended;
        expect(got).toBe('HTTP/1.1 200 Connection Established\r\n\r\npong');
        expect(events).toEqual([
            ['info', 'egress allowed', { host: 'inflect.example.com', port: 443 }],
            ['warn', 'egress upstream failed', { host: 'inflect.example.com' }],
        ]);
        upstreamSocket?.destroy();
    });

    it('closes the upstream when the scanner hangs up', async () => {
        const upstreamClosed = new Promise<void>((resolve) => {
            const upstream = createTcpServer((s) => {
                s.on('error', () => undefined);
                s.on('close', () => resolve());
            });
            servers.push(upstream);
            void listen(upstream).then(async (upstreamPort) => {
                const proxy = createEgressProxy({ allow: ALLOW, log: recordingLog().log, dial: () => connect({ host: '127.0.0.1', port: upstreamPort }) });
                servers.push(proxy);
                const client = connect({ host: '127.0.0.1', port: await listen(proxy) });
                client.on('error', () => undefined);
                client.on('data', () => client.destroy());
                client.write(CONNECT);
            });
        });
        await upstreamClosed;
    });

    it('logs every refusal with its reason, to stderr as JSON lines when no log is given', async () => {
        const lines: string[] = [];
        const stderr = jest.spyOn(process.stderr, 'write').mockImplementation((chunk) => (lines.push(String(chunk)), true));
        try {
            const proxy = createEgressProxy({
                allow: ALLOW,
                dial: () => {
                    throw new Error('a refused request dials nothing');
                },
            });
            servers.push(proxy);
            const port = await listen(proxy);
            expect(await exchange(port, 'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n')).toMatch(/^HTTP\/1\.1 403 Forbidden\r\n/);
            expect(await exchange(port, 'CONNECT inflect.example.com HTTP/1.1\r\nHost: inflect.example.com\r\n\r\n')).toMatch(/^HTTP\/1\.1 400 Bad Request\r\n/);
            expect(await exchange(port, 'POST / HTTP/1.1\r\nHost: inflect.example.com\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')).toMatch(/^HTTP\/1\.1 405 /);
        } finally {
            stderr.mockRestore();
        }
        const events = lines.map((l) => JSON.parse(l) as Record<string, unknown>);
        expect(events.map((e) => [e.level, e.msg, e.reason, 'host' in e ? e.host : e.method])).toEqual([
            ['warn', 'egress refused', 'HOST_NOT_ALLOWED', 'example.com'],
            ['warn', 'egress refused', 'MALFORMED_TARGET', null],
            ['warn', 'egress refused', 'NOT_CONNECT', 'POST'],
        ]);
    });
});
