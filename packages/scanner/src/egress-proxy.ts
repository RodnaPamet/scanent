/**
 * THE SCANNER'S EGRESS PROXY — the only way out of its network.
 *
 * In the VM overlay the scanner sits on an INTERNAL Docker network with no
 * route out. This proxy is the one container on both that network and one that
 * reaches the internet, and it forwards exactly one thing: a CONNECT tunnel to
 * a host on its allowlist, on port 443. Everything else is refused:
 *
 *   • a CONNECT to any other host, any other port, or an IP literal — 403;
 *   • any plain HTTP request, absolute-form or not — 405: the scanner speaks
 *     only https, so a proxy that relayed cleartext would be a second, wider
 *     door beside the first;
 *   • a malformed target — 400.
 *
 * The allowlist is EXACT hostnames, lower-cased, from `EGRESS_ALLOW`
 * (comma-separated). No wildcard and no suffix match: `*.example.com` would
 * admit any host somebody can create under it. An empty or missing allowlist
 * refuses everything, so a proxy started without its configuration fails
 * CLOSED.
 *
 * It decides on the CONNECT line, before any byte of the tunnel, and never sees
 * inside it: TLS runs end to end between the scanner and the host. So it logs
 * what it decided — host, port, allowed or refused — and can log nothing else,
 * because it holds nothing else.
 *
 * AN ALLOWLISTED NAME IS NOT ENOUGH: THE ADDRESS IS CHECKED, AND IT IS THE
 * ADDRESS DIALLED. The allowlist now carries hosts an estate names (an MCP
 * server, a self-hosted LangSmith), and whoever answers DNS for such a name
 * chooses where it points. So the proxy resolves the name itself, refuses when
 * ANY address is loopback, link-local (cloud metadata) or unspecified, or is
 * private and outside `EGRESS_PRIVATE_CIDR_ALLOWLIST`, and connects to the
 * address it checked, never to the name again. TLS runs inside the tunnel with
 * the client's own server name, so connecting by address costs nothing. This
 * is the scanner's own rule (`customer-host.ts`) applied where the connection
 * is made, which is what lets a scanner with no resolver of its own leave the
 * check to this proxy (`EGRESS_PROXY_CHECKS_ADDRESSES`).
 *
 * It ships in the scanner's own image and runs from the same pinned digest
 * (`deploy/compose.egress.yaml`), so the proxy is the reviewed
 * code beside the scanner, not a third-party image with its own supply chain.
 */
import { createServer, type IncomingMessage, type Server } from 'node:http';
import { connect, isIP, type Socket } from 'node:net';
import type { Duplex } from 'node:stream';

import { addressReachable, parsePrivateCidrAllowlist, resolveWithDns, type PrivateCidrAllowlist, type ResolveHost } from './customer-host';
import { jsonLineLog, type ScannerLog } from './log';

/** The one port a tunnel may name: the scanner speaks https and nothing else. */
export const EGRESS_PORT = 443;
/** Where the proxy listens inside its container. */
export const EGRESS_PROXY_LISTEN_PORT = 3128;

/** A hostname as DNS allows it, lower-case: labels of letters, digits and hyphens. */
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

/** `EGRESS_ALLOW` to the set of exact hostnames it names. Anything not a plain hostname is refused. */
export function parseEgressAllowlist(value: string | undefined): ReadonlySet<string> {
    const hosts = new Set<string>();
    for (const raw of (value ?? '').split(',')) {
        const host = raw.trim().toLowerCase();
        if (host === '') continue;
        if (!HOSTNAME.test(host) || isIP(host) !== 0) {
            throw new Error(`EGRESS_ALLOW names something that is not a hostname: ${JSON.stringify(raw.trim())}`);
        }
        hosts.add(host);
    }
    return hosts;
}

export type EgressDecision =
    | { readonly allowed: true; readonly host: string; readonly port: number }
    | { readonly allowed: false; readonly status: 400 | 403; readonly reason: string; readonly host: string | null };

/** The decision for one CONNECT target (`host:port`), against the allowlist. Pure. */
export function decideConnect(target: string | undefined, allow: ReadonlySet<string>): EgressDecision {
    const m = /^([^:\s/@]+):(\d{1,5})$/.exec(target ?? '');
    if (m === null) return { allowed: false, status: 400, reason: 'MALFORMED_TARGET', host: null };
    const host = m[1].toLowerCase();
    const port = Number(m[2]);
    if (isIP(host) !== 0) return { allowed: false, status: 403, reason: 'IP_LITERAL', host };
    if (port !== EGRESS_PORT) return { allowed: false, status: 403, reason: 'PORT_NOT_ALLOWED', host };
    if (!allow.has(host)) return { allowed: false, status: 403, reason: 'HOST_NOT_ALLOWED', host };
    return { allowed: true, host, port };
}

export interface EgressProxyOptions {
    readonly allow: ReadonlySet<string>;
    readonly log?: ScannerLog;
    /**
     * Opens the upstream connection, by NAME, with no address check. A TEST
     * SEAM: production passes none, and resolves, checks and dials an address.
     * Passed with `resolve`, the name is still resolved and checked first.
     */
    readonly dial?: (host: string, port: number) => Socket;
    /** How an allowlisted name is resolved. Absent (and no `dial`), DNS. */
    readonly resolve?: ResolveHost;
    /** Opens the connection to a checked ADDRESS. Absent, `net.connect`. */
    readonly connectAddress?: (address: string, port: number) => Socket;
    /** Private ranges the proxy may dial (`EGRESS_PRIVATE_CIDR_ALLOWLIST`). Loopback, link-local and metadata are refused inside them too. */
    readonly privateCidrs?: PrivateCidrAllowlist;
    /** How long a connection may carry nothing before it is closed. Absent, `EGRESS_IDLE_TIMEOUT_MS`. */
    readonly idleTimeoutMs?: number;
    /** How many connections may be open at once. Absent, `EGRESS_MAX_CONNECTIONS`. */
    readonly maxConnections?: number;
}

/**
 * A connection that carries nothing for this long is closed: one that asked
 * for nothing, one whose upstream never answered, and an open tunnel gone
 * quiet. Without it, anything that can reach the port could hold sockets open
 * for as long as it liked. It counts silence, not duration: a long download
 * keeps its tunnel for as long as bytes move. What it does cut is a read whose
 * server sends nothing for two minutes; the scanner reports that source
 * incomplete, as it does any read that fails.
 */
export const EGRESS_IDLE_TIMEOUT_MS = 120_000;

/**
 * How many connections the proxy holds at once; one over is dropped by the
 * server as it arrives. A scan reads its sources one request after another per
 * source, so a few dozen is a busy scan and this is several times that.
 */
export const EGRESS_MAX_CONNECTIONS = 256;

/** `EGRESS_PRIVATE_CIDR_ALLOWLIST` (comma-separated CIDRs) parsed. An entry that is not a CIDR is refused: the proxy does not start. */
export function parseEgressPrivateCidrs(value: string | undefined): PrivateCidrAllowlist {
    const entries = (value ?? '').split(',').map((s) => s.trim()).filter((s) => s !== '');
    const parsed = parsePrivateCidrAllowlist(entries);
    if (parsed === null) throw new Error('EGRESS_PRIVATE_CIDR_ALLOWLIST names something that is not a CIDR');
    return parsed;
}

function refuse(socket: Duplex, status: 400 | 403 | 405 | 502, text: string): void {
    socket.end(`HTTP/1.1 ${status} ${text}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
}

export function createEgressProxy(opts: EgressProxyOptions): Server {
    const log = opts.log ?? jsonLineLog();
    const privateCidrs = opts.privateCidrs ?? [];
    // The name is resolved and its addresses checked whenever the production path runs, or a test asks for it.
    const resolve = opts.resolve ?? (opts.dial === undefined ? resolveWithDns : null);
    const connectAddress = opts.connectAddress ?? ((address: string, port: number) => connect({ host: address, port }));
    const idleTimeoutMs = opts.idleTimeoutMs ?? EGRESS_IDLE_TIMEOUT_MS;
    const server = createServer((req, res) => {
        // Cleartext forwarding is never offered.
        log.warn('egress refused', { reason: 'NOT_CONNECT', method: String(req.method ?? '') });
        res.writeHead(405, { Connection: 'close', 'Content-Length': '0' }).end();
    });
    // The two bounds on what a peer can hold. The count is the server's own:
    // a connection over it is closed as it arrives, before anything is read.
    // The idle limit covers a connection that has asked for nothing yet; a
    // tunnel is no longer the HTTP server's socket, and is given its own below.
    server.maxConnections = opts.maxConnections ?? EGRESS_MAX_CONNECTIONS;
    server.on('drop', () => log.warn('egress refused', { reason: 'TOO_MANY_CONNECTIONS' }));
    server.timeout = idleTimeoutMs;
    server.headersTimeout = Math.min(server.headersTimeout, idleTimeoutMs);
    server.requestTimeout = Math.min(server.requestTimeout, idleTimeoutMs);
    server.on('connect', (req: IncomingMessage, client: Duplex, head: Buffer) => {
        // From here the socket is this handler's: Node's own listeners are gone.
        // A client that resets while it is being refused, or twice, would
        // otherwise raise an `error` nobody listens for, which ends the process
        // and with it every other scanner's way out. Each path below still
        // reacts to the first error in its own way; this one only absorbs.
        client.on('error', () => undefined);
        const decision = decideConnect(req.url, opts.allow);
        if (!decision.allowed) {
            log.warn('egress refused', { reason: decision.reason, host: decision.host });
            refuse(client, decision.status, decision.status === 400 ? 'Bad Request' : 'Forbidden');
            return;
        }
        // One limit, on both sockets. Before the tunnel opens it is the limit on
        // getting one (the name resolved, the upstream connected), and the
        // client is owed an answer; after, it is the limit on the tunnel's
        // silence. Bytes one way are a write on the other socket, so traffic
        // resets both timers. Whichever fires first ends both ends: the client
        // closing destroys the upstream, below.
        let established = false;
        const giveUp = (): void => {
            log.warn('egress closed', { reason: established ? 'IDLE' : 'UPSTREAM_DID_NOT_CONNECT', host: decision.host });
            if (!established && client.writable) refuse(client, 502, 'Bad Gateway');
            else client.destroy();
        };
        (client as Socket).setTimeout(idleTimeoutMs, giveUp);
        const open = (upstream: Socket): void => {
            upstream.setTimeout(idleTimeoutMs, () => {
                giveUp();
                upstream.destroy();
            });
            upstream.once('connect', () => {
                established = true;
                log.info('egress allowed', { host: decision.host, port: decision.port });
                client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
                if (head.length > 0) upstream.write(head);
                upstream.pipe(client);
                client.pipe(upstream);
            });
            // The same for the upstream: its first error is handled below, a second is absorbed.
            upstream.on('error', () => undefined);
            upstream.once('error', () => {
                log.warn('egress upstream failed', { host: decision.host });
                // Before the tunnel opened, the client is owed an answer; after,
                // the bytes are TLS and a status line would corrupt them.
                if (!established && client.writable) refuse(client, 502, 'Bad Gateway');
                else client.destroy();
            });
            client.once('error', () => upstream.destroy());
            client.once('close', () => upstream.destroy());
        };
        if (resolve === null) {
            open((opts.dial as NonNullable<typeof opts.dial>)(decision.host, decision.port));
            return;
        }
        // The client may go away while the name resolves; nothing is dialled for it then.
        let gone = false;
        client.once('close', () => {
            gone = true;
        });
        client.once('error', () => {
            gone = true;
        });
        resolve(decision.host).then(
            (addresses) => {
                if (gone) return;
                if (addresses.length === 0) {
                    log.warn('egress refused', { reason: 'HOST_DID_NOT_RESOLVE', host: decision.host });
                    refuse(client, 502, 'Bad Gateway');
                    return;
                }
                // EVERY address, as the scanner's own check has it: one bad answer among good ones is a bad name.
                if (!addresses.every((a) => addressReachable(a, privateCidrs))) {
                    log.warn('egress refused', { reason: 'ADDRESS_NOT_ALLOWED', host: decision.host });
                    refuse(client, 403, 'Forbidden');
                    return;
                }
                // The address that was checked is the address dialled: the name is not resolved a second time.
                open(opts.dial === undefined ? connectAddress(addresses[0], decision.port) : opts.dial(decision.host, decision.port));
            },
            () => {
                if (gone) return;
                log.warn('egress refused', { reason: 'HOST_DID_NOT_RESOLVE', host: decision.host });
                refuse(client, 502, 'Bad Gateway');
            },
        );
    });
    return server;
}

if (require.main === module) {
    const log = jsonLineLog();
    for (const [signal, code] of [['SIGTERM', 143], ['SIGINT', 130]] as const) {
        process.once(signal, () => process.exit(code));
    }
    const allow = parseEgressAllowlist(process.env.EGRESS_ALLOW);
    const privateCidrs = parseEgressPrivateCidrs(process.env.EGRESS_PRIVATE_CIDR_ALLOWLIST);
    // An empty allowlist is not an error the proxy can recover from: it would
    // refuse every tunnel. Say so at start rather than at the scanner's first
    // read, and keep running — refusing everything is the safe state.
    if (allow.size === 0) log.warn('egress allowlist is empty: every tunnel will be refused');
    createEgressProxy({ allow, privateCidrs, log }).listen(EGRESS_PROXY_LISTEN_PORT, () => {
        log.info('egress proxy listening', { port: EGRESS_PROXY_LISTEN_PORT, hosts: [...allow].sort().join(',') });
    });
}
