/**
 * THE HOSTS A CONFIGURATION REACHES — derived, offline, from the same
 * constants the declared surface is built from.
 *
 * A network team opening a firewall, a NetworkPolicy and the bundled egress
 * proxy's allowlist all need one list, and it must not fall behind the code.
 * `hostsFor` reads each fixed host from the constant its source exports and
 * each configured host from the configuration, and a test holds the result
 * equal to the hosts a full scan actually contacted.
 *
 * Every port is 443: the scanner makes no request that is not https.
 *
 * GROUPED BY SCANNER. Each entry names the scanner its source belongs to (the
 * `inflect` output posts the agent report, so it is the agent scanner's), and
 * the `lines` format prints one group per scanner that reaches a host, under a
 * `# <scanner>` comment line. A host two scanners reach is listed under each.
 * `egress-allow` is one value for one proxy, so it stays one flat list.
 */
import type { ScannerConfig } from './config';
import { SCANNER_OF_SOURCE, SCANNERS, type ScannerId } from './scanners';
import { AZURE_LOGIN_ORIGIN } from './sources/azure-key-vault';
import { GRAPH_ORIGIN } from './sources/entra';
import { GCP_IAM_ORIGIN, GOOGLE_OAUTH_ORIGIN } from './sources/gcp-service-accounts';
import { GITHUB_API_ORIGIN } from './sources/github-actions';
import { LANGSMITH_CLOUD_ORIGINS } from './sources/langsmith';

export interface HostEntry {
    /** The scanner whose source (or, for `inflect`, whose report) reaches the host. */
    readonly scanner: ScannerId;
    readonly host: string;
    readonly port: 443;
    /** The source kind, or `inflect` for the ingest output. */
    readonly source: string;
    readonly purpose: 'read' | 'token' | 'ingest';
    /** `fixed`: the host is the product's own. `configured`: the configuration names it. */
    readonly named: 'fixed' | 'configured';
}

const hostOf = (origin: string): string => new URL(origin).hostname;

/** Whether the `inflect` output is in effect for a configuration with no flags: `outputs.ts`, rule 1. */
function postsToInflect(config: ScannerConfig): boolean {
    if (config.inflect === undefined) return false;
    return config.outputs === undefined || config.outputs.some((o) => o.kind === 'inflect');
}

/** Every host the configuration makes the scanner reach, one entry per (host, source, purpose), sorted. */
export function hostsFor(config: ScannerConfig): HostEntry[] {
    const out: HostEntry[] = [];
    const add = (origin: string, source: keyof typeof SCANNER_OF_SOURCE | 'inflect', purpose: HostEntry['purpose'], named: HostEntry['named']) => {
        const host = hostOf(origin);
        const scanner: ScannerId = source === 'inflect' ? 'agents' : SCANNER_OF_SOURCE[source];
        if (!out.some((e) => e.host === host && e.source === source && e.purpose === purpose)) out.push({ scanner, host, port: 443, source, purpose, named });
    };
    for (const s of config.sources) {
        switch (s.kind) {
            case 'entra-sp':
            case 'entra-integrations':
                add(AZURE_LOGIN_ORIGIN, s.kind, 'token', 'fixed');
                add(GRAPH_ORIGIN, s.kind, 'read', 'fixed');
                break;
            case 'vault':
                add(AZURE_LOGIN_ORIGIN, s.kind, 'token', 'fixed');
                for (const url of s.vaultUrls) add(url, s.kind, 'read', 'configured');
                break;
            case 'okta-app':
                add(s.orgUrl, s.kind, 'read', 'configured');
                break;
            case 'cicd':
                add(GITHUB_API_ORIGIN, s.kind, 'read', 'fixed');
                break;
            case 'gcp-sa':
                add(GOOGLE_OAUTH_ORIGIN, s.kind, 'token', 'fixed');
                add(GCP_IAM_ORIGIN, s.kind, 'read', 'fixed');
                break;
            case 'runtime':
                if ('cloud' in s.endpoint) add(LANGSMITH_CLOUD_ORIGINS[s.endpoint.cloud], s.kind, 'read', 'fixed');
                else add(s.endpoint.selfHosted, s.kind, 'read', 'configured');
                break;
            case 'mcp':
                for (const server of s.servers) add(server.url, s.kind, 'read', 'configured');
                break;
            case 'inflect-register':
                if (config.inflect !== undefined) add(config.inflect.baseUrl, s.kind, 'read', 'configured');
                break;
            case 'code':
                break;
            default: {
                // Every kind has a case: a kind added without one does not compile.
                const unhandled: never = s;
                throw new Error(`no hosts for ${(unhandled as { kind: string }).kind}`);
            }
        }
    }
    if (config.inflect !== undefined && postsToInflect(config)) add(config.inflect.baseUrl, 'inflect', 'ingest', 'configured');
    const rank = (e: HostEntry): number => SCANNERS.indexOf(e.scanner);
    return out.sort((a, b) =>
        rank(a) !== rank(b)
            ? rank(a) - rank(b)
            : a.host < b.host
                ? -1
                : a.host > b.host
                    ? 1
                    : a.source < b.source
                        ? -1
                        : a.source > b.source
                            ? 1
                            : a.purpose < b.purpose
                                ? -1
                                : a.purpose > b.purpose
                                    ? 1
                                    : 0,
    );
}

/** The distinct host names, sorted. */
export function hostNames(entries: readonly HostEntry[]): string[] {
    return [...new Set(entries.map((e) => e.host))].sort();
}

export type HostsFormat = 'lines' | 'json' | 'egress-allow';
export const HOSTS_FORMATS: readonly HostsFormat[] = ['lines', 'json', 'egress-allow'];

/** How the `lines` format heads each scanner's group. */
export const HOSTS_GROUP_HEADING: Readonly<Record<ScannerId, string>> = Object.freeze({
    agents: '# agent scanner',
    integrations: '# integrations scanner',
});

/**
 * What `scanent hosts` prints. `lines`: per scanner that reaches a host, a
 * `# <scanner>` line and then `host:443` per line, sorted; nothing at all
 * when no host is reached. `json`: every entry, with its scanner, the agent
 * scanner's first. `egress-allow`: the value `EGRESS_ALLOW` takes, one list.
 */
export function renderHosts(entries: readonly HostEntry[], format: HostsFormat): string {
    if (format === 'json') return `${JSON.stringify(entries, null, 2)}\n`;
    if (format === 'egress-allow') {
        const names = hostNames(entries);
        return names.length === 0 ? '' : `${names.join(',')}\n`;
    }
    return SCANNERS.flatMap((scanner) => {
        const names = hostNames(entries.filter((e) => e.scanner === scanner));
        return names.length === 0 ? [] : [`${HOSTS_GROUP_HEADING[scanner]}\n`, ...names.map((h) => `${h}:443\n`)];
    }).join('');
}
