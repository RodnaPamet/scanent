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
 */
import type { ScannerConfig } from './config';
import { AZURE_LOGIN_ORIGIN } from './sources/azure-key-vault';
import { GRAPH_ORIGIN } from './sources/entra';
import { GCP_IAM_ORIGIN, GOOGLE_OAUTH_ORIGIN } from './sources/gcp-service-accounts';
import { GITHUB_API_ORIGIN } from './sources/github-actions';
import { LANGSMITH_CLOUD_ORIGINS } from './sources/langsmith';

export interface HostEntry {
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
    const add = (origin: string, source: string, purpose: HostEntry['purpose'], named: HostEntry['named']) => {
        const host = hostOf(origin);
        if (!out.some((e) => e.host === host && e.source === source && e.purpose === purpose)) out.push({ host, port: 443, source, purpose, named });
    };
    for (const s of config.sources) {
        switch (s.kind) {
            case 'entra-sp':
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
        }
    }
    if (config.inflect !== undefined && postsToInflect(config)) add(config.inflect.baseUrl, 'inflect', 'ingest', 'configured');
    return out.sort((a, b) => (a.host < b.host ? -1 : a.host > b.host ? 1 : a.source < b.source ? -1 : a.source > b.source ? 1 : a.purpose < b.purpose ? -1 : a.purpose > b.purpose ? 1 : 0));
}

/** The distinct host names, sorted. */
export function hostNames(entries: readonly HostEntry[]): string[] {
    return [...new Set(entries.map((e) => e.host))].sort();
}

export type HostsFormat = 'lines' | 'json' | 'egress-allow';
export const HOSTS_FORMATS: readonly HostsFormat[] = ['lines', 'json', 'egress-allow'];

/** What `scanent hosts` prints. `lines`: `host:443` per line. `egress-allow`: the value `EGRESS_ALLOW` takes. */
export function renderHosts(entries: readonly HostEntry[], format: HostsFormat): string {
    const names = hostNames(entries);
    if (format === 'json') return `${JSON.stringify(entries, null, 2)}\n`;
    if (format === 'egress-allow') return names.length === 0 ? '' : `${names.join(',')}\n`;
    return names.map((h) => `${h}:443\n`).join('');
}
