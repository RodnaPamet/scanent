/**
 * `scanent hosts`: the hosts a configuration reaches, derived offline, and
 * held to what a scan actually contacts.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { main } from '../src/cli';
import { parseScannerConfig } from '../src/config';
import { parseEgressAllowlist } from '../src/egress-proxy';
import { hostNames, hostsFor, renderHosts } from '../src/hosts';
import { jsonLineLog } from '../src/log';
import { scanAndDeliver } from '../src/outputs';
import { createDoctorWorld, fullEstateConfig, fullEstateEnv } from './helpers/doctor-world';
import { agentsOf } from './helpers/run-scan';

let dir: string;
beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'scanent-hosts-'));
});
afterEach(() => {
    jest.restoreAllMocks();
    rmSync(dir, { recursive: true, force: true });
});

const full = () => parseScannerConfig(fullEstateConfig('/out'));

describe('hostsFor', () => {
    it('lists each source\'s hosts, fixed and configured, every one on 443', () => {
        const entries = hostsFor(full());
        expect(entries.every((e) => e.port === 443)).toBe(true);
        const by = (source: string) => entries.filter((e) => e.source === source).map((e) => `${e.host} ${e.purpose} ${e.named}`);
        expect(by('entra-sp')).toEqual(['graph.microsoft.com read fixed', 'login.microsoftonline.com token fixed']);
        expect(by('vault')).toEqual(['acme-agents.vault.azure.net read configured', 'login.microsoftonline.com token fixed']);
        expect(by('okta-app')).toEqual(['acme.okta.com read configured']);
        expect(by('cicd')).toEqual(['api.github.com read fixed']);
        expect(by('gcp-sa')).toEqual(['iam.googleapis.com read fixed', 'oauth2.googleapis.com token fixed']);
        expect(by('runtime')).toEqual(['api.smith.langchain.com read fixed']);
        expect(by('mcp')).toEqual(['mcp.acme.example read configured']);
        expect(by('inflect-register')).toEqual(['inflect.example.com read configured']);
        expect(by('inflect')).toEqual(['inflect.example.com ingest configured']);
        expect(by('code')).toEqual([]);
    });

    it('follows the region, a self-hosted LangSmith, and whether the tenant is posted to', () => {
        const base = { estate: 'a', scanner: { agentId: 'a', signingKeyEnv: 'K' }, schedule: { everyHours: 1 } };
        const eu = parseScannerConfig({ ...base, outputs: [{ kind: 'stdout' }], sources: [{ kind: 'runtime', product: 'langsmith', endpoint: { cloud: 'eu' }, apiKeyEnv: 'L' }] });
        expect(hostNames(hostsFor(eu))).toEqual(['eu.api.smith.langchain.com']);
        const own = parseScannerConfig({ ...base, outputs: [{ kind: 'stdout' }], sources: [{ kind: 'runtime', product: 'langsmith', endpoint: { selfHosted: 'https://langsmith.acme.example' }, apiKeyEnv: 'L' }] });
        expect(hostsFor(own)).toEqual([{ scanner: 'agents', host: 'langsmith.acme.example', port: 443, source: 'runtime', purpose: 'read', named: 'configured' }]);
        const inflect = { baseUrl: 'https://tenant.example.com', tenantSlug: 't', apiKeyEnv: 'I' };
        const code = [{ kind: 'code', product: 'langchain', roots: [{ label: 'r', path: '/srv/code' }] }];
        // An inflect block with no outputs posts, as it always has; one with only a file output does not.
        expect(hostNames(hostsFor(parseScannerConfig({ ...base, inflect, sources: code })))).toEqual(['tenant.example.com']);
        expect(hostsFor(parseScannerConfig({ ...base, inflect, outputs: [{ kind: 'file', dir: '/out' }], sources: code }))).toEqual([]);
    });

    it('is exactly the set of hosts a full scan contacts', async () => {
        const world = createDoctorWorld();
        const config = parseScannerConfig(fullEstateConfig(join(dir, 'out')));
        const result = await scanAndDeliver({
            config,
            env: fullEstateEnv(),
            log: jsonLineLog(() => undefined),
            outputs: [{ kind: 'inflect' }],
            fetchImpl: world.fetchImpl,
            resolveHost: async () => ['93.184.216.34'],
            now: () => Date.parse('2026-10-19T03:00:00.000Z'),
        });
        expect(result.ok).toBe(true);
        expect(agentsOf(result).body.population.sources.filter((s) => s.status !== 'COMPLETE')).toEqual([]);
        expect([...new Set(world.log.map((r) => r.host))].sort()).toEqual(hostNames(hostsFor(config)));
    });
});

describe('the three formats', () => {
    /** The full estate with the integrations scanner's source beside the agent scanner's. */
    const both = () => {
        const c = fullEstateConfig('/out');
        const integrations = { kind: 'entra-integrations', directoryId: '11111111-2222-4333-8444-555555555555', clientId: '11111111-2222-4333-8444-555555555555', clientSecretEnv: 'X' };
        return parseScannerConfig({ ...c, sources: [...(c.sources as unknown[]), integrations] });
    };

    it('lines: grouped by scanner, each group under its heading, host:443, sorted, one per line', () => {
        const entries = hostsFor(both());
        const of = (scanner: string) => hostNames(entries.filter((e) => e.scanner === scanner)).map((h) => `${h}:443`);
        expect(renderHosts(entries, 'lines').split('\n').filter(Boolean)).toEqual(['# agent scanner', ...of('agents'), '# integrations scanner', ...of('integrations')]);
        // A host two scanners reach is listed under each: here, the identity platform and Graph.
        expect(of('integrations')).toEqual(['graph.microsoft.com:443', 'login.microsoftonline.com:443']);
        expect(of('agents')).toEqual(expect.arrayContaining(of('integrations')));
        // Every host, once the headings are set aside.
        expect([...new Set(renderHosts(entries, 'lines').split('\n').filter((l) => l !== '' && !l.startsWith('#')))].sort()).toEqual(hostNames(entries).map((h) => `${h}:443`));
        // A scanner that reaches no host has no heading.
        const integrationsOnly = hostsFor(parseScannerConfig({ estate: 'a', scanner: { agentId: 'a', signingKeyEnv: 'K' }, schedule: { everyHours: 1 }, outputs: [{ kind: 'stdout' }], sources: [{ kind: 'entra-integrations', directoryId: '11111111-2222-4333-8444-555555555555', clientId: '11111111-2222-4333-8444-555555555555', clientSecretEnv: 'X' }] }));
        expect(renderHosts(integrationsOnly, 'lines')).toBe('# integrations scanner\ngraph.microsoft.com:443\nlogin.microsoftonline.com:443\n');
    });

    it('json: each entry names its scanner, the agent scanner\'s first; the ingest is the agent scanner\'s', () => {
        const entries = hostsFor(both());
        const scanners = entries.map((e) => e.scanner);
        expect(scanners).toEqual([...scanners].sort((a, b) => (a === b ? 0 : a === 'agents' ? -1 : 1)));
        expect(entries.find((e) => e.source === 'inflect')?.scanner).toBe('agents');
        expect(entries.filter((e) => e.scanner === 'integrations').map((e) => e.source)).toEqual(['entra-integrations', 'entra-integrations']);
    });

    it('the Okta and GitHub readers: the org\'s host and api.github.com, under the integrations scanner', () => {
        const config = parseScannerConfig({
            estate: 'a',
            scanner: { agentId: 'a', signingKeyEnv: 'K' },
            schedule: { everyHours: 1 },
            outputs: [{ kind: 'stdout' }],
            sources: [
                { kind: 'okta-integrations', orgUrl: 'https://acme.okta.com', apiTokenEnv: 'X' },
                { kind: 'github-integrations', organization: 'acme', tokenEnv: 'Y' },
            ],
        });
        const entries = hostsFor(config);
        expect(entries.map((e) => [e.scanner, e.host, e.source, e.purpose, e.named])).toEqual([
            ['integrations', 'acme.okta.com', 'okta-integrations', 'read', 'configured'],
            ['integrations', 'api.github.com', 'github-integrations', 'read', 'fixed'],
        ]);
        expect(renderHosts(entries, 'lines')).toBe('# integrations scanner\nacme.okta.com:443\napi.github.com:443\n');
    });

    it('egress-allow: the value the bundled proxy\'s EGRESS_ALLOW takes', () => {
        const value = renderHosts(hostsFor(full()), 'egress-allow').trim();
        expect([...parseEgressAllowlist(value)].sort()).toEqual(hostNames(hostsFor(full())));
    });

    it('json: the entries', () => {
        expect(JSON.parse(renderHosts(hostsFor(full()), 'json'))).toEqual(hostsFor(full()));
    });

    it('a configuration that reaches no host prints nothing in lines and egress-allow', () => {
        expect(renderHosts([], 'lines')).toBe('');
        expect(renderHosts([], 'egress-allow')).toBe('');
    });
});

describe('the command', () => {
    let out: string[];
    let err: string[];
    let configFile: string;
    beforeEach(() => {
        out = [];
        err = [];
        jest.spyOn(process.stdout, 'write').mockImplementation((chunk) => (out.push(String(chunk)), true));
        jest.spyOn(process.stderr, 'write').mockImplementation((chunk) => (err.push(String(chunk)), true));
        configFile = join(dir, 'config.json');
        writeFileSync(configFile, JSON.stringify(fullEstateConfig('/out')));
    });

    it('prints the hosts without a credential, a key or a request', async () => {
        const fetched = jest.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('offline'));
        expect(await main(['hosts', '--config', configFile], {})).toBe(0);
        expect(out.join('')).toBe(renderHosts(hostsFor(full()), 'lines'));
        expect(fetched).not.toHaveBeenCalled();
        out.length = 0;
        expect(await main(['hosts', '--config', configFile, '--format=egress-allow'], {})).toBe(0);
        expect(out.join('')).toBe(renderHosts(hostsFor(full()), 'egress-allow'));
    });

    it('refuses a format it does not have, and an unknown flag', async () => {
        expect(await main(['hosts', '--config', configFile, '--format', 'yaml'], {})).toBe(2);
        expect(await main(['hosts', '--config', configFile, '--format'], {})).toBe(2);
        expect(await main(['hosts', '--config', configFile, '--dry-run'], {})).toBe(2);
        expect(out).toEqual([]);
    });
});
