/**
 * The deployment templates, held to the scanner they deploy.
 *
 * What a text or YAML read can hold on every `npm test`: every example
 * configuration is what the wizard writes and what `scan` accepts; no template
 * holds anything shaped like a secret; the Compose files and the chart run the
 * container non-root, read-only, with nothing added; the bundle scripts build,
 * verify and load a bundle.
 *
 * The chart is also asserted on AS RENDERED, by `helm template`, when `helm`
 * is on the path. Without it those cases are skipped BY NAME, never passed,
 * and with REQUIRE_HELM=1 (CI's `chart` job) its absence fails the suite.
 */
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { looksLikeSecret } from '@rodnapamet/scanent-contract/harness-contract-rules';
import * as yaml from 'js-yaml';

import { credentialEnvNames, parseScannerConfig } from '../src/config';
import { PROXY_CHECKS_ADDRESSES_ENV } from '../src/customer-host';
import { parseEgressAllowlist, parseEgressPrivateCidrs } from '../src/egress-proxy';
import { hostsFor } from '../src/hosts';
import { parseInitAnswers } from '../src/init/answers';
import { planInit, renderEnvTemplate } from '../src/init/plan';
import { SCANNER_VERSION } from '../src/scanner-surface';

jest.setTimeout(120_000);

const REPO_ROOT = path.resolve(__dirname, '../../..');
const abs = (rel: string): string => path.join(REPO_ROOT, rel);
const read = (rel: string): string => fs.readFileSync(abs(rel), 'utf8');
const CHART = 'deploy/helm/scanent';
const IMAGE_REPOSITORY = 'ghcr.io/rodnapamet/scanent';

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

/** Every file under a directory of the repository, as repository-relative paths, sorted. */
function filesUnder(rel: string): string[] {
    const out: string[] = [];
    const walk = (dir: string) => {
        for (const entry of fs.readdirSync(abs(dir), { withFileTypes: true })) {
            const child = `${dir}/${entry.name}`;
            if (entry.isDirectory()) walk(child);
            else out.push(child);
        }
    };
    walk(rel);
    return out.sort();
}

/** Every string in a parsed document, with the path it sits at. */
function stringsOf(node: unknown, at = ''): Array<{ at: string; value: string }> {
    if (typeof node === 'string') return [{ at, value: node }];
    if (Array.isArray(node)) return node.flatMap((v, i) => stringsOf(v, `${at}[${i}]`));
    if (node !== null && typeof node === 'object') {
        return Object.entries(node).flatMap(([k, v]) => [{ at: `${at}.${k}#key`, value: k }, ...stringsOf(v, `${at}.${k}`)]);
    }
    return [];
}

/** The NAMES an env template gives a value to (`NAME=` or `NAME_FILE=`), without the `_FILE`. */
function envTemplateNames(text: string): string[] {
    return text
        .split('\n')
        .filter((line) => line !== '' && !line.startsWith('#'))
        .map((line) => line.slice(0, line.indexOf('=')).replace(/_FILE$/, ''));
}

// ───────────────────────────── examples ─────────────────────────────

describe('deploy/examples', () => {
    const dir = 'deploy/examples';
    const names = fs
        .readdirSync(abs(dir))
        .filter((f) => f.endsWith('.answers.json'))
        .map((f) => f.slice(0, -'.answers.json'.length))
        .sort();

    it('holds the four shapes, each as an answers file, a configuration and an env template, and nothing else', () => {
        expect(names).toEqual(['ci-and-cloud', 'cloud-identities', 'code-only', 'everything']);
        expect(fs.readdirSync(abs(dir)).sort()).toEqual(
            ['README.md', ...names.flatMap((n) => [`${n}.answers.json`, `${n}.env`, `${n}.json`])].sort(),
        );
    });

    it.each(names)('%s: the configuration and the env template are what init writes for the answers', (name) => {
        const plan = planInit(parseInitAnswers(JSON.parse(read(`${dir}/${name}.answers.json`))));
        expect(read(`${dir}/${name}.json`)).toBe(plan.configText);
        // The signing key's path as every documented mount gives it.
        expect(read(`${dir}/${name}.env`)).toBe(renderEnvTemplate(plan.credentialNames, '/etc/scanent/signing-key.pem'));
    });

    it.each(names)('%s: the configuration parses under the strict schema, and the env template names exactly its credentials', (name) => {
        const config = parseScannerConfig(JSON.parse(read(`${dir}/${name}.json`)));
        expect(config.sources.length).toBeGreaterThan(0);
        expect(envTemplateNames(read(`${dir}/${name}.env`)).sort()).toEqual([...credentialEnvNames(config)].sort());
    });

    it.each(names)('%s: every line of the env template is a comment, blank, or a NAME with nothing or a path after it', (name) => {
        const lines = read(`${dir}/${name}.env`).split('\n');
        for (const line of lines) expect(line).toMatch(/^(#.*|[A-Z][A-Z0-9_]*=(\/[^\s]*)?)?$/);
        // The one value in any template is the signing key's path.
        expect(lines.filter((line) => /=./.test(line) && !line.startsWith('#'))).toEqual(['SCANNER_SIGNING_KEY_FILE=/etc/scanent/signing-key.pem']);
    });

    it('covers every source a person can choose in the everything example, and no tenant in any', () => {
        const kinds = (name: string) => parseScannerConfig(JSON.parse(read(`${dir}/${name}.json`))).sources.map((s) => s.kind);
        expect(kinds('everything').sort()).toEqual(['cicd', 'code', 'entra-sp', 'gcp-sa', 'mcp', 'okta-app', 'runtime', 'vault']);
        expect(kinds('code-only')).toEqual(['code']);
        for (const name of names) {
            const config = parseScannerConfig(JSON.parse(read(`${dir}/${name}.json`)));
            expect(config.inflect).toBeUndefined();
            expect(config.outputs).toEqual([expect.objectContaining({ kind: 'file', dir: '/out' })]);
        }
    });
});

describe('examples/', () => {
    it('holds configuration templates that parse once the checkout path is filled in', () => {
        const templates = filesUnder('examples').filter((f) => /config\.[a-z.]*template\.json$/.test(f));
        expect(templates).toEqual(['examples/code-only/config.local.template.json', 'examples/code-only/config.template.json']);
        for (const file of templates) {
            const config = parseScannerConfig(JSON.parse(read(file).replaceAll('__REPO__', REPO_ROOT)));
            expect(config.sources.map((s) => s.kind)).toEqual(['code']);
        }
    });
});

describe('no deployment file holds anything shaped like a secret', () => {
    const files = [...filesUnder('deploy'), ...filesUnder('examples'), ...filesUnder('.github'), 'docs/quick-start.md', 'docs/deployment.md'];

    it('reads a real population of files', () => {
        expect(files.length).toBeGreaterThan(30);
        expect(files).toEqual(expect.arrayContaining(['deploy/compose.yaml', `${CHART}/values.yaml`, 'deploy/airgap/load.sh', 'deploy/examples/everything.env']));
    });

    it('in any line or word of any text file', () => {
        const hits: string[] = [];
        for (const file of files) {
            read(file)
                .split('\n')
                .forEach((line, i) => {
                    for (const piece of [line.trim(), ...line.split(/[\s"'`=,()[\]{}<>|]+/)]) {
                        if (piece !== '' && looksLikeSecret(piece)) hits.push(`${file}:${i + 1}`);
                    }
                });
        }
        expect(hits).toEqual([]);
    });

    it('in any string of any parsed JSON or YAML document', () => {
        const hits: string[] = [];
        const parsedCount = { n: 0 };
        for (const file of files) {
            if (file.includes('/templates/')) continue; // Go templates are not YAML until rendered; the line scan above reads them.
            let docs: unknown[];
            if (file.endsWith('.json')) docs = [JSON.parse(read(file))];
            else if (/\.ya?ml$/.test(file)) docs = yaml.loadAll(read(file));
            else continue;
            parsedCount.n += 1;
            for (const doc of docs) for (const s of stringsOf(doc)) if (looksLikeSecret(s.value)) hits.push(`${file}${s.at}`);
        }
        expect(parsedCount.n).toBeGreaterThan(15);
        expect(hits).toEqual([]);
    });

    it('and the detector is the one that would catch one', () => {
        expect(looksLikeSecret('-----BEGIN PRIVATE KEY-----')).toBe(true);
    });
});

// ───────────────────────────── Compose ─────────────────────────────

describe('deploy/compose.yaml and its egress overlay', () => {
    const base = yaml.load(read('deploy/compose.yaml')) as Json;
    const overlay = yaml.load(read('deploy/compose.egress.yaml')) as Json;
    /** The services that are stated in full: the scanner, and the overlay's proxy. */
    const full: Array<[string, Json]> = [
        ['scanent', base.services.scanent],
        ['egress-proxy', overlay.services['egress-proxy']],
    ];

    it('defines one service, and the overlay adds exactly the proxy', () => {
        expect(Object.keys(base.services)).toEqual(['scanent']);
        expect(Object.keys(overlay.services).sort()).toEqual(['egress-proxy', 'scanent']);
    });

    it.each(full)('%s runs non-root, read-only, with every capability dropped and no privilege gain', (_name, service) => {
        expect(service.read_only).toBe(true);
        expect(service.cap_drop).toEqual(['ALL']);
        expect(service.security_opt).toEqual(['no-new-privileges:true']);
        // The default user, and the only way to change it: a numeric uid and gid, 1000 unless set.
        expect(service.user).toBe('${SCANENT_UID:-1000}:${SCANENT_GID:-1000}');
        expect(service.pids_limit).toBeGreaterThan(0);
        expect(typeof service.mem_limit).toBe('string');
    });

    it.each(full)('%s is given nothing it does not need', (_name, service) => {
        for (const key of ['privileged', 'cap_add', 'ports', 'network_mode', 'pid', 'ipc', 'devices', 'tmpfs', 'extra_hosts', 'sysctls', 'userns_mode']) {
            expect(service[key]).toBeUndefined();
        }
        for (const volume of (service.volumes ?? []) as string[]) expect(volume).not.toMatch(/docker\.sock|\/var\/run|\/proc|\/sys/);
    });

    it.each(full)('%s names the image by a required version, never latest', (_name, service) => {
        expect(service.image).toBe(`${IMAGE_REPOSITORY}:\${SCANENT_VERSION:?set SCANENT_VERSION to the image version}`);
        expect(JSON.stringify([base, overlay])).not.toMatch(/:latest|SCANENT_VERSION:-/);
    });

    it('mounts the configuration read-only and exactly one writable directory', () => {
        const volumes = base.services.scanent.volumes as string[];
        expect(volumes).toEqual(['${SCANENT_DIR:-./scanent}:/etc/scanent:ro', '${SCANENT_OUT:-./scanent-out}:/out']);
        expect(volumes.filter((v) => !v.endsWith(':ro'))).toEqual(['${SCANENT_OUT:-./scanent-out}:/out']);
    });

    it('gives the signing key as a file secret and no credential as a value', () => {
        const service = base.services.scanent;
        expect(service.secrets).toEqual(['scanner_signing_key']);
        expect(base.secrets).toEqual({ scanner_signing_key: { file: '${SCANENT_DIR:-./scanent}/signing-key.pem' } });
        // The one environment entry is a path, and it is the _FILE form.
        expect(service.environment).toEqual({ SCANNER_SIGNING_KEY_FILE: '/run/secrets/scanner_signing_key' });
        expect(service.env_file).toEqual(['${SCANENT_DIR:-./scanent}/scanent.env']);
    });

    it('runs the image as built: no entrypoint, no command, so the default schedule and no shell', () => {
        expect(base.services.scanent.entrypoint).toBeUndefined();
        expect(base.services.scanent.command).toBeUndefined();
        expect(base.services.scanent.init).toBe(false);
    });

    it('the overlay moves the scanner onto an internal network and behind the bundled proxy, and changes nothing else', () => {
        expect(overlay.services.scanent).toEqual({
            // The second variable is new with the review: the scanner has no resolver on the internal network,
            // so the address check for a host the estate names is the proxy's (`customer-host.ts`).
            environment: { HTTPS_PROXY: 'http://egress-proxy:3128', EGRESS_PROXY_CHECKS_ADDRESSES: '1' },
            networks: ['scanent-internal'],
            depends_on: ['egress-proxy'],
        });
        expect(overlay.networks).toEqual({ 'scanent-internal': { internal: true }, 'scanent-egress': {} });
        const proxy = overlay.services['egress-proxy'];
        expect(proxy.networks).toEqual(['scanent-internal', 'scanent-egress']);
        // Exec form: node and the proxy's file, which the scanner package builds.
        expect(proxy.entrypoint).toEqual(['node', '/app/packages/scanner/dist/egress-proxy.js']);
        expect(fs.existsSync(abs('packages/scanner/src/egress-proxy.ts'))).toBe(true);
        expect(proxy.command).toEqual([]);
        // The allowlist is required, and is the value `scanent hosts --format egress-allow` prints.
        // The private ranges are optional and empty by default: a private address is then refused (also new with the review).
        expect(proxy.environment).toEqual({
            EGRESS_ALLOW: '${EGRESS_ALLOW:?set EGRESS_ALLOW from scanent hosts --format egress-allow}',
            EGRESS_PRIVATE_CIDR_ALLOWLIST: '${EGRESS_PRIVATE_CIDR_ALLOWLIST:-}',
        });
        expect(parseEgressPrivateCidrs('')).toEqual([]);
        expect(proxy.volumes).toBeUndefined();
        expect(proxy.secrets).toBeUndefined();
        expect(proxy.env_file).toBeUndefined();
    });

    it('the variable that hands the address check to a proxy is set only where the proxy is the bundled one', () => {
        // Beside any other proxy it turns the check off, so no other deployment file may carry it.
        expect(PROXY_CHECKS_ADDRESSES_ENV).toBe('EGRESS_PROXY_CHECKS_ADDRESSES');
        expect(base.services.scanent.environment?.EGRESS_PROXY_CHECKS_ADDRESSES).toBeUndefined();
        const carriers = execFileSync('git', ['grep', '-l', 'EGRESS_PROXY_CHECKS_ADDRESSES', '--', 'deploy'], { cwd: REPO_ROOT, encoding: 'utf8' }).trim().split('\n');
        expect(carriers).toEqual(['deploy/compose.egress.yaml']);
        // And the overlay says, where the reader sets EGRESS_ALLOW, that a host of their own belongs in it.
        const text = read('deploy/compose.egress.yaml');
        expect(text).toMatch(/an MCP server, a self-hosted LangSmith\) goes\n# in EGRESS_ALLOW/);
        expect(text).not.toContain('SCANENT_VERSION=<version> docker compose');
    });
});

// ───────────────────────────── the chart, as text ─────────────────────────────

describe('the chart, without rendering it', () => {
    const chart = yaml.load(read(`${CHART}/Chart.yaml`)) as Json;
    const values = yaml.load(read(`${CHART}/values.yaml`)) as Json;
    const schema = JSON.parse(read(`${CHART}/values.schema.json`)) as Json;
    const templates = filesUnder(`${CHART}/templates`);

    it('is versioned with the scanner it installs', () => {
        expect(chart.apiVersion).toBe('v2');
        expect(chart.type).toBe('application');
        expect(chart.appVersion).toBe(SCANNER_VERSION);
        expect(chart.version).toBe(SCANNER_VERSION);
        expect(values.image).toEqual({ repository: IMAGE_REPOSITORY, tag: '', digest: '', pullPolicy: 'IfNotPresent' });
    });

    it('has exactly these templates', () => {
        expect(templates.map((t) => path.basename(t))).toEqual([
            'NOTES.txt',
            '_helpers.tpl',
            'ciliumnetworkpolicy.yaml',
            'configmap.yaml',
            'cronjob.yaml',
            'egress-proxy.yaml',
            'networkpolicy.yaml',
            'pvc.yaml',
            'serviceaccount.yaml',
        ]);
    });

    it('creates no Secret, Role or Ingress, and reads no credential into the environment', () => {
        const kinds = templates.flatMap((t) => [...read(t).matchAll(/^kind: (\S+)$/gm)].map((m) => m[1])).sort();
        expect(kinds).toEqual(['CiliumNetworkPolicy', 'ConfigMap', 'CronJob', 'Deployment', 'NetworkPolicy', 'NetworkPolicy', 'PersistentVolumeClaim', 'Service', 'ServiceAccount']);
        for (const t of templates.filter((t) => !t.endsWith('NOTES.txt'))) {
            expect(read(t)).not.toMatch(/secretKeyRef|valueFrom|envFrom|stringData|hostNetwork|hostPID|hostPath|privileged: true/);
        }
    });

    it('starts the scanner with arguments only: the CronJob template has no command', () => {
        const cronjob = read(`${CHART}/templates/cronjob.yaml`);
        expect(cronjob).not.toMatch(/^\s*command:/m);
        expect(cronjob).toMatch(/^\s+automountServiceAccountToken: false$/m);
        // The proxy, the one container that needs a command, names node and a file: exec form, no shell.
        expect(read(`${CHART}/templates/egress-proxy.yaml`)).toMatch(/command:\n\s+- node\n\s+- \/app\/packages\/scanner\/dist\/egress-proxy\.js\n/);
        for (const t of templates) expect(read(t)).not.toMatch(/\b(sh|bash) -c\b|\/bin\/sh/);
    });

    it('refuses any value it does not know: every object in the schema is closed', () => {
        expect(schema.$schema).toBe('http://json-schema.org/draft-07/schema#');
        const open: string[] = [];
        let objects = 0;
        const walk = (node: Json, at: string) => {
            const isObject = node.type === 'object' || node.properties !== undefined;
            if (isObject) {
                objects += 1;
                const extra = node.additionalProperties;
                // Closed, or a map whose values are scalars (labels, annotations, resource quantities).
                const scalarMap = extra !== null && typeof extra === 'object' && [extra.type].flat().every((t: string) => ['string', 'number'].includes(t));
                if (extra !== false && !scalarMap) open.push(at);
            }
            for (const [k, v] of Object.entries(node.properties ?? {})) walk(v as Json, `${at}.${k}`);
            if (node.items !== undefined) walk(node.items as Json, `${at}[]`);
        };
        walk(schema, '');
        expect(objects).toBeGreaterThan(15);
        // The one open object is the scanner's own configuration, which the scanner's strict schema parses.
        expect(open).toEqual(['.config']);
    });

    it('documents exactly the values the schema knows', () => {
        expect(Object.keys(values).sort()).toEqual(Object.keys(schema.properties).sort());
        for (const [key, node] of Object.entries(schema.properties as Record<string, Json>)) {
            if (node.properties === undefined || key === 'config') continue;
            expect(Object.keys(values[key]).sort()).toEqual(Object.keys(node.properties).sort());
        }
    });

    it('has no value that can hold a credential', () => {
        // Keys whose name suggests a credential, and the only ones allowed: each names a Secret, a key in one, or a file.
        const suspicious = stringsOf(values)
            .filter((s) => !s.at.endsWith('#key'))
            .filter((s) => /password|passwd|token|secret|key|credential|auth/i.test(s.at.split('.').pop() ?? ''))
            .map((s) => s.at);
        expect(suspicious).toEqual(['.secrets.existingSecret', '.secrets.files[0].key', '.extraCa.key']);
        expect(values.secrets).toEqual({ existingSecret: '', files: [{ env: 'SCANNER_SIGNING_KEY', key: 'signing-key.pem' }] });
        // A proxy URL may not carry a user name or password.
        const proxy = new RegExp(schema.properties.proxy.properties.httpsProxy.pattern as string);
        expect(proxy.test('http://proxy.internal.example:3128')).toBe(true);
        expect(proxy.test('')).toBe(true);
        expect(proxy.test('http://user:pass@proxy.internal.example:3128')).toBe(false);
        // `latest` is not a version.
        expect(schema.properties.image.properties.tag.not).toEqual({ const: 'latest' });
    });

    it('lists, in its README, the hosts the everything example reaches', () => {
        const config = parseScannerConfig(JSON.parse(read('deploy/examples/everything.json')));
        const bySource = new Map<string, string[]>();
        for (const e of hostsFor(config)) bySource.set(e.source, [...(bySource.get(e.source) ?? []), e.host]);
        const expected = [
            '| Source | Hosts |',
            '|---|---|',
            ...config.sources.map((s) => `| \`${s.kind}\` | ${(bySource.get(s.kind) ?? []).map((h) => `\`${h}\``).join(', ') || 'none'} |`),
        ];
        const readme = read(`${CHART}/README.md`);
        const block = readme.slice(readme.indexOf('<!-- hosts:begin -->') + '<!-- hosts:begin -->'.length, readme.indexOf('<!-- hosts:end -->'));
        expect(block.trim().split('\n')).toEqual(expected);
        expect(expected.length).toBe(2 + 8);
    });

    it('says, in the README and the notes, what a NetworkPolicy does not give', () => {
        for (const file of [`${CHART}/README.md`, `${CHART}/templates/NOTES.txt`, 'docs/deployment.md']) {
            expect(read(file).replace(/\s+/g, ' ')).toMatch(/matches addresses(,| and ports,)? not names/);
        }
    });
});

// ───────────────────────────── the chart, rendered ─────────────────────────────

function helmVersion(): string | null {
    const found = spawnSync('helm', ['version', '--short'], { encoding: 'utf8' });
    return found.status === 0 ? found.stdout.trim() : null;
}
const HELM = helmVersion();
const REQUIRE_HELM = process.env.REQUIRE_HELM === '1';
/** Rendered cases run with helm, and are skipped by name without it. */
const rendered = HELM === null ? it.skip : it;

interface Render {
    readonly ok: boolean;
    readonly docs: Json[];
    readonly stderr: string;
}

function helmTemplate(valueSets: readonly string[], sets: readonly string[] = [], base = true): Render {
    const args = ['template', 'scanent', abs(CHART), '--namespace', 'scanent'];
    if (base) args.push('-f', abs(`${CHART}/ci/base-values.yaml`));
    for (const v of valueSets) args.push('-f', abs(`${CHART}/ci/${v}-values.yaml`));
    for (const s of sets) args.push('--set', s);
    const out = spawnSync('helm', args, { encoding: 'utf8' });
    if (out.status !== 0) return { ok: false, docs: [], stderr: out.stderr };
    return { ok: true, docs: (yaml.loadAll(out.stdout) as Array<Json | null>).filter((d): d is Json => d !== null), stderr: out.stderr };
}

const kindsOf = (r: Render): string[] => r.docs.map((d) => d.kind as string).sort();
const one = (r: Render, kind: string, name?: string): Json => {
    const found = r.docs.filter((d) => d.kind === kind && (name === undefined || d.metadata.name === name));
    if (found.length !== 1) throw new Error(`expected one ${kind}${name ? ` named ${name}` : ''}, found ${found.length}`);
    return found[0];
};
const scannerPod = (r: Render): Json => one(r, 'CronJob').spec.jobTemplate.spec.template.spec;

const POD_SECURITY = { runAsNonRoot: true, runAsUser: 1000, runAsGroup: 1000, fsGroup: 1000, seccompProfile: { type: 'RuntimeDefault' } };
const CONTAINER_SECURITY = { readOnlyRootFilesystem: true, allowPrivilegeEscalation: false, privileged: false, capabilities: { drop: ['ALL'] } };
const SCANNER_LABELS = { 'app.kubernetes.io/name': 'scanent', 'app.kubernetes.io/instance': 'scanent', 'app.kubernetes.io/component': 'scanner' };
const PROXY_LABELS = { ...SCANNER_LABELS, 'app.kubernetes.io/component': 'egress-proxy' };
const DNS_RULE = {
    to: [{ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'kube-system' } }, podSelector: { matchLabels: { 'k8s-app': 'kube-dns' } } }],
    ports: [
        { protocol: 'UDP', port: 53 },
        { protocol: 'TCP', port: 53 },
    ],
};
const PUBLIC_443_RULE = {
    to: [
        { ipBlock: { cidr: '0.0.0.0/0', except: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '169.254.0.0/16'] } },
        { ipBlock: { cidr: '::/0', except: ['fc00::/7', 'fe80::/10'] } },
    ],
    ports: [{ protocol: 'TCP', port: 443 }],
};

describe('the chart, rendered by helm template', () => {
    it('has helm when REQUIRE_HELM=1 says it must', () => {
        if (REQUIRE_HELM) expect(HELM).not.toBeNull();
        // Without helm the cases below are reported as skipped; none of them passes unrun.
        expect(rendered === it).toBe(HELM !== null);
    });

    describe('the default install', () => {
        const r = HELM === null ? { ok: false, docs: [], stderr: '' } : helmTemplate([]);

        rendered('renders exactly a CronJob, its ConfigMap, a claim, a service account and a NetworkPolicy', () => {
            expect(r.ok).toBe(true);
            expect(kindsOf(r)).toEqual(['ConfigMap', 'CronJob', 'NetworkPolicy', 'PersistentVolumeClaim', 'ServiceAccount']);
        });

        rendered('runs the pod non-root with no service account token, and the container read-only with nothing added', () => {
            const pod = scannerPod(r);
            expect(pod.securityContext).toEqual(POD_SECURITY);
            expect(pod.automountServiceAccountToken).toBe(false);
            expect(pod.restartPolicy).toBe('Never');
            expect(pod.hostNetwork).toBeUndefined();
            expect(pod.containers).toHaveLength(1);
            expect(pod.initContainers).toBeUndefined();
            expect(pod.containers[0].securityContext).toEqual(CONTAINER_SECURITY);
            expect(one(r, 'ServiceAccount').automountServiceAccountToken).toBe(false);
        });

        rendered('starts the image as built: no command, the scan arguments, the chart version of the image', () => {
            const container = scannerPod(r).containers[0];
            expect(container.command).toBeUndefined();
            expect(container.args).toEqual(['scan', '--config', '/etc/scanent/config.json', '--out', '/out']);
            expect(container.image).toBe(`${IMAGE_REPOSITORY}:${SCANNER_VERSION}`);
        });

        rendered('gives each credential as a file path, and no environment entry holds or references a value', () => {
            const container = scannerPod(r).containers[0];
            expect(container.env).toEqual([{ name: 'SCANNER_SIGNING_KEY_FILE', value: '/run/secrets/scanent/signing-key.pem' }]);
            expect(container.envFrom).toBeUndefined();
            const credentials = scannerPod(r).volumes.find((v: Json) => v.name === 'credentials');
            expect(credentials.secret).toEqual({ secretName: 'scanent-credentials', defaultMode: 0o440, items: [{ key: 'signing-key.pem', path: 'signing-key.pem' }] });
            expect(container.volumeMounts.find((m: Json) => m.name === 'credentials')).toEqual({ name: 'credentials', mountPath: '/run/secrets/scanent', readOnly: true });
        });

        rendered('mounts the configuration and the code read-only, and one writable volume', () => {
            const mounts = scannerPod(r).containers[0].volumeMounts as Json[];
            expect(mounts.filter((m) => m.readOnly !== true)).toEqual([{ name: 'out', mountPath: '/out' }]);
            expect(mounts.map((m) => m.mountPath).sort()).toEqual(['/estate', '/etc/scanent', '/out', '/run/secrets/scanent']);
            expect(scannerPod(r).volumes.find((v: Json) => v.name === 'out')).toEqual({ name: 'out', persistentVolumeClaim: { claimName: 'scanent-out' } });
        });

        rendered('renders a configuration the scanner accepts, and names it in the pod by its checksum', () => {
            const data = one(r, 'ConfigMap').data['config.json'] as string;
            const config = parseScannerConfig(JSON.parse(data));
            expect(config.estate).toBe('acme-code');
            expect(config.sources.map((s) => s.kind)).toEqual(['code']);
            // Every credential the configuration names is one the chart mounts.
            const mounted = (scannerPod(r).containers[0].env as Json[]).map((e) => (e.name as string).replace(/_FILE$/, ''));
            expect(credentialEnvNames(config).sort()).toEqual(mounted.sort());
            expect(one(r, 'CronJob').spec.jobTemplate.spec.template.metadata.annotations['checksum/config']).toMatch(/^[0-9a-f]{64}$/);
        });

        rendered('never retries, never overlaps, and keeps the claim when the release is removed', () => {
            const spec = one(r, 'CronJob').spec;
            expect(spec.concurrencyPolicy).toBe('Forbid');
            expect(spec.schedule).toBe('17 2 * * *');
            expect(spec.jobTemplate.spec.backoffLimit).toBe(0);
            expect(spec.jobTemplate.spec.activeDeadlineSeconds).toBe(1800);
            expect(spec.jobTemplate.spec.ttlSecondsAfterFinished).toBe(86400);
            const pvc = one(r, 'PersistentVolumeClaim');
            expect(pvc.metadata.annotations['helm.sh/resource-policy']).toBe('keep');
            expect(pvc.spec.accessModes).toEqual(['ReadWriteOnce']);
        });

        rendered('allows nothing in, and out only DNS and TCP 443 to public addresses', () => {
            const policy = one(r, 'NetworkPolicy').spec;
            expect(policy.podSelector).toEqual({ matchLabels: SCANNER_LABELS });
            expect(policy.policyTypes).toEqual(['Ingress', 'Egress']);
            expect(policy.ingress).toBeUndefined();
            expect(policy.egress).toEqual([DNS_RULE, PUBLIC_443_RULE]);
            // The policy selects the pod the CronJob makes.
            expect(one(r, 'CronJob').spec.jobTemplate.spec.template.metadata.labels).toEqual(SCANNER_LABELS);
        });
    });

    rendered('cilium: a CiliumNetworkPolicy for exactly egress.fqdns, and no NetworkPolicy', () => {
        const r = helmTemplate(['cilium']);
        expect(r.ok).toBe(true);
        expect(kindsOf(r)).toEqual(['CiliumNetworkPolicy', 'ConfigMap', 'CronJob', 'PersistentVolumeClaim', 'ServiceAccount']);
        const fqdns = ['api.github.com', 'iam.googleapis.com', 'oauth2.googleapis.com'];
        const spec = one(r, 'CiliumNetworkPolicy').spec;
        expect(spec.endpointSelector).toEqual({ matchLabels: SCANNER_LABELS });
        expect(spec.ingress).toEqual([{}]);
        expect(spec.egress).toEqual([
            {
                toEndpoints: [{ matchLabels: { 'k8s:io.kubernetes.pod.namespace': 'kube-system', 'k8s-app': 'kube-dns' } }],
                toPorts: [{ ports: [{ port: '53', protocol: 'ANY' }], rules: { dns: fqdns.map((matchName) => ({ matchName })) } }],
            },
            { toFQDNs: fqdns.map((matchName) => ({ matchName })), toPorts: [{ ports: [{ port: '443', protocol: 'TCP' }] }] },
            { toCIDR: ['10.20.0.0/16'], toPorts: [{ ports: [{ port: '443', protocol: 'TCP' }] }] },
        ]);
        // Three credentials, each a file.
        expect(scannerPod(r).containers[0].env).toEqual([
            { name: 'SCANNER_SIGNING_KEY_FILE', value: '/run/secrets/scanent/signing-key.pem' },
            { name: 'GITHUB_READ_TOKEN_FILE', value: '/run/secrets/scanent/github-read-token' },
            { name: 'GCP_SCANNER_KEY_FILE', value: '/run/secrets/scanent/gcp-key.json' },
        ]);
    });

    rendered('egress proxy: the scanner reaches DNS and the proxy only, and the proxy is the same hardened image', () => {
        const r = helmTemplate(['egress-proxy']);
        expect(r.ok).toBe(true);
        expect(kindsOf(r)).toEqual(['ConfigMap', 'CronJob', 'Deployment', 'NetworkPolicy', 'NetworkPolicy', 'PersistentVolumeClaim', 'Service', 'ServiceAccount']);

        const scanner = one(r, 'NetworkPolicy', 'scanent').spec;
        expect(scanner.egress).toEqual([DNS_RULE, { to: [{ podSelector: { matchLabels: PROXY_LABELS } }], ports: [{ protocol: 'TCP', port: 3128 }] }]);
        expect(JSON.stringify(scanner)).not.toContain('ipBlock');
        expect(scannerPod(r).containers[0].env).toContainEqual({ name: 'HTTPS_PROXY', value: 'http://scanent-egress-proxy:3128' });

        const proxyPolicy = one(r, 'NetworkPolicy', 'scanent-egress-proxy').spec;
        expect(proxyPolicy.podSelector).toEqual({ matchLabels: PROXY_LABELS });
        expect(proxyPolicy.ingress).toEqual([{ from: [{ podSelector: { matchLabels: SCANNER_LABELS } }], ports: [{ protocol: 'TCP', port: 3128 }] }]);
        expect(proxyPolicy.egress).toEqual([DNS_RULE, PUBLIC_443_RULE]);

        const deployment = one(r, 'Deployment').spec;
        expect(deployment.template.metadata.labels).toEqual(PROXY_LABELS);
        const pod = deployment.template.spec;
        expect(pod.securityContext).toEqual(POD_SECURITY);
        expect(pod.automountServiceAccountToken).toBe(false);
        const container = pod.containers[0];
        expect(container.securityContext).toEqual(CONTAINER_SECURITY);
        expect(container.image).toBe(scannerPod(r).containers[0].image);
        expect(container.command).toEqual(['node', '/app/packages/scanner/dist/egress-proxy.js']);
        expect(container.volumeMounts).toBeUndefined();
        // The allowlist is the value the proxy itself parses, and is exactly egress.fqdns.
        expect(container.env).toEqual([{ name: 'EGRESS_ALLOW', value: 'api.github.com,iam.googleapis.com,oauth2.googleapis.com' }]);
        expect([...parseEgressAllowlist(container.env[0].value)].sort()).toEqual(['api.github.com', 'iam.googleapis.com', 'oauth2.googleapis.com']);
        expect(one(r, 'Service').spec.selector).toEqual(PROXY_LABELS);
    });

    rendered('egress proxy: private ranges reach the proxy as its own allowlist and as a rule of its policy, and nowhere else', () => {
        const r = helmTemplate(['egress-proxy'], ['egressProxy.privateCidrs={10.20.0.0/16,fd00:20::/64}']);
        expect(r.ok).toBe(true);
        const env = one(r, 'Deployment').spec.template.spec.containers[0].env as Json[];
        expect(env).toContainEqual({ name: 'EGRESS_PRIVATE_CIDR_ALLOWLIST', value: '10.20.0.0/16,fd00:20::/64' });
        // The value is one the proxy itself accepts.
        expect(parseEgressPrivateCidrs('10.20.0.0/16,fd00:20::/64')).toHaveLength(2);
        expect(one(r, 'NetworkPolicy', 'scanent-egress-proxy').spec.egress).toEqual([
            DNS_RULE,
            PUBLIC_443_RULE,
            { to: [{ ipBlock: { cidr: '10.20.0.0/16' } }], ports: [{ protocol: 'TCP', port: 443 }] },
            { to: [{ ipBlock: { cidr: 'fd00:20::/64' } }], ports: [{ protocol: 'TCP', port: 443 }] },
        ]);
        // The scanner's own policy is unchanged: it still reaches DNS and the proxy only.
        expect(JSON.stringify(one(r, 'NetworkPolicy', 'scanent').spec)).not.toContain('10.20.0.0');
        // Without the bundled proxy the ranges would do nothing, so they are refused.
        const alone = helmTemplate([], ['egressProxy.privateCidrs={10.20.0.0/16}']);
        expect(alone.ok).toBe(false);
        expect(alone.stderr).toMatch(/egressProxy.privateCidrs/);
        expect(helmTemplate(['egress-proxy'], ['egressProxy.privateCidrs={internal.example}']).ok).toBe(false);
    });

    rendered('DNS that is not the kube-dns pods on 53: the port and node addresses are values, in both flavors', () => {
        // OpenShift: other pods, port 5353.
        const openshift = helmTemplate([], [
            'networkPolicy.dns.namespace=openshift-dns',
            'networkPolicy.dns.port=5353',
            'networkPolicy.dns.podLabels.k8s-app=null',
            'networkPolicy.dns.podLabels.dns\\.operator\\.openshift\\.io/daemonset-dns=default',
        ]);
        expect(openshift.stderr).toBe('');
        expect(one(openshift, 'NetworkPolicy').spec.egress[0]).toEqual({
            to: [
                {
                    namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'openshift-dns' } },
                    podSelector: { matchLabels: { 'dns.operator.openshift.io/daemonset-dns': 'default' } },
                },
            ],
            ports: [
                { protocol: 'UDP', port: 5353 },
                { protocol: 'TCP', port: 5353 },
            ],
        });
        // NodeLocal DNSCache: a node address, which is inside the link-local range the 443 rule excludes.
        const nodeLocal = helmTemplate([], ['networkPolicy.dns.cidrs={169.254.20.10/32}']);
        expect(nodeLocal.ok).toBe(true);
        expect(one(nodeLocal, 'NetworkPolicy').spec.egress[0]).toEqual({ to: [...DNS_RULE.to, { ipBlock: { cidr: '169.254.20.10/32' } }], ports: DNS_RULE.ports });
        expect(one(nodeLocal, 'NetworkPolicy').spec.egress[1]).toEqual(PUBLIC_443_RULE);
        // The egress proxy's own policy takes the same rule.
        const proxied = helmTemplate(['egress-proxy'], ['networkPolicy.dns.cidrs={169.254.20.10/32}', 'networkPolicy.dns.port=5353']);
        for (const name of ['scanent', 'scanent-egress-proxy']) {
            expect(one(proxied, 'NetworkPolicy', name).spec.egress[0]).toEqual({
                to: [...DNS_RULE.to, { ipBlock: { cidr: '169.254.20.10/32' } }],
                ports: [
                    { protocol: 'UDP', port: 5353 },
                    { protocol: 'TCP', port: 5353 },
                ],
            });
        }
        // Cilium: the port moves, and the node address gets the same DNS rule for the same names.
        const cilium = helmTemplate(['cilium'], ['networkPolicy.dns.cidrs={169.254.20.10/32}', 'networkPolicy.dns.port=5353']);
        const egress = one(cilium, 'CiliumNetworkPolicy').spec.egress as Json[];
        expect(egress[0].toPorts[0].ports).toEqual([{ port: '5353', protocol: 'ANY' }]);
        expect(egress[1].toCIDR).toEqual(['169.254.20.10/32']);
        expect(egress[1].toPorts).toEqual(egress[0].toPorts);
        expect(egress[2].toFQDNs).toBeDefined();
        // The defaults are what they were.
        expect(one(helmTemplate([]), 'NetworkPolicy').spec.egress[0]).toEqual(DNS_RULE);
        const plain = one(helmTemplate(['cilium']), 'CiliumNetworkPolicy').spec.egress as Json[];
        expect(plain[0].toPorts[0].ports).toEqual([{ port: '53', protocol: 'ANY' }]);
        expect(plain.filter((e) => e.toCIDR !== undefined && e.toPorts[0].rules !== undefined)).toEqual([]);
        // And a value the schema does not know is still refused.
        expect(helmTemplate([], ['networkPolicy.dns.port=0']).ok).toBe(false);
        expect(helmTemplate([], ['networkPolicy.dns.cidrs={kube-dns}']).ok).toBe(false);
    });

    rendered('a long release name: every object name fits its limit, and the proxy Service is a DNS label', () => {
        // 53 is the longest release name helm itself takes.
        for (const length of [40, 52, 53]) {
            const release = 'a'.repeat(length);
            const args = ['template', release, abs(CHART), '--namespace', 'scanent', '-f', abs(`${CHART}/ci/base-values.yaml`), '-f', abs(`${CHART}/ci/egress-proxy-values.yaml`)];
            const out = spawnSync('helm', args, { encoding: 'utf8' });
            expect(out.status).toBe(0);
            const docs = (yaml.loadAll(out.stdout) as Array<Json | null>).filter((d): d is Json => d !== null);
            expect(docs.length).toBeGreaterThan(5);
            for (const d of docs) {
                const name = d.metadata.name as string;
                // A CronJob's name leaves room for the suffix its Jobs and pods take.
                expect([d.kind, name.length <= (d.kind === 'CronJob' ? 52 : 63)]).toEqual([d.kind, true]);
                expect(name).toMatch(/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/);
            }
            const service = docs.find((d) => d.kind === 'Service') as Json;
            const pod = (docs.find((d) => d.kind === 'CronJob') as Json).spec.jobTemplate.spec.template.spec;
            // The scanner is pointed at the Service by the same name.
            expect(pod.containers[0].env).toContainEqual({ name: 'HTTPS_PROXY', value: `http://${service.metadata.name}:3128` });
        }
        // A release name that fits is not shortened.
        expect(one(helmTemplate(['egress-proxy']), 'Service').metadata.name).toBe('scanent-egress-proxy');
    });

    rendered('a forward proxy and a private CA: the 443 rule becomes the proxy, the CA is a mounted file, --strict is passed', () => {
        const r = helmTemplate(['proxy-and-ca']);
        expect(r.ok).toBe(true);
        const policy = one(r, 'NetworkPolicy').spec;
        expect(policy.egress).toEqual([
            DNS_RULE,
            { to: [{ ipBlock: { cidr: '10.0.0.15/32' } }], ports: [{ protocol: 'TCP', port: 3128 }] },
            { to: [{ ipBlock: { cidr: '10.20.0.0/16' } }], ports: [{ protocol: 'TCP', port: 443 }] },
        ]);
        expect(JSON.stringify(policy)).not.toContain('0.0.0.0/0');
        const container = scannerPod(r).containers[0];
        expect(container.env).toEqual([
            { name: 'SCANNER_SIGNING_KEY_FILE', value: '/run/secrets/scanent/signing-key.pem' },
            { name: 'HTTPS_PROXY', value: 'http://proxy.internal.example:3128' },
            { name: 'NO_PROXY', value: 'mcp.internal.example' },
            { name: 'NODE_EXTRA_CA_CERTS', value: '/etc/scanent-ca/ca.pem' },
        ]);
        expect(JSON.stringify(container.env)).not.toContain('NODE_TLS_REJECT_UNAUTHORIZED');
        expect(container.volumeMounts).toContainEqual({ name: 'extra-ca', mountPath: '/etc/scanent-ca', readOnly: true });
        expect(container.args).toEqual(['scan', '--config', '/etc/scanent/config.json', '--out', '/out', '--strict']);
        expect(container.image).toBe(`${IMAGE_REPOSITORY}@sha256:${'0'.repeat(64)}`);
        expect(one(r, 'CronJob').spec.timeZone).toBe('Europe/Sofia');
    });

    rendered('no value set renders a Secret, a secretKeyRef, a command on the scanner or a privileged container', () => {
        for (const set of [[], ['cilium'], ['egress-proxy'], ['proxy-and-ca']]) {
            const r = helmTemplate(set);
            expect(r.ok).toBe(true);
            expect(kindsOf(r)).not.toEqual(expect.arrayContaining(['Secret']));
            const text = JSON.stringify(r.docs);
            expect(text).not.toMatch(/secretKeyRef|valueFrom|envFrom|hostPath|hostNetwork/);
            expect(scannerPod(r).containers[0].command).toBeUndefined();
            expect(scannerPod(r).containers[0].securityContext).toEqual(CONTAINER_SECURITY);
        }
    });

    rendered('flavor none renders no policy of either kind', () => {
        const r = helmTemplate([], ['networkPolicy.flavor=none']);
        expect(r.ok).toBe(true);
        expect(kindsOf(r)).toEqual(['ConfigMap', 'CronJob', 'PersistentVolumeClaim', 'ServiceAccount']);
    });

    rendered('an existing ConfigMap and an existing claim are used, and none is created', () => {
        const r = helmTemplate([], ['existingConfigMap=my-config', 'output.type=existingClaim', 'output.existingClaim=my-claim', 'secrets.existingSecret=creds'], false);
        expect(r.ok).toBe(true);
        expect(kindsOf(r)).toEqual(['CronJob', 'NetworkPolicy', 'ServiceAccount']);
        const volumes = scannerPod(r).volumes as Json[];
        expect(volumes.find((v) => v.name === 'config')).toEqual({ name: 'config', configMap: { name: 'my-config' } });
        expect(volumes.find((v) => v.name === 'out')).toEqual({ name: 'out', persistentVolumeClaim: { claimName: 'my-claim' } });
    });

    const refusals: Array<[string, string[], boolean, RegExp]> = [
        ['no configuration at all', ['secrets.existingSecret=creds'], false, /set `config` \(the scanner configuration\) or `existingConfigMap`/],
        ['both a configuration and an existing ConfigMap', ['existingConfigMap=my-config'], true, /not both/],
        ['credentials listed with no Secret to read them from', ['secrets.existingSecret='], true, /`secrets\.existingSecret` is empty/],
        ['emptyDir for a configuration that delivers nowhere else', ['output.type=emptyDir'], true, /emptyDir` keeps nothing after the pod ends/],
        ['emptyDir with a ConfigMap the chart cannot read', ['existingConfigMap=c', 'output.type=emptyDir', 'secrets.existingSecret=creds'], false, /emptyDir/],
        ['an existing claim that is not named', ['output.type=existingClaim'], true, /`output\.existingClaim` is empty/],
        ['cilium with no host: it would deny every host', ['networkPolicy.flavor=cilium'], true, /would deny every host/],
        ['the egress proxy with no host: it would refuse every host', ['egressProxy.enabled=true'], true, /would refuse every host/],
        ['the egress proxy and cilium together', ['egressProxy.enabled=true', 'networkPolicy.flavor=cilium', 'egress.fqdns={api.github.com}'], true, /Choose one/],
        ['the egress proxy and a forward proxy together', ['egressProxy.enabled=true', 'egress.fqdns={api.github.com}', 'proxy.httpsProxy=http://p.example:3128'], true, /bundled/],
        ['a value the schema does not know', ['secrets.values.ENTRA_CLIENT_SECRET=x'], true, /additional properties 'values' not allowed/i],
        ['an environment list', ['env[0].name=X'], true, /additional properties 'env' not allowed/i],
        ['the tag latest', ['image.tag=latest'], true, /image\/tag|image\.tag/],
        ['a proxy URL carrying a password', ['proxy.httpsProxy=http://user:pass@p.example:3128'], true, /httpsProxy/],
        ['a host that is not a hostname', ['networkPolicy.flavor=cilium', 'egress.fqdns={*.example.com}'], true, /egress\/fqdns|egress\.fqdns/],
    ];
    rendered.each(refusals)('refuses %s', (_what, sets, base, message) => {
        const r = helmTemplate([], sets, base);
        expect(r.ok).toBe(false);
        expect(r.stderr).toMatch(message);
    });

    rendered('accepts emptyDir when the configuration also delivers each run somewhere else', () => {
        const r = helmTemplate([], ['output.type=emptyDir', 'config.outputs[1].kind=stdout']);
        expect(r.ok).toBe(true);
        expect(kindsOf(r)).not.toContain('PersistentVolumeClaim');
        expect(scannerPod(r).volumes.find((v: Json) => v.name === 'out')).toEqual({ name: 'out', emptyDir: {} });
    });
});

// ───────────────────────────── the air-gapped bundle ─────────────────────────────

describe('deploy/airgap', () => {
    const VERSION = '9.8.7';
    const AMD = `${IMAGE_REPOSITORY}:${VERSION}-amd64`;
    const ARM = `${IMAGE_REPOSITORY}:${VERSION}-arm64`;
    let work: string;
    let stubs: string;
    let stubLog: string;

    /** A container runtime and a `uname` that answer what the scripts ask, from files. No daemon, no network. */
    function writeStubs(): void {
        fs.mkdirSync(stubs);
        fs.writeFileSync(
            path.join(stubs, 'docker'),
            `#!/bin/sh
echo "docker $*" >> "$STUB_LOG"
case "$1 $2" in
  "image inspect") for ref; do :; done
    case "$ref" in *amd64) echo linux/amd64 ;; *arm64) echo linux/arm64 ;; *) exit 1 ;; esac ;;
  "save -o") printf 'a stand-in image archive for %s\\n' "$4" > "$3" ;;
  "load -i") test -f "$3" && echo "Loaded image" ;;
  "tag "*) : ;;
  *) echo "unexpected: $*" >&2; exit 64 ;;
esac
`,
            { mode: 0o755 },
        );
        fs.writeFileSync(path.join(stubs, 'uname'), '#!/bin/sh\nif [ "$1" = "-m" ]; then echo "$STUB_MACHINE"; else echo Linux; fi\n', { mode: 0o755 });
    }

    function sh(cmd: string, args: string[], extraEnv: Record<string, string> = {}, cwd?: string): { status: number; stdout: string; stderr: string } {
        const out = spawnSync(cmd, args, {
            cwd,
            encoding: 'utf8',
            env: { PATH: `${stubs}:${process.env.PATH ?? ''}`, STUB_LOG: stubLog, STUB_MACHINE: 'x86_64', SOURCE_DATE_EPOCH: '1767225600', ...extraEnv },
        });
        return { status: out.status ?? -1, stdout: out.stdout, stderr: out.stderr };
    }

    const build = (outDir: string, extraEnv: Record<string, string> = {}, refs: [string, string] = [AMD, ARM], version = VERSION) =>
        sh(abs('deploy/airgap/build-bundle.sh'), [version, refs[0], refs[1], outDir], extraEnv);

    const treeFiles = (root: string): string[] => {
        const out: string[] = [];
        const walk = (dir: string) => {
            for (const e of fs.readdirSync(path.join(root, dir), { withFileTypes: true })) {
                const child = dir === '' ? e.name : `${dir}/${e.name}`;
                if (e.isDirectory()) walk(child);
                else out.push(child);
            }
        };
        walk('');
        return out.sort();
    };

    beforeEach(() => {
        work = fs.mkdtempSync(path.join(os.tmpdir(), 'scanent-airgap-'));
        stubs = path.join(work, 'stubs');
        stubLog = path.join(work, 'stub.log');
        writeStubs();
    });
    afterEach(() => fs.rmSync(work, { recursive: true, force: true }));

    it('builds the documented tree, with a checksum for every file, from two images it only saves', () => {
        const out = build(path.join(work, 'out'));
        expect(out.stderr).toBe('');
        expect(out.status).toBe(0);
        const tree = path.join(work, 'out', `scanent-${VERSION}-airgap`);
        const files = treeFiles(tree);
        const examples = fs.readdirSync(abs('deploy/examples')).map((f) => `examples/${f}`);
        expect(files).toEqual(
            [
                'LICENSE',
                'NOTICE',
                'README.md',
                'SHA256SUMS',
                'VERSION',
                'deploy/compose.egress.yaml',
                'deploy/compose.yaml',
                `deploy/helm/scanent-${VERSION}.tgz`,
                'docs/access.md',
                'docs/deployment.md',
                // Phase 4: what a site's security team and its operator read, and how to verify the bundle itself.
                'docs/network-and-permissions.md',
                'docs/operations.md',
                'docs/quick-start.md',
                'docs/scanner.md',
                'docs/verify-a-release.md',
                ...examples,
                'images/IMAGES',
                `images/scanent-${VERSION}-linux-amd64.tar`,
                `images/scanent-${VERSION}-linux-arm64.tar`,
                'load.sh',
                'sbom/README.txt',
                'verify.sh',
            ].sort(),
        );
        expect(fs.readFileSync(path.join(tree, 'VERSION'), 'utf8')).toBe(`${VERSION}\n`);
        expect(fs.readFileSync(path.join(tree, 'images/IMAGES'), 'utf8')).toBe(
            `amd64 images/scanent-${VERSION}-linux-amd64.tar ${AMD}\narm64 images/scanent-${VERSION}-linux-arm64.tar ${ARM}\n`,
        );
        // Every file but the list is in the list, once, sorted by path.
        const listed = fs
            .readFileSync(path.join(tree, 'SHA256SUMS'), 'utf8')
            .trimEnd()
            .split('\n')
            .map((line) => line.replace(/^[0-9a-f]{64} {2}/, ''));
        expect(listed).toEqual(files.filter((f) => f !== 'SHA256SUMS'));
        // No SBOM was asked for: the bundle says so, and holds no file under an SBOM's name.
        // (The notice used to name Phase 4 as where an SBOM would come from. A release now carries one, so it says why this bundle does not.)
        expect(fs.readFileSync(path.join(tree, 'sbom/README.txt'), 'utf8')).toBe(
            'No SBOM in this bundle: it was built without one. A released bundle holds sbom/<arch>.cdx.json for each image.\n',
        );
        // Nor was a signature asked for: there is no signatures directory at all.
        expect(fs.existsSync(path.join(tree, 'signatures'))).toBe(false);
        // It asked the runtime about, and saved, the two images, and did nothing else with it: no build, pull or push.
        const calls = fs.readFileSync(stubLog, 'utf8').trim().split('\n');
        expect(calls.map((c) => c.split(' ').slice(1, 3).join(' '))).toEqual(['image inspect', 'image inspect', 'save -o', 'save -o']);
        // The archive holds the same files.
        const archived = execFileSync('tar', ['-tf', `${tree}.tar`], { encoding: 'utf8' })
            .trim()
            .split('\n')
            .filter((p) => !p.endsWith('/'))
            .map((p) => p.replace(`scanent-${VERSION}-airgap/`, ''))
            .sort();
        expect(archived).toEqual(files);
        // The chart archive unpacks to the chart directory helm installs.
        const chartFiles = execFileSync('tar', ['-tzf', path.join(tree, `deploy/helm/scanent-${VERSION}.tgz`)], { encoding: 'utf8' });
        expect(chartFiles).toContain('scanent/Chart.yaml\n');
        expect(chartFiles).toContain('scanent/templates/cronjob.yaml\n');
    });

    it('gives the same archive, byte for byte, from the same inputs', () => {
        expect(build(path.join(work, 'a')).status).toBe(0);
        expect(build(path.join(work, 'b')).status).toBe(0);
        const a = fs.readFileSync(path.join(work, 'a', `scanent-${VERSION}-airgap.tar`));
        const b = fs.readFileSync(path.join(work, 'b', `scanent-${VERSION}-airgap.tar`));
        expect(a.length).toBeGreaterThan(10_000);
        expect(a.equals(b)).toBe(true);
    });

    it('refuses, writing nothing: a bad version, one image twice, an image of the wrong architecture, an image that is not there', () => {
        const out = path.join(work, 'out');
        const cases: Array<[ReturnType<typeof build>, RegExp]> = [
            [build(out, {}, [AMD, ARM], 'v1.2.3'), /MAJOR\.MINOR\.PATCH/],
            [build(out, {}, [AMD, AMD]), /the same/],
            [build(out, {}, [ARM, AMD]), /is linux\/arm64, not linux\/amd64/],
            [build(out, {}, [AMD, `${IMAGE_REPOSITORY}:${VERSION}-missing`]), /no local image/],
        ];
        for (const [result, message] of cases) {
            expect(result.status).toBe(1);
            expect(result.stderr).toMatch(message);
        }
        expect(fs.existsSync(out) ? fs.readdirSync(out) : []).toEqual([]);
        expect(sh(abs('deploy/airgap/build-bundle.sh'), [VERSION]).status).toBe(2);
    });

    it('will not write over an earlier bundle', () => {
        const out = path.join(work, 'out');
        expect(build(out).status).toBe(0);
        const again = build(out);
        expect(again.status).toBe(1);
        expect(again.stderr).toMatch(/already exists/);
    });

    it('stores an SBOM per image when a command gives one, and refuses an empty one', () => {
        const sbom = path.join(stubs, 'sbom-tool');
        fs.writeFileSync(sbom, '#!/bin/sh\nfor ref; do :; done\nprintf \'{"bomFormat":"CycloneDX","for":"%s"}\\n\' "$ref"\n', { mode: 0o755 });
        const ok = build(path.join(work, 'with'), { SCANENT_SBOM_CMD: `${sbom} --format cyclonedx` });
        expect(ok.status).toBe(0);
        const tree = path.join(work, 'with', `scanent-${VERSION}-airgap`);
        expect(fs.readdirSync(path.join(tree, 'sbom')).sort()).toEqual(['amd64.cdx.json', 'arm64.cdx.json']);
        expect(JSON.parse(fs.readFileSync(path.join(tree, 'sbom/arm64.cdx.json'), 'utf8'))).toEqual({ bomFormat: 'CycloneDX', for: ARM });
        expect(fs.readFileSync(path.join(tree, 'SHA256SUMS'), 'utf8')).toContain('  sbom/amd64.cdx.json\n');

        const silent = path.join(stubs, 'sbom-silent');
        fs.writeFileSync(silent, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
        const empty = build(path.join(work, 'empty'), { SCANENT_SBOM_CMD: silent });
        expect(empty.status).toBe(1);
        expect(empty.stderr).toMatch(/an empty SBOM is not stored/);
        expect(fs.existsSync(path.join(work, 'empty', `scanent-${VERSION}-airgap.tar`))).toBe(false);

        // Something that is not an SBOM is not stored as one.
        const prose = path.join(stubs, 'sbom-prose');
        fs.writeFileSync(prose, '#!/bin/sh\necho "no vulnerabilities found"\n', { mode: 0o755 });
        const notOne = build(path.join(work, 'prose'), { SCANENT_SBOM_CMD: prose });
        expect(notOne.status).toBe(1);
        expect(notOne.stderr).toMatch(/did not print a CycloneDX document/);
        expect(fs.existsSync(path.join(work, 'prose', `scanent-${VERSION}-airgap.tar`))).toBe(false);
    });

    const CYCLONEDX = '{"bomFormat":"CycloneDX","components":[{"name":"zod"}]}\n';

    /** SBOMs as the release's build job makes them: one file per architecture, in one directory. */
    function sbomDir(name: string, files: Record<string, string> = { 'amd64.cdx.json': CYCLONEDX, 'arm64.cdx.json': CYCLONEDX }): string {
        const dir = path.join(work, name);
        fs.mkdirSync(dir);
        for (const [file, text] of Object.entries(files)) fs.writeFileSync(path.join(dir, file), text);
        return dir;
    }

    /**
     * A signing command. It logs its arguments, then runs `body` with `$1` the
     * file to write and `$2` the file to sign, which are its last two arguments.
     */
    function signTool(body: string): string {
        const tool = path.join(stubs, 'sign-tool');
        fs.writeFileSync(tool, `#!/bin/sh\necho "sign $*" >> "$STUB_LOG"\nwhile [ "$#" -gt 2 ]; do shift; done\n${body}\n`, { mode: 0o755 });
        return tool;
    }
    /** Writes `signed:<sha256 of the file>`: a stand-in that still depends on every byte of what it signs. */
    const SIGN = 'printf "signed:%s\\n" "$(sha256sum "$2" | cut -d" " -f1)" > "$1"';

    it('copies in the SBOMs a directory holds, one per image, and refuses a missing, empty or foreign one, or both ways at once', () => {
        const ok = build(path.join(work, 'with'), { SCANENT_SBOM_DIR: sbomDir('sboms') });
        expect(ok.stderr).toBe('');
        expect(ok.status).toBe(0);
        const tree = path.join(work, 'with', `scanent-${VERSION}-airgap`);
        expect(fs.readdirSync(path.join(tree, 'sbom')).sort()).toEqual(['amd64.cdx.json', 'arm64.cdx.json']);
        expect(fs.readFileSync(path.join(tree, 'sbom/amd64.cdx.json'), 'utf8')).toBe(CYCLONEDX);
        expect(fs.readFileSync(path.join(tree, 'SHA256SUMS'), 'utf8')).toContain('  sbom/arm64.cdx.json\n');

        const refused: Array<[string, Record<string, string>, RegExp]> = [
            ['one-missing', { 'amd64.cdx.json': CYCLONEDX }, /holds no arm64\.cdx\.json, or an empty one/],
            ['one-empty', { 'amd64.cdx.json': CYCLONEDX, 'arm64.cdx.json': '' }, /holds no arm64\.cdx\.json, or an empty one/],
            ['one-foreign', { 'amd64.cdx.json': '{"spdxVersion":"SPDX-2.3"}', 'arm64.cdx.json': CYCLONEDX }, /amd64\.cdx\.json is not a CycloneDX document/],
        ];
        for (const [name, files, message] of refused) {
            const out = build(path.join(work, `out-${name}`), { SCANENT_SBOM_DIR: sbomDir(name, files) });
            expect(out.status).toBe(1);
            expect(out.stderr).toMatch(message);
            expect(fs.existsSync(path.join(work, `out-${name}`, `scanent-${VERSION}-airgap.tar`))).toBe(false);
        }
        const both = build(path.join(work, 'both'), { SCANENT_SBOM_DIR: path.join(work, 'sboms'), SCANENT_SBOM_CMD: 'true' });
        expect(both.status).toBe(1);
        expect(both.stderr).toMatch(/not both/);
    });

    it('signs the list of checksums when given a command to, and stores the signature outside the list and inside the archive', () => {
        const out = build(path.join(work, 'signed'), { SCANENT_SIGN_CMD: `${signTool(SIGN)} sign-blob --yes --bundle`, SCANENT_SBOM_DIR: sbomDir('sboms') });
        expect(out.stderr).toBe('');
        expect(out.status).toBe(0);
        const tree = path.join(work, 'signed', `scanent-${VERSION}-airgap`);
        const sums = fs.readFileSync(path.join(tree, 'SHA256SUMS'));
        // The command was given its flags as written, then where to write, then the list: `cosign sign-blob --yes --bundle <out> <blob>`.
        expect(fs.readFileSync(stubLog, 'utf8')).toContain(`sign sign-blob --yes --bundle ${tree}/signatures/SHA256SUMS.sigstore.json ${tree}/SHA256SUMS\n`);
        // What it signed is the list as it stands in the bundle, with every other file already hashed into it.
        expect(fs.readFileSync(path.join(tree, 'signatures/SHA256SUMS.sigstore.json'), 'utf8')).toBe(`signed:${createHash('sha256').update(sums).digest('hex')}\n`);
        expect(sums.toString('utf8')).not.toContain('signatures/');
        expect(sums.toString('utf8')).toContain('  sbom/amd64.cdx.json\n');
        expect(execFileSync('tar', ['-tf', `${tree}.tar`], { encoding: 'utf8' })).toContain(`scanent-${VERSION}-airgap/signatures/SHA256SUMS.sigstore.json\n`);

        // A command that fails, or that writes nothing, leaves no archive: an unsigned bundle is never passed off as a signed one.
        const failing = build(path.join(work, 'failing'), { SCANENT_SIGN_CMD: signTool('exit 3') });
        expect(failing.status).toBe(1);
        expect(failing.stderr).toMatch(/the signing command failed/);
        expect(fs.existsSync(path.join(work, 'failing', `scanent-${VERSION}-airgap.tar`))).toBe(false);
        const silent = build(path.join(work, 'silent'), { SCANENT_SIGN_CMD: signTool(': > "$1"') });
        expect(silent.status).toBe(1);
        expect(silent.stderr).toMatch(/wrote no signature/);
        expect(fs.existsSync(path.join(work, 'silent', `scanent-${VERSION}-airgap.tar`))).toBe(false);
    });

    it('sign-bundle.sh signs an unsigned bundle into the bytes build-bundle.sh makes when it signs, and signs nothing it cannot vouch for', () => {
        const signCmd = `${signTool(SIGN)} sign-blob --yes --bundle`;
        const sign = (archive: string, outDir: string, env: Record<string, string> = { SCANENT_SIGN_CMD: signCmd }) => sh(abs('deploy/airgap/sign-bundle.sh'), [archive, outDir], env);
        const sha = (file: string) => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
        const sboms = sbomDir('sboms');
        expect(build(path.join(work, 'unsigned'), { SCANENT_SBOM_DIR: sboms }).status).toBe(0);
        expect(build(path.join(work, 'direct'), { SCANENT_SBOM_DIR: sboms, SCANENT_SIGN_CMD: signCmd }).status).toBe(0);
        const unsigned = path.join(work, 'unsigned', `scanent-${VERSION}-airgap.tar`);

        // The archive's own time is used when none is given, as the release job runs it.
        const out = spawnSync(abs('deploy/airgap/sign-bundle.sh'), [unsigned, path.join(work, 'signed-later')], {
            encoding: 'utf8',
            env: { PATH: `${stubs}:${process.env.PATH ?? ''}`, STUB_LOG: stubLog, SCANENT_SIGN_CMD: signCmd },
        });
        expect(out.stderr).toBe('');
        expect(out.status).toBe(0);
        const signed = path.join(work, 'signed-later', `scanent-${VERSION}-airgap.tar`);
        expect(out.stdout).toBe(`bundle: ${signed}\nsha256: ${sha(signed)}\n`);
        // Signed apart or signed at once: one archive, byte for byte.
        expect(sha(signed)).toBe(sha(path.join(work, 'direct', `scanent-${VERSION}-airgap.tar`)));
        expect(sha(signed)).not.toBe(sha(unsigned));
        const tree = path.join(work, 'signed-later', `scanent-${VERSION}-airgap`);
        expect(fs.readFileSync(path.join(tree, 'signatures/SHA256SUMS.sigstore.json'), 'utf8')).toBe(`signed:${sha(path.join(tree, 'SHA256SUMS'))}\n`);
        expect(fs.readFileSync(path.join(tree, 'SHA256SUMS'))).toEqual(fs.readFileSync(path.join(work, 'unsigned', `scanent-${VERSION}-airgap`, 'SHA256SUMS')));

        // No command to sign with, a missing archive, a second run into the same place: nothing is written.
        expect(sign(unsigned, path.join(work, 'none'), {}).stderr).toMatch(/SCANENT_SIGN_CMD is not set/);
        expect(fs.existsSync(path.join(work, 'none'))).toBe(false);
        expect(sign(path.join(work, 'missing.tar'), path.join(work, 'none')).status).toBe(1);
        expect(sign(unsigned, path.join(work, 'signed-later')).stderr).toMatch(/already exists/);
        expect(sh(abs('deploy/airgap/sign-bundle.sh'), [unsigned]).status).toBe(2);
        // A bundle that is already signed is not signed twice.
        const twice = sign(signed, path.join(work, 'twice'));
        expect(twice.status).toBe(1);
        expect(twice.stderr).toMatch(/already carries a signature/);
        // A signing command that fails, or writes nothing, leaves no archive.
        expect(sign(unsigned, path.join(work, 'failing'), { SCANENT_SIGN_CMD: signTool('exit 3') }).stderr).toMatch(/the signing command failed/);
        expect(fs.existsSync(path.join(work, 'failing', `scanent-${VERSION}-airgap.tar`))).toBe(false);
        expect(sign(unsigned, path.join(work, 'silent'), { SCANENT_SIGN_CMD: signTool(': > "$1"') }).stderr).toMatch(/wrote no signature/);
        expect(fs.existsSync(path.join(work, 'silent', `scanent-${VERSION}-airgap.tar`))).toBe(false);

        // A tree whose files are not the files its list names is not signed: the signature would vouch for the list alone.
        const changed = path.join(work, 'changed');
        fs.mkdirSync(changed);
        execFileSync('tar', ['-xf', unsigned, '-C', changed]);
        fs.appendFileSync(path.join(changed, `scanent-${VERSION}-airgap`, 'load.sh'), '# changed after the list was made\n');
        execFileSync('tar', ['-C', changed, '-cf', path.join(changed, 'changed.tar'), `scanent-${VERSION}-airgap`]);
        fs.writeFileSync(stubLog, '');
        const refused = sign(path.join(changed, 'changed.tar'), path.join(work, 'refused'));
        expect(refused.status).toBe(1);
        expect(refused.stderr).toMatch(/does not pass its own check; it is not signed/);
        expect(fs.readFileSync(stubLog, 'utf8')).not.toContain('sign-blob');
        // An archive that is not one bundle directory is refused before it is unpacked.
        const stray = path.join(work, 'stray');
        fs.mkdirSync(path.join(stray, 'other'), { recursive: true });
        fs.writeFileSync(path.join(stray, 'other', 'x'), 'x');
        execFileSync('tar', ['-C', stray, '-cf', path.join(stray, 'stray.tar'), 'other']);
        const notOne = sign(path.join(stray, 'stray.tar'), path.join(work, 'stray-out'));
        expect(notOne.status).toBe(1);
        expect(notOne.stderr).toMatch(/does not hold one scanent-<version>-airgap directory/);
        expect(fs.existsSync(path.join(work, 'stray-out', 'other'))).toBe(false);
    });

    describe('verify.sh and load.sh, on a built bundle', () => {
        let tree: string;
        // This bundle was built here with no signing command, so it is checked the way
        // one you built yourself is: `--unsigned`. With no flag it is refused (below).
        const verify = () => sh(path.join(tree, 'verify.sh'), ['--unsigned']);
        const load = (machine: string) => sh(path.join(tree, 'load.sh'), ['--unsigned'], { STUB_MACHINE: machine });

        beforeEach(() => {
            expect(build(path.join(work, 'out')).status).toBe(0);
            tree = path.join(work, 'out', `scanent-${VERSION}-airgap`);
            fs.writeFileSync(stubLog, '');
        });

        it('verify passes on the bundle as built, and says how many files it checked', () => {
            const out = verify();
            expect(out.status).toBe(0);
            // Phase 4 added the two lines after the first: what the bundle holds no SBOM and no signature of, said and not left out.
            expect(out.stdout).toBe(
                `verify: ${treeFiles(tree).length - 1} files match SHA256SUMS\n` +
                    'verify: this bundle was built without an SBOM\n' +
                    'verify: this bundle carries no signature. The checksums detect damage, not a replaced bundle\n',
            );
        });

        it('verify takes one flag, and refuses anything else', () => {
            // The usage line grew with `--unsigned`; two flags together are still refused, the new one included.
            for (const args of [['--frobnicate'], ['--require-signature', '--no-signature'], ['--no-signature', '--no-signature'], ['x'], ['--unsigned', '--no-signature'], ['--require-signature', '--unsigned']]) {
                const out = sh(path.join(tree, 'verify.sh'), args);
                expect(out.status).toBe(2);
                expect(out.stderr).toBe('usage: verify.sh [--unsigned | --no-signature | --require-signature]\n');
            }
        });

        it('with no flag, a bundle with no signature fails and loads nothing: its absence is never accepted unasked', () => {
            const out = sh(path.join(tree, 'verify.sh'), []);
            expect(out.status).toBe(1);
            expect(out.stdout).toContain('files match SHA256SUMS');
            expect(out.stderr).toBe(
                'verify: this bundle carries no signature, so nothing shows it is the one the release made.\n' +
                    'verify: a released bundle is signed. Pass --unsigned only for a bundle you built yourself.\n',
            );
            const loaded = sh(path.join(tree, 'load.sh'), [], { STUB_MACHINE: 'x86_64' });
            expect(loaded.status).toBe(1);
            expect(fs.readFileSync(stubLog, 'utf8')).toBe('');
            // --no-signature accepts it too, and says the same thing --unsigned does.
            const skipped = sh(path.join(tree, 'verify.sh'), ['--no-signature']);
            expect(skipped.status).toBe(0);
            expect(skipped.stdout).toContain('verify: this bundle carries no signature. The checksums detect damage, not a replaced bundle\n');
        });

        it('a file named SHA256SUMS anywhere but the top of the bundle is an added file', () => {
            for (const at of ['images/SHA256SUMS', 'x/SHA256SUMS', 'docs/SHA256SUMS']) {
                fs.mkdirSync(path.dirname(path.join(tree, at)), { recursive: true });
                fs.writeFileSync(path.join(tree, at), 'evil\n');
                const out = verify();
                expect(out.status).toBe(1);
                expect(out.stderr).toBe('verify: the files here are not the files SHA256SUMS lists\n');
                fs.rmSync(path.join(tree, at));
                if (at.startsWith('x/')) fs.rmdirSync(path.join(tree, 'x'));
            }
            expect(verify().status).toBe(0);
        });

        it('verify --require-signature fails on a bundle with no signature, and load with it loads nothing', () => {
            const out = sh(path.join(tree, 'verify.sh'), ['--require-signature']);
            expect(out.status).toBe(1);
            expect(out.stderr).toBe('verify: this bundle carries no signature, and --require-signature was given\n');
            const loaded = sh(path.join(tree, 'load.sh'), ['--require-signature']);
            expect(loaded.status).toBe(1);
            expect(fs.readFileSync(stubLog, 'utf8')).toBe('');
        });

        it('verify fails when sbom/ holds both a notice and an SBOM, neither, an empty one, or a file that is neither', () => {
            // Each change is made with the list brought up to date, so the checksum step passes and the SBOM step is what decides.
            const relist = () => {
                const lines = treeFiles(tree)
                    .filter((f) => f !== 'SHA256SUMS')
                    .map((f) => `${createHash('sha256').update(fs.readFileSync(path.join(tree, f))).digest('hex')}  ${f}`);
                fs.writeFileSync(path.join(tree, 'SHA256SUMS'), `${lines.join('\n')}\n`);
            };
            const expectFailure = (message: RegExp) => {
                relist();
                const out = verify();
                expect(out.status).toBe(1);
                expect(out.stderr).toMatch(message);
            };
            fs.writeFileSync(path.join(tree, 'sbom/amd64.cdx.json'), CYCLONEDX);
            expectFailure(/holds both an SBOM and the notice that there is none/);
            fs.rmSync(path.join(tree, 'sbom/README.txt'));
            expectFailure(/the SBOM for arm64 is missing or empty/);
            fs.writeFileSync(path.join(tree, 'sbom/arm64.cdx.json'), '{"spdxVersion":"SPDX-2.3"}\n');
            expectFailure(/the SBOM for arm64 is not a CycloneDX document/);
            fs.writeFileSync(path.join(tree, 'sbom/arm64.cdx.json'), CYCLONEDX);
            fs.writeFileSync(path.join(tree, 'sbom/notes.txt'), 'x');
            expectFailure(/holds a file that is not the SBOM of one of the images/);
            fs.rmSync(path.join(tree, 'sbom/notes.txt'));
            relist();
            expect(verify().stdout).toContain('verify: 2 CycloneDX SBOMs, one per image\n');
            // The notice with something beside it is refused too.
            fs.rmSync(path.join(tree, 'sbom/amd64.cdx.json'));
            fs.rmSync(path.join(tree, 'sbom/arm64.cdx.json'));
            fs.writeFileSync(path.join(tree, 'sbom/README.txt'), 'No SBOM.\n');
            fs.writeFileSync(path.join(tree, 'sbom/notes.txt'), 'x');
            expectFailure(/holds a file that is neither an SBOM nor the notice/);
        });

        it('verify fails when a byte is changed, a file is removed, a file is added, or the list is emptied', () => {
            const image = path.join(tree, `images/scanent-${VERSION}-linux-amd64.tar`);
            const original = fs.readFileSync(image);
            fs.writeFileSync(image, Buffer.concat([original.subarray(0, 5), Buffer.from('X'), original.subarray(6)]));
            expect(verify().status).toBe(1);
            expect(verify().stderr).toMatch(/does not match its checksum/);
            fs.writeFileSync(image, original);
            expect(verify().status).toBe(0);

            fs.rmSync(path.join(tree, 'docs/access.md'));
            expect(verify().status).toBe(1);
            fs.copyFileSync(abs('docs/access.md'), path.join(tree, 'docs/access.md'));
            expect(verify().status).toBe(0);

            fs.writeFileSync(path.join(tree, 'images/extra.tar'), 'not in the list');
            const added = verify();
            expect(added.status).toBe(1);
            expect(added.stderr).toMatch(/not the files SHA256SUMS lists/);
            fs.rmSync(path.join(tree, 'images/extra.tar'));
            expect(verify().status).toBe(0);

            // Something that is not a regular file is not in the list either, and no checksum vouches for it.
            fs.symlinkSync('/etc/passwd', path.join(tree, 'images/link'));
            const linked = verify();
            expect(linked.status).toBe(1);
            expect(linked.stderr).toMatch(/neither a file nor a directory/);
            fs.rmSync(path.join(tree, 'images/link'));
            fs.symlinkSync(path.join(tree, 'docs'), path.join(tree, 'more-docs'));
            expect(verify().status).toBe(1);
            fs.rmSync(path.join(tree, 'more-docs'));
            fs.mkdirSync(path.join(tree, 'empty'));
            const empty = verify();
            expect(empty.status).toBe(1);
            expect(empty.stderr).toMatch(/an empty directory/);
            fs.rmdirSync(path.join(tree, 'empty'));
            expect(verify().status).toBe(0);

            // Nothing listed is nothing verified, not a pass.
            fs.writeFileSync(path.join(tree, 'SHA256SUMS'), '');
            const emptied = verify();
            expect(emptied.status).toBe(1);
            expect(emptied.stderr).toMatch(/nothing was verified/);
        });

        it.each([
            ['x86_64', 'amd64', AMD],
            ['amd64', 'amd64', AMD],
            ['aarch64', 'arm64', ARM],
            ['arm64', 'arm64', ARM],
        ])('load on %s verifies first, loads the %s archive and tags it by version', (machine, arch, ref) => {
            const out = load(machine);
            expect(out.status).toBe(0);
            expect(out.stdout.indexOf('verify: ')).toBeGreaterThanOrEqual(0);
            expect(out.stdout.indexOf('verify: ')).toBeLessThan(out.stdout.indexOf('loaded: '));
            expect(out.stdout).toContain(`loaded: ${IMAGE_REPOSITORY}:${VERSION}  (linux/${arch})`);
            expect(fs.readFileSync(stubLog, 'utf8').trim().split('\n')).toEqual([
                `docker load -i images/scanent-${VERSION}-linux-${arch}.tar`,
                `docker tag ${ref} ${IMAGE_REPOSITORY}:${VERSION}`,
            ]);
            // What it tells the person to run next is the hardened form.
            for (const flag of ['--read-only', '--cap-drop ALL', '--security-opt no-new-privileges', '--user "$(id -u):$(id -g)"']) {
                expect(out.stdout).toContain(flag);
            }
        });

        it('load refuses an architecture the bundle has no image for, and loads nothing', () => {
            const out = load('riscv64');
            expect(out.status).toBe(1);
            expect(out.stderr).toMatch(/no scanent image for this machine's architecture: riscv64/);
            expect(fs.readFileSync(stubLog, 'utf8')).toBe('');
        });

        it('load stops before the runtime is touched when the bundle does not verify', () => {
            fs.appendFileSync(path.join(tree, `images/scanent-${VERSION}-linux-amd64.tar`), 'tampered');
            const out = load('x86_64');
            expect(out.status).toBe(1);
            expect(fs.readFileSync(stubLog, 'utf8')).toBe('');
        });

        it('load uses the runtime it is told to', () => {
            fs.copyFileSync(path.join(stubs, 'docker'), path.join(stubs, 'podman'));
            const out = sh(path.join(tree, 'load.sh'), ['--unsigned'], { CONTAINER_RUNTIME: 'podman' });
            expect(out.status).toBe(0);
            // The stub logs under the name `docker`; what matters is which file ran, and the hint names it.
            expect(out.stdout).toContain('podman run --rm');
        });
    });

    describe('verify.sh and load.sh, on a signed bundle', () => {
        let tree: string;
        let bin: string;
        const IDENTITY = `https://github.com/RodnaPamet/scanent/.github/workflows/release.yml@refs/tags/v${VERSION}`;
        const SIGNATURE = 'signatures/SHA256SUMS.sigstore.json';

        /**
         * A `cosign` that verifies the stand-in signature `signTool(SIGN)` writes: it passes
         * only when the bundle file holds the SHA-256 of the blob it is given. It logs its arguments.
         */
        function cosignStub(dir: string): void {
            fs.writeFileSync(
                path.join(dir, 'cosign'),
                `#!/bin/sh
echo "cosign $*" >> "$STUB_LOG"
[ "$1" = "verify-blob" ] || exit 64
shift
bundle=""
while [ "$#" -gt 1 ]; do
  case "$1" in
    --bundle) bundle="$2"; shift ;;
    --certificate-identity | --certificate-oidc-issuer | --trusted-root) shift ;;
    *) echo "Error: unknown flag: $1" >&2; exit 64 ;;
  esac
  shift
done
[ "$(cat "$bundle")" = "signed:$(sha256sum "$1" | cut -d' ' -f1)" ] || { echo "Error: none of the expected identities matched what was in the certificate" >&2; exit 1; }
`,
                { mode: 0o755 },
            );
        }

        /** With `cosign` on the path, or with a path that holds every tool the scripts use and no `cosign`. */
        const run = (script: string, args: string[], cosign: boolean, extraEnv: Record<string, string> = {}) =>
            spawnSync(path.join(tree, script), args, {
                encoding: 'utf8',
                env: { PATH: cosign ? `${stubs}:${bin}` : bin, STUB_LOG: stubLog, STUB_MACHINE: 'x86_64', ...extraEnv },
            });

        beforeEach(() => {
            const out = build(path.join(work, 'signed'), { SCANENT_SIGN_CMD: `${signTool(SIGN)} sign-blob --yes --bundle`, SCANENT_SBOM_DIR: sbomDir('sboms') });
            expect(out.status).toBe(0);
            tree = path.join(work, 'signed', `scanent-${VERSION}-airgap`);
            cosignStub(stubs);
            // The tools the two scripts call, and nothing else: whatever `cosign` this machine has is not among them.
            bin = path.join(work, 'bin');
            fs.mkdirSync(bin);
            for (const tool of ['sh', 'cat', 'cut', 'dirname', 'find', 'grep', 'head', 'sed', 'sha256sum', 'sort', 'tr', 'wc']) {
                const found = execFileSync('sh', ['-c', `command -v ${tool}`], { encoding: 'utf8' }).trim();
                fs.symlinkSync(found, path.join(bin, tool));
            }
            for (const stub of ['docker', 'uname']) fs.copyFileSync(path.join(stubs, stub), path.join(bin, stub));
            fs.writeFileSync(stubLog, '');
        });

        it('passes with cosign on the path, for the release workflow at this version\'s tag, offline', () => {
            const out = run('verify.sh', ['--require-signature'], true);
            expect(out.stderr).toBe('');
            expect(out.status).toBe(0);
            expect(out.stdout).toBe(
                `verify: ${treeFiles(tree).length - 2} files match SHA256SUMS\n` +
                    'verify: 2 CycloneDX SBOMs, one per image\n' +
                    `verify: SHA256SUMS is signed by ${IDENTITY}\n`,
            );
            // Exactly the check the documents give: the bundle's own signature, this identity, GitHub's issuer.
            // No `--offline`: cosign 3 deprecates it, and the stub above refuses any flag it does not know, as a later cosign would.
            expect(fs.readFileSync(stubLog, 'utf8')).toBe(
                `cosign verify-blob --bundle ${SIGNATURE} --certificate-identity ${IDENTITY} --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS\n`,
            );
            // Without the flag a signed bundle is checked all the same.
            expect(run('verify.sh', [], true).stdout).toContain(`verify: SHA256SUMS is signed by ${IDENTITY}\n`);
        });

        it('fails when the signature does not verify: the list changed, the signature changed, or it is empty', () => {
            // A file and the list changed together, as someone replacing a file would: the checksums agree, the signature does not.
            const doc = path.join(tree, 'docs/access.md');
            fs.appendFileSync(doc, 'replaced\n');
            const sums = path.join(tree, 'SHA256SUMS');
            const original = fs.readFileSync(sums, 'utf8');
            const digest = createHash('sha256').update(fs.readFileSync(doc)).digest('hex');
            fs.writeFileSync(sums, original.replace(/^[0-9a-f]{64} {2}docs\/access\.md$/m, `${digest}  docs/access.md`));
            const replaced = run('verify.sh', [], true);
            expect(replaced.status).toBe(1);
            expect(replaced.stdout).toContain('files match SHA256SUMS');
            // cosign's own reason is shown, then ours: a failure to verify and a cosign that cannot run the check read differently.
            expect(replaced.stderr).toBe(
                'verify: cosign: Error: none of the expected identities matched what was in the certificate\n' +
                    `verify: the signature over SHA256SUMS does not verify for ${IDENTITY}\n`,
            );
            // The checksums alone would have let it through: that is what the signature is for.
            expect(run('verify.sh', ['--no-signature'], true).status).toBe(0);
            // And load stops there.
            expect(run('load.sh', [], true).status).toBe(1);
            expect(fs.readFileSync(stubLog, 'utf8')).not.toContain('docker load');

            fs.writeFileSync(sums, original);
            fs.copyFileSync(abs('docs/access.md'), doc);
            expect(run('verify.sh', [], true).status).toBe(0);
            fs.writeFileSync(path.join(tree, SIGNATURE), 'signed:0000\n');
            expect(run('verify.sh', [], true).status).toBe(1);
            fs.writeFileSync(path.join(tree, SIGNATURE), '');
            const empty = run('verify.sh', [], true);
            expect(empty.status).toBe(1);
            expect(empty.stderr).toBe('verify: the signature file is empty\n');
        });

        it('fails, and says the signature was not checked, when the bundle is signed and cosign is absent', () => {
            const out = run('verify.sh', [], false);
            expect(out.status).toBe(1);
            expect(out.stdout).toContain('files match SHA256SUMS');
            expect(out.stderr).toBe(
                'verify: this bundle is signed, and cosign is not on the path, so the signature was NOT checked.\n' +
                    'verify: install cosign and run this again, or pass --no-signature to accept the checksums alone.\n',
            );
            expect(run('verify.sh', ['--require-signature'], false).status).toBe(1);
            // load.sh loads nothing either.
            expect(run('load.sh', [], false).status).toBe(1);
            expect(fs.readFileSync(stubLog, 'utf8')).toBe('');
        });

        it('--no-signature accepts the checksums alone, says so, and load then loads', () => {
            const out = run('verify.sh', ['--no-signature'], false);
            expect(out.status).toBe(0);
            expect(out.stdout).toContain('verify: the signature was NOT checked (--no-signature)\n');
            const loaded = run('load.sh', ['--no-signature'], false);
            expect(loaded.status).toBe(0);
            expect(loaded.stdout).toContain('verify: the signature was NOT checked (--no-signature)\n');
            expect(fs.readFileSync(stubLog, 'utf8')).toContain(`docker load -i images/scanent-${VERSION}-linux-amd64.tar\n`);
        });

        it('a released bundle with its signature taken out and its list rewritten does not load', () => {
            // What someone replacing a release bundle does: change the image, bring the list up to date, remove the signature.
            const image = path.join(tree, `images/scanent-${VERSION}-linux-amd64.tar`);
            fs.writeFileSync(image, 'a different image');
            const sums = path.join(tree, 'SHA256SUMS');
            const digest = createHash('sha256').update('a different image').digest('hex');
            const listed = fs.readFileSync(sums, 'utf8');
            const relisted = listed.replace(new RegExp(`^[0-9a-f]{64} {2}images/scanent-${VERSION.replace(/\./g, '\\.')}-linux-amd64\\.tar$`, 'm'), `${digest}  images/scanent-${VERSION}-linux-amd64.tar`);
            expect(relisted).not.toBe(listed);
            fs.writeFileSync(sums, relisted);
            fs.rmSync(path.join(tree, 'signatures'), { recursive: true });
            for (const cosign of [true, false]) {
                const out = run('verify.sh', [], cosign);
                expect(out.status).toBe(1);
                expect(out.stdout).toContain('files match SHA256SUMS');
                expect(out.stderr).toContain('verify: this bundle carries no signature, so nothing shows it is the one the release made.\n');
                expect(run('verify.sh', ['--require-signature'], cosign).status).toBe(1);
                expect(run('load.sh', [], cosign).status).toBe(1);
            }
            expect(fs.readFileSync(stubLog, 'utf8')).not.toContain('docker');
        });

        it('--unsigned does not skip a signature that is there', () => {
            expect(run('verify.sh', ['--unsigned'], true).stdout).toContain(`verify: SHA256SUMS is signed by ${IDENTITY}\n`);
            expect(run('verify.sh', ['--unsigned'], false).status).toBe(1);
            fs.writeFileSync(path.join(tree, SIGNATURE), 'signed:0000\n');
            expect(run('verify.sh', ['--unsigned'], true).status).toBe(1);
        });

        it('shows what cosign said when it cannot run the check, and fails', () => {
            // A cosign that refuses a flag, as a version that dropped one would.
            fs.writeFileSync(path.join(stubs, 'cosign'), '#!/bin/sh\necho "Error: unknown flag: --bundle" >&2\nexit 1\n', { mode: 0o755 });
            const out = run('verify.sh', [], true);
            expect(out.status).toBe(1);
            expect(out.stderr).toBe(`verify: cosign: Error: unknown flag: --bundle\nverify: the signature over SHA256SUMS does not verify for ${IDENTITY}\n`);
        });

        it('allows the signature file and nothing else outside the list', () => {
            fs.writeFileSync(path.join(tree, 'signatures/extra.json'), '{}');
            const out = run('verify.sh', [], true);
            expect(out.status).toBe(1);
            expect(out.stderr).toBe('verify: the files here are not the files SHA256SUMS lists\n');
        });

        it('passes a trusted root to cosign when one is named, and refuses a VERSION that is not one', () => {
            expect(run('verify.sh', [], true, { SCANENT_TRUSTED_ROOT: '/srv/trusted_root.json' }).status).toBe(0);
            expect(fs.readFileSync(stubLog, 'utf8')).toContain('cosign verify-blob --trusted-root /srv/trusted_root.json --bundle ');
            // The identity is built from VERSION, which is in the signed list: a changed one fails at the checksums, before it is used.
            fs.writeFileSync(path.join(tree, 'VERSION'), '9.8.7 --insecure\n');
            const out = run('verify.sh', [], true);
            expect(out.status).toBe(1);
            expect(out.stderr).toContain('verify: a file does not match its checksum\n');
            // And with the list changed to match, the identity is still never built from text that is not a version.
            const sums = path.join(tree, 'SHA256SUMS');
            const digest = createHash('sha256').update('9.8.7 --insecure\n').digest('hex');
            fs.writeFileSync(sums, fs.readFileSync(sums, 'utf8').replace(/^[0-9a-f]{64} {2}VERSION$/m, `${digest}  VERSION`));
            fs.writeFileSync(stubLog, '');
            const relisted = run('verify.sh', [], true);
            expect(relisted.status).toBe(1);
            expect(relisted.stderr).toBe('verify: VERSION does not hold a version\n');
            expect(fs.readFileSync(stubLog, 'utf8')).toBe('');
        });
    });

    it('the containerd path gives the imported image the name the chart asks for', () => {
        // The archive holds the per-architecture reference; without the tag step a pod with pullPolicy Never cannot start.
        const readme = read('deploy/airgap/README.md');
        const chartImage = `${(yaml.load(read(`${CHART}/values.yaml`)) as Json).image.repository}:<version>`;
        expect(chartImage).toBe(`${IMAGE_REPOSITORY}:<version>`);
        const importAt = readme.indexOf('ctr -n k8s.io images import images/scanent-<version>-linux-<arch>.tar');
        const tagAt = readme.indexOf(`ctr -n k8s.io images tag "$ref" ${chartImage}`);
        expect(importAt).toBeGreaterThan(-1);
        expect(tagAt).toBeGreaterThan(importAt);
        // `$ref` is read from the file build-bundle.sh writes, by the column load.sh reads it from.
        expect(readme).toContain(`ref="$(awk -v a=<arch> '$1 == a { print $3 }' images/IMAGES)"`);
        expect(build(path.join(work, 'out')).status).toBe(0);
        const images = fs.readFileSync(path.join(work, 'out', `scanent-${VERSION}-airgap`, 'images/IMAGES'), 'utf8');
        expect(images.split('\n')[0].split(' ')).toEqual(['amd64', `images/scanent-${VERSION}-linux-amd64.tar`, AMD]);
    });

    it('the quick start and the overlay set the Compose variables once, so the next compose command still has them', () => {
        const quick = read('docs/quick-start.md');
        // A variable given as a prefix of one command is gone for the next: `docker compose logs` then cannot read the file.
        expect(quick).not.toMatch(/^SCANENT_VERSION=\S+ .*docker compose/m);
        expect(quick).toContain('export SCANENT_VERSION=0.12.0 SCANENT_UID="$(id -u)" SCANENT_GID="$(id -g)"\ndocker compose up -d\ndocker compose logs');
        expect(read('docs/deployment.md')).not.toMatch(/^SCANENT_VERSION=\S+ docker compose/m);
        // Step 6 says a code source needs its roots mounted, and what a read estate looks like in the log.
        expect(quick).toMatch(/add each\s+root under the service's `volumes:`/);
        expect(read('deploy/compose.yaml')).toContain('# - /srv/agents:/estate:ro');
        expect(quick).toContain('"status":"COMPLETE"');
    });

    it('load.sh and verify.sh are POSIX sh, executable in the repository, and need no network tool', () => {
        for (const script of ['deploy/airgap/load.sh', 'deploy/airgap/verify.sh']) {
            const text = read(script);
            expect(text.startsWith('#!/bin/sh\n')).toBe(true);
            expect(text).not.toMatch(/\b(curl|wget|pull)\b|\[\[|<<<|\bfunction\b/);
            expect(execFileSync('git', ['ls-files', '-s', script], { cwd: REPO_ROOT, encoding: 'utf8' })).toMatch(/^100755 /);
        }
        expect(execFileSync('git', ['ls-files', '-s', 'deploy/airgap/build-bundle.sh'], { cwd: REPO_ROOT, encoding: 'utf8' })).toMatch(/^100755 /);
        const code = read('deploy/airgap/build-bundle.sh')
            .split('\n')
            .filter((line) => !line.trimStart().startsWith('#'))
            .join('\n');
        expect(code).not.toMatch(/\b(curl|wget)\b|docker (pull|push|build)|"\$RUNTIME" (pull|push|build)/);
        // The signing script is held to the same: executable, no network tool, and no container runtime at all.
        expect(execFileSync('git', ['ls-files', '-s', 'deploy/airgap/sign-bundle.sh'], { cwd: REPO_ROOT, encoding: 'utf8' })).toMatch(/^100755 /);
        const signCode = read('deploy/airgap/sign-bundle.sh')
            .split('\n')
            .filter((line) => !line.trimStart().startsWith('#'))
            .join('\n');
        expect(signCode).not.toMatch(/\b(curl|wget|docker|podman|nerdctl|cosign)\b/);
    });
});

// ───────────────────────────── the workflows and the smoke test ─────────────────────────────

describe('the release workflow', () => {
    const release = yaml.load(read('.github/workflows/release.yml')) as Json;
    const ci = yaml.load(read('.github/workflows/ci.yml')) as Json;
    const steps = (job: Json): Json[] => job.steps as Json[];
    const scripts = (job: Json): string => steps(job).map((s) => (s.run as string | undefined) ?? '').join('\n');

    it('runs on a version tag or by hand, and publishes only from a tag', () => {
        // js-yaml reads the bare key `on` as the boolean true.
        const on = (release.on ?? release.true) as Json;
        expect(Object.keys(on).sort()).toEqual(['push', 'workflow_dispatch']);
        expect(on.push).toEqual({ tags: ['v*.*.*'] });
        // A PUSHED tag (the review): a manual run on a tag ref, which is also ref_type tag, pushes nothing.
        expect(release.jobs.publish.if).toBe("github.event_name == 'push' && github.ref_type == 'tag'");
        expect(release.jobs.release.if).toBe(release.jobs.publish.if);
        // The contract package is published under the same condition, and packed and checked on every run.
        expect(release.jobs['publish-contract'].if).toBe(release.jobs.publish.if);
        expect(release.jobs['contract-package'].if).toBeUndefined();
    });

    it('may read the repository everywhere and write packages in the two publishing jobs alone', () => {
        expect(release.permissions).toEqual({ contents: 'read' });
        // Phase 4: keyless signing needs the job's identity token, and the provenance attestation its own permission.
        expect(release.jobs.publish.permissions).toEqual({ contents: 'read', packages: 'write', 'id-token': 'write', attestations: 'write' });
        expect(release.jobs.build.permissions).toBeUndefined();
        // The Phase 4 review: `bundle` runs the repository's scripts on a manual run from any branch, so it holds no
        // identity token at all. The list of checksums is signed by `sign-bundle`, which exists for that and runs
        // for a pushed tag only. (`bundle` held `id-token: write` here before, with step conditions keeping it unused.)
        expect(release.jobs.bundle.permissions).toEqual({ contents: 'read' });
        expect(release.jobs['sign-bundle'].permissions).toEqual({ contents: 'read', 'id-token': 'write', attestations: 'write' });
        expect(release.jobs.gates.permissions).toBeUndefined();
        // The identity token exists only in jobs that run for a pushed tag and for nothing else.
        for (const [name, job] of Object.entries(release.jobs as Record<string, Json>)) {
            const granted = (job.permissions ?? {}) as Record<string, string>;
            if (granted['id-token'] !== undefined || granted.attestations !== undefined) {
                // `publish-contract` joined with the contract package: it attests the tarball it publishes.
                expect(['publish', 'sign-bundle', 'publish-contract']).toContain(name);
                expect(job.if).toBe("github.event_name == 'push' && github.ref_type == 'tag'");
            }
        }
        // No job but `publish` (the image) and `publish-contract` (the npm package) may write a package, and none
        // may write the repository's contents but `release`.
        for (const [name, job] of Object.entries(release.jobs as Record<string, Json>)) {
            const granted = (job.permissions ?? {}) as Record<string, string>;
            if (name !== 'publish' && name !== 'publish-contract') expect(granted.packages).toBeUndefined();
            if (name !== 'release') expect(granted.contents ?? 'read').toBe('read');
            for (const scope of Object.keys(granted)) expect(['contents', 'packages', 'id-token', 'attestations']).toContain(scope);
        }
        // `release` is new with the review: the one job that may write a release, and it may write nothing else.
        // The Phase 4 review added `gates` (what main is held to, before anything is built) and `sign-bundle`.
        // The contract package added two: `contract-package` packs and checks with no more than a read of the
        // repository, and `publish-contract` holds what `publish` holds and publishes that tarball.
        expect(Object.keys(release.jobs)).toEqual(['gates', 'build', 'publish', 'bundle', 'sign-bundle', 'contract-package', 'publish-contract', 'release']);
        expect(release.jobs['contract-package'].permissions).toEqual({ contents: 'read' });
        expect(release.jobs['publish-contract'].permissions).toEqual(release.jobs.publish.permissions);
        expect(release.jobs.release.permissions).toEqual({ contents: 'write' });
        expect(ci.permissions).toEqual({ contents: 'read' });
    });

    it('builds each architecture on a runner of that architecture, and smoke-tests and scans it before it is saved', () => {
        expect(release.jobs.build.strategy.matrix.include).toEqual([
            { arch: 'amd64', runner: 'ubuntu-24.04' },
            { arch: 'arm64', runner: 'ubuntu-24.04-arm' },
        ]);
        const names = steps(release.jobs.build).map((s) => (s.name as string | undefined) ?? (s.uses as string));
        const at = (needle: string) => names.findIndex((n) => n.includes(needle));
        expect(at('Build the image')).toBeGreaterThan(at('Version'));
        expect(at('Smoke-test')).toBeGreaterThan(at('Build the image'));
        expect(at('Trivy')).toBeGreaterThan(at('Smoke-test'));
        expect(at('Save the image')).toBeGreaterThan(at('Trivy'));
        const build = scripts(release.jobs.build);
        expect(build).toContain('docker build --provenance=false --sbom=false -f deploy/Dockerfile');
        expect(build).toContain('deploy/smoke.sh');
        // No emulation: nothing sets up QEMU or builds for a platform other than the runner's.
        expect(read('.github/workflows/release.yml')).not.toMatch(/qemu|--platform/i);
    });

    it('fails when the tag is not the scanner version, and reads that version the way this test does', () => {
        const version = scripts(release.jobs.build);
        expect(version).toContain('"$REF_NAME" != "v$version"');
        // The two reads the workflow makes, run here as it runs them.
        const commands = [...version.matchAll(/^\s*(version|chart)="\$\((sed .*)\)"$/gm)].map((m) => [m[1], m[2]]);
        expect(commands.map(([name]) => name)).toEqual(['version', 'chart']);
        for (const [, command] of commands) {
            expect(execFileSync('sh', ['-c', command], { cwd: REPO_ROOT, encoding: 'utf8' }).trim()).toBe(SCANNER_VERSION);
        }
    });

    it('pushes the images it tested, one manifest over exactly two architectures, and never latest', () => {
        const publish = scripts(release.jobs.publish);
        expect(publish).toContain('docker load -i');
        expect(publish).not.toMatch(/docker build /);
        expect(publish).toContain('docker buildx imagetools create');
        expect(publish).toContain('[ "$platforms" = "linux/amd64,linux/arm64" ]');
        expect(publish).toContain('--password-stdin');
        expect(read('.github/workflows/release.yml')).not.toMatch(/:latest|-t "?\$\{IMAGE_REPOSITORY\}:latest/);
        expect(release.env.IMAGE_REPOSITORY).toBe(IMAGE_REPOSITORY);
    });

    it('never pushes a version twice, and publishes only once the bundle check has passed', () => {
        // `sign-bundle` joined the list with the Phase 4 review: it is the job that checks the bundle a site receives.
        expect(release.jobs.publish.needs).toEqual(['build', 'bundle', 'sign-bundle']);
        const names = steps(release.jobs.publish).map((s) => (s.name as string | undefined) ?? '');
        const at = (needle: string) => names.findIndex((n) => n.includes(needle));
        expect(at('already published')).toBeGreaterThan(at('Log in'));
        expect(at('Push each')).toBeGreaterThan(at('already published'));
        const refuse = steps(release.jobs.publish)[at('already published')].run as string;
        expect(refuse).toContain('docker buildx imagetools inspect "${IMAGE_REPOSITORY}:${VERSION}"');
        expect(refuse).toContain('exit 1');
    });

    it('releases the bundle and the checksum the documents tell a site to compare', () => {
        const job = release.jobs.release;
        // `publish-contract` joined the list with the contract package: a release names what was published, all of it.
        expect(job.needs).toEqual(['build', 'bundle', 'sign-bundle', 'publish', 'publish-contract']);
        // The artifact it attaches is the one the signing job checked and uploaded: the signed bundle, never the unsigned one.
        const upload = steps(release.jobs['sign-bundle']).find((s) => String(s.name ?? '') === 'Upload the bundle');
        expect(upload?.with.name).toBe('scanent-${{ needs.build.outputs.version }}-airgap');
        const unsigned = steps(release.jobs.bundle).find((s) => String(s.uses ?? '').startsWith('actions/upload-artifact'));
        expect(unsigned?.with.name).toBe('scanent-${{ needs.build.outputs.version }}-airgap-unsigned');
        const download = steps(job).find((s) => String(s.uses ?? '').startsWith('actions/download-artifact'));
        expect(download?.with.name).toBe(upload?.with.name);
        const text = scripts(job);
        expect(text).toContain('sha256sum "scanent-${VERSION}-airgap.tar" > "scanent-${VERSION}-airgap.tar.sha256"');
        expect(text).toMatch(/gh release create "\$REF_NAME" --verify-tag[\s\S]*"scanent-\$\{VERSION\}-airgap\.tar" "scanent-\$\{VERSION\}-airgap\.tar\.sha256"/);
        // No third-party action, and the token is the job's own. (Four downloads: the bundle, its signed checksums, the SBOMs,
        // and, since the Phase 4 review, the provenance attestations.)
        expect(steps(job).filter((s) => s.uses !== undefined).map((s) => String(s.uses).split('@')[0])).toEqual([
            'actions/download-artifact',
            'actions/download-artifact',
            'actions/download-artifact',
            'actions/download-artifact',
        ]);
        // The release also carries each image's SBOM and the signed list of the bundle's checksums, named by version.
        const create = text.slice(text.indexOf('gh release create'));
        for (const file of [
            '"scanent-${VERSION}-linux-amd64.cdx.json"',
            '"scanent-${VERSION}-linux-arm64.cdx.json"',
            '"scanent-${VERSION}-airgap.SHA256SUMS"',
            '"scanent-${VERSION}-airgap.SHA256SUMS.sigstore.json"',
            // Provenance for everything a client runs or loads: the manifest, each architecture's image, the bundle.
            '"provenance/scanent-${VERSION}-image.provenance.jsonl"',
            '"provenance/scanent-${VERSION}-linux-amd64.provenance.jsonl"',
            '"provenance/scanent-${VERSION}-linux-arm64.provenance.jsonl"',
            '"provenance/scanent-${VERSION}-airgap.provenance.jsonl"',
        ]) {
            expect(create).toContain(file);
        }
        expect(text).toContain('for name in image linux-amd64 linux-arm64 airgap; do\n  test -s "provenance/scanent-${VERSION}-${name}.provenance.jsonl"');
        expect(create).not.toMatch(/not signed|signed yet/i);
        expect(create).toContain('docs/verify-a-release.md');
        // Both documents now say where that checksum is.
        expect(read('deploy/airgap/README.md')).toContain('scanent-<version>-airgap.tar.sha256');
        expect(read('docs/deployment.md')).toContain('scanent-<version>-airgap.tar.sha256');
    });

    it('checks the bundle the way a site receives it: unpack, verify, load, then scan with what was loaded', () => {
        const bundle = scripts(release.jobs.bundle);
        const order = ['deploy/airgap/build-bundle.sh', 'docker image rm', 'tar -xf', './verify.sh', './load.sh', 'deploy/smoke.sh "${IMAGE_REPOSITORY}:${VERSION}"'];
        const positions = order.map((needle) => bundle.indexOf(needle));
        expect(positions.every((p) => p >= 0)).toBe(true);
        expect([...positions].sort((a, b) => a - b)).toEqual(positions);
        // And the signed one, in the job that signs it: the same order, from the archive that is released.
        const signed = scripts(release.jobs['sign-bundle']);
        const signedOrder = ['deploy/airgap/sign-bundle.sh', 'tar -xf', './verify.sh --require-signature', './load.sh --require-signature', 'deploy/smoke.sh "${IMAGE_REPOSITORY}:${VERSION}"'];
        const signedAt = signedOrder.map((needle) => signed.indexOf(needle));
        expect(signedAt.every((p) => p >= 0)).toBe(true);
        expect([...signedAt].sort((a, b) => a - b)).toEqual(signedAt);
    });

    it('holds the released commit to what main is held to, before anything is built, and refuses a tag that is not on main', () => {
        const gates = release.jobs.gates as Json;
        // Nothing is built, signed or pushed unless it passes: every other job needs it, directly or through `build`.
        expect(release.jobs.build.needs).toBe('gates');
        for (const [name, job] of Object.entries(release.jobs as Record<string, Json>)) {
            if (name === 'gates') continue;
            const needs = ([] as string[]).concat(job.needs as string | string[]);
            expect(needs.includes('gates') || needs.includes('build')).toBe(true);
        }
        expect(gates.if).toBeUndefined();
        expect(gates.needs).toBeUndefined();
        // Each gate of ci.yml's `checks` job is here, with the same command, word for word.
        const ciSteps = steps(ci.jobs.checks);
        const run = (job: Json[], name: string): string => {
            const found = job.filter((s) => s.name === name);
            expect(found).toHaveLength(1);
            return String(found[0].run);
        };
        const GATES = [
            'Install',
            'Gate: npm audit of the production dependencies (moderate and above)',
            'Gate: licences of the production dependencies',
            'Lint',
            'Type-check',
            'Build',
            'Test with coverage (gate)',
            'Reproducible build',
        ];
        for (const name of GATES) expect(run(steps(gates), name)).toBe(run(ciSteps, name));
        // In ci.yml's order, none skipped by a condition, none allowed to fail.
        const names = steps(gates).map((s) => String(s.name ?? ''));
        const at = GATES.map((name) => names.indexOf(name));
        expect([...at].sort((a, b) => a - b)).toEqual(at);
        for (const name of GATES) {
            const step = steps(gates).find((s) => s.name === name) as Json;
            expect(step.if).toBeUndefined();
            expect(step['continue-on-error']).toBeUndefined();
        }
        // ci.yml has no gate this job leaves out: every step of `checks` that runs a command is one of these, or its plain-test twin.
        const ciRuns = ciSteps.filter((s) => s.run !== undefined).map((s) => String(s.name));
        expect(ciRuns.filter((n) => !GATES.includes(n))).toEqual(['Test']);
        expect(run(ciSteps, 'Test')).toBe('npm test');
        expect(run(steps(gates), 'Test with coverage (gate)')).toBe('npm run test:coverage');

        // The commit is on main, asked of the whole history, on a pushed tag, before anything is installed.
        const checkout = steps(gates)[0];
        expect(String(checkout.uses)).toMatch(/^actions\/checkout@[0-9a-f]{40}$/);
        expect(checkout.with).toEqual({ 'persist-credentials': false, 'fetch-depth': 0 });
        const onMain = steps(gates).find((s) => s.name === 'The tagged commit is on main') as Json;
        expect(onMain.if).toBe("github.event_name == 'push' && github.ref_type == 'tag'");
        expect(onMain.run).toContain('git merge-base --is-ancestor "$GITHUB_SHA" refs/remotes/origin/main');
        // A main that could not be read is a failure, never a pass.
        expect(onMain.run).toContain('git rev-parse --verify --quiet refs/remotes/origin/main > /dev/null || {');
        expect(names.indexOf('The tagged commit is on main')).toBeLessThan(names.indexOf('Install'));
        expect(names.indexOf('The tagged commit is on main')).toBeGreaterThan(0);
    });

    it('the on-main check passes a commit main holds and refuses one it does not, in a real repository', () => {
        const onMain = steps(release.jobs.gates).find((s) => s.name === 'The tagged commit is on main') as Json;
        const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'scanent-on-main-'));
        try {
            const git = (...args: string[]): string =>
                execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false', ...args], { cwd: repo, encoding: 'utf8' }).trim();
            git('init', '-q', '-b', 'main');
            git('commit', '-q', '--allow-empty', '-m', 'one');
            const first = git('rev-parse', 'HEAD');
            git('commit', '-q', '--allow-empty', '-m', 'two');
            const head = git('rev-parse', 'HEAD');
            git('update-ref', 'refs/remotes/origin/main', head);
            git('checkout', '-q', '-b', 'side', first);
            git('commit', '-q', '--allow-empty', '-m', 'not on main');
            const side = git('rev-parse', 'HEAD');
            const check = (sha: string) => spawnSync('bash', ['-c', String(onMain.run)], { cwd: repo, encoding: 'utf8', env: { PATH: process.env.PATH ?? '', GITHUB_SHA: sha } });
            expect(check(head).status).toBe(0);
            expect(check(first).status).toBe(0);
            const refused = check(side);
            expect(refused.status).toBe(1);
            expect(refused.stderr).toContain('is not on main; a release is cut from main');
            // With no main to ask, the check fails closed.
            git('update-ref', '-d', 'refs/remotes/origin/main');
            const blind = check(head);
            expect(blind.status).toBe(1);
            expect(blind.stderr).toContain('the check cannot be made');
        } finally {
            fs.rmSync(repo, { recursive: true, force: true });
        }
    });

    it('uses only the actions ci.yml already pins, and one more from the same publisher', () => {
        const usesOf = (wf: Json): string[] =>
            Object.values(wf.jobs as Record<string, Json>)
                .flatMap((job) => steps(job))
                .map((s) => s.uses as string | undefined)
                .filter((u): u is string => u !== undefined)
                .map((u) => u.split('@')[0]);
        const known = new Set(usesOf(ci));
        const extra = [...new Set(usesOf(release))].filter((u) => !known.has(u));
        // Phase 4 adds the three a signed release needs: the SBOM generator, the cosign installer, and GitHub's provenance attestation.
        expect(extra.sort()).toEqual(['actions/attest-build-provenance', 'actions/download-artifact', 'anchore/sbom-action', 'sigstore/cosign-installer']);
    });
});

describe('what a release signs and attests', () => {
    const text = read('.github/workflows/release.yml');
    const release = yaml.load(text) as Json;
    const steps = (job: Json): Json[] => job.steps as Json[];
    const named = (job: Json, needle: string): Json => {
        const found = steps(job).filter((s) => String(s.name ?? '').includes(needle));
        expect(found).toHaveLength(1);
        return found[0];
    };
    const order = (job: Json, needles: string[]): void => {
        const names = steps(job).map((s) => String(s.name ?? s.uses ?? ''));
        const at = needles.map((n) => names.findIndex((name) => name.includes(n)));
        expect(at.every((i) => i >= 0)).toBe(true);
        expect([...at].sort((a, b) => a - b)).toEqual(at);
    };
    const TAG_ONLY = "github.event_name == 'push' && github.ref_type == 'tag'";

    it('signs by digest, never by tag: the manifest and each architecture, read from what was pushed', () => {
        const publish = release.jobs.publish as Json;
        order(publish, ['Push each', 'Create the manifest', 'Read the digests', 'Sign the manifest', 'Attest each', 'Attest the build', 'Verify the signatures', 'Log out']);
        const digests = named(publish, 'Read the digests');
        expect(digests.id).toBe('digests');
        // Read two ways, which must agree, and each is checked to be a digest before anything is signed with it.
        expect(digests.run).toContain('sha256sum index.json');
        expect(digests.run).toContain("--format '{{json .Manifest}}'");
        expect(digests.run).toContain('[ "$index" = "$named" ]');
        expect(digests.run).toContain('is_digest() { [[ "$1" =~ ^sha256:[0-9a-f]{64}$ ]]; }');
        const sign = named(publish, 'Sign the manifest');
        expect(sign.env).toEqual({ INDEX: '${{ steps.digests.outputs.index }}', AMD64: '${{ steps.digests.outputs.amd64 }}', ARM64: '${{ steps.digests.outputs.arm64 }}' });
        expect(sign.run).toContain('cosign sign --yes "${IMAGE_REPOSITORY}@${digest}"');
        // Nothing is ever signed, attested or verified by a tag.
        for (const line of text.split('\n').filter((l) => /cosign (sign|attest|verify|verify-attestation) /.test(l) && !l.trimStart().startsWith('#'))) {
            expect(line).toMatch(/"\$\{IMAGE_REPOSITORY\}@\$\{(digest|AMD64|ARM64)\}"/);
            expect(line).not.toMatch(/:\$\{VERSION\}/);
        }
        // Keyless: no key, no key reference and no secret anywhere in the workflow.
        expect(text).not.toMatch(/--key\b|COSIGN_PRIVATE_KEY|COSIGN_PASSWORD|\$\{\{\s*secrets\./);
    });

    it('makes the SBOM from the image that was tested, checks it is one, and attaches it to that image', () => {
        const build = release.jobs.build as Json;
        order(build, ['Smoke-test', 'Trivy', 'Grype', 'SBOM of the image', 'The SBOM is a CycloneDX', 'Upload the SBOM', 'Save the image']);
        const sbom = named(build, 'SBOM of the image');
        expect(String(sbom.uses)).toMatch(/^anchore\/sbom-action@[0-9a-f]{40}$/);
        expect(sbom.with).toEqual({
            image: '${{ env.IMAGE_REPOSITORY }}:${{ steps.version.outputs.version }}-${{ matrix.arch }}',
            format: 'cyclonedx-json',
            'output-file': 'sbom/${{ matrix.arch }}.cdx.json',
            'syft-version': '${{ env.SYFT_VERSION }}',
            // The action neither uploads nor publishes anything itself.
            'upload-artifact': false,
            'upload-release-assets': false,
            'dependency-snapshot': false,
        });
        expect(named(build, 'The SBOM is a CycloneDX').run).toContain('for name in zod js-yaml typescript; do');
        const attest = named(release.jobs.publish as Json, 'Attest each');
        expect(attest.run).toContain('cosign attest --yes --type cyclonedx --predicate sboms/amd64.cdx.json "${IMAGE_REPOSITORY}@${AMD64}"');
        expect(attest.run).toContain('cosign attest --yes --type cyclonedx --predicate sboms/arm64.cdx.json "${IMAGE_REPOSITORY}@${ARM64}"');
        // The tools are named by version, in one place.
        expect(release.env.COSIGN_VERSION).toMatch(/^v\d+\.\d+\.\d+$/);
        expect(release.env.SYFT_VERSION).toMatch(/^v\d+\.\d+\.\d+$/);
        // (`sign-bundle` took `bundle`'s place here with the Phase 4 review: `bundle` no longer installs cosign.)
        for (const job of [release.jobs.publish, release.jobs['sign-bundle']] as Json[]) {
            const installer = steps(job).find((s) => String(s.uses ?? '').startsWith('sigstore/cosign-installer@'));
            expect(installer?.with).toEqual({ 'cosign-release': '${{ env.COSIGN_VERSION }}' });
        }
        expect(steps(release.jobs.bundle).some((s) => String(s.uses ?? '').startsWith('sigstore/cosign-installer@'))).toBe(false);
    });

    it('attests provenance for the pushed manifest, and the images stay plain manifests', () => {
        const provenance = named(release.jobs.publish as Json, 'Attest the build');
        expect(String(provenance.uses)).toMatch(/^actions\/attest-build-provenance@[0-9a-f]{40}$/);
        expect(provenance.with).toEqual({ 'subject-name': '${{ env.IMAGE_REPOSITORY }}', 'subject-digest': '${{ steps.digests.outputs.index }}', 'push-to-registry': true });
        expect(text).toContain('docker build --provenance=false --sbom=false');
    });

    it('attests provenance for each architecture\'s image and for the bundle too, and keeps each attestation for the release', () => {
        const publish = release.jobs.publish as Json;
        for (const arch of ['amd64', 'arm64']) {
            const step = named(publish, `Attest the ${arch} image's provenance`);
            expect(String(step.uses)).toBe(String(named(publish, 'Attest the build').uses));
            expect(step.with).toEqual({ 'subject-name': '${{ env.IMAGE_REPOSITORY }}', 'subject-digest': `\${{ steps.digests.outputs.${arch} }}`, 'push-to-registry': true });
        }
        order(publish, ['Sign the manifest', 'Attest the build', 'Attest the amd64', 'Attest the arm64', 'Keep the provenance', 'Upload the provenance', 'Verify the signatures']);
        const keep = named(publish, 'Keep the provenance attestations');
        // Three files, each from its own step's output, and a missing one stops the release.
        for (const id of ['provenance-index', 'provenance-amd64', 'provenance-arm64']) expect(JSON.stringify(keep.env)).toContain(`steps.${id}.outputs.bundle-path`);
        expect(keep.run).toContain('[ "$(find provenance -type f -size +0 | wc -l)" -eq 3 ]');

        const sign = release.jobs['sign-bundle'] as Json;
        const bundleProvenance = named(sign, "Attest the bundle's provenance");
        expect(String(bundleProvenance.uses)).toBe(String(named(publish, 'Attest the build').uses));
        // The subject is the archive that is released: the signed one, after it was checked.
        expect(bundleProvenance.with).toEqual({ 'subject-path': 'bundle-out/scanent-${{ needs.build.outputs.version }}-airgap.tar' });
        order(sign, ['Sign the bundle', 'Unpack, verify and load', "Attest the bundle's provenance", 'Keep the provenance', 'Upload the bundle']);
    });

    it('verifies its own signatures with the identity the documents give, before it logs out', () => {
        const verify = named(release.jobs.publish as Json, 'Verify the signatures');
        expect(verify.run).toContain('identity="https://github.com/${GITHUB_REPOSITORY}/.github/workflows/release.yml@refs/tags/v${VERSION}"');
        expect(verify.run).toContain('issuer="https://token.actions.githubusercontent.com"');
        expect(verify.run).toContain('cosign verify "${IMAGE_REPOSITORY}@${digest}" --certificate-identity "$identity" --certificate-oidc-issuer "$issuer"');
        expect(verify.run).toContain('cosign verify-attestation --type cyclonedx "${IMAGE_REPOSITORY}@${digest}" --certificate-identity "$identity" --certificate-oidc-issuer "$issuer"');
    });

    it('signs the bundle\'s list of checksums on a pushed tag only, and requires the signature when it checks that bundle', () => {
        // What this held of the `bundle` job's tag-only steps, it now holds of the `sign-bundle` job, which is tag-only
        // as a whole: the same signing command, the same test that a signature was written, the same required check.
        const bundle = release.jobs.bundle as Json;
        const sign = release.jobs['sign-bundle'] as Json;
        expect(sign.if).toBe(TAG_ONLY);
        expect(sign.needs).toEqual(['build', 'bundle']);
        const installer = steps(sign).find((s) => String(s.uses ?? '').startsWith('sigstore/cosign-installer@'));
        expect(installer?.if).toBeUndefined();
        const build = named(bundle, 'Build the bundle');
        expect(build.run).toContain('export SCANENT_SBOM_DIR="$PWD/sboms"');
        // The job with no identity signs nothing, and says the bundle it made carries no signature.
        expect(JSON.stringify(bundle)).not.toMatch(/cosign|SCANENT_SIGN_CMD|id-token/);
        expect(build.run).toContain('test ! -e "bundle-out/scanent-${VERSION}-airgap/signatures"');
        expect(named(bundle, 'Unpack, verify and load').run).toMatch(/\.\/verify\.sh --unsigned\n\s*\.\/load\.sh --unsigned\n/);
        const signing = named(sign, 'Sign the bundle');
        expect(signing.run).toContain('export SCANENT_SIGN_CMD="cosign sign-blob --yes --bundle"');
        expect(signing.run).toContain('deploy/airgap/sign-bundle.sh "unsigned/scanent-${VERSION}-airgap.tar" bundle-out');
        expect(signing.run).toContain('test -s "bundle-out/scanent-${VERSION}-airgap/signatures/SHA256SUMS.sigstore.json"');
        const check = named(sign, 'Unpack, verify and load');
        expect(check.run).toMatch(/\.\/verify\.sh --require-signature\n\s*\.\/load\.sh --require-signature\n/);
        expect(check.run).not.toMatch(/--unsigned|--no-signature/);
        expect(named(sign, 'Upload the signed checksums').if).toBeUndefined();
        // What it signs is what `bundle` checked and uploaded.
        const unsigned = steps(bundle).find((s) => String(s.uses ?? '').startsWith('actions/upload-artifact')) as Json;
        const download = steps(sign).find((s) => String(s.uses ?? '').startsWith('actions/download-artifact')) as Json;
        expect(download.with.name).toBe(unsigned.with.name);
        // A manual run signs nothing: every use of cosign is in a job that runs on a pushed tag only.
        expect(release.jobs.publish.if).toBe(TAG_ONLY);
        for (const [name, job] of Object.entries(release.jobs as Record<string, Json>)) {
            if (JSON.stringify(job).includes('cosign')) expect([name, job.if]).toEqual([name, TAG_ONLY]);
        }
    });

    it('verify.sh, the workflow and the document name one identity', () => {
        const identity = 'https://github.com/RodnaPamet/scanent/.github/workflows/release.yml@refs/tags/v';
        expect(read('deploy/airgap/verify.sh')).toContain(`identity="${identity}$version"`);
        const doc = read('docs/verify-a-release.md');
        expect(doc).toContain(`--certificate-identity "${identity}<version>"`);
        expect(doc).toContain(`IDENTITY="${identity}$VERSION"`);
        expect(doc).toContain('--certificate-oidc-issuer "https://token.actions.githubusercontent.com"');
        // The path in the identity is this workflow's own file, and the tag is the pattern it runs on.
        expect(fs.existsSync(abs('.github/workflows/release.yml'))).toBe(true);
        const on = (release.on ?? release.true) as Json;
        expect(on.push.tags).toEqual(['v*.*.*']);
        expect(release.name).toBe('Release');
        // The repository in the identity is this one, as the image's own name spells it, case apart.
        expect(identity.toLowerCase()).toContain(IMAGE_REPOSITORY.replace('ghcr.io/', 'github.com/'));
        // Every command the document gives verifies by that identity: none trusts any workflow, or any tag.
        expect(doc).not.toMatch(/certificate-identity-regexp|certificate-oidc-issuer-regexp/);
        for (const command of ['cosign verify ', 'cosign verify-attestation ', 'cosign verify-blob ', 'gh attestation verify ']) expect(doc).toContain(command);
    });
});

describe('the CI gates', () => {
    const text = read('.github/workflows/ci.yml');
    const ci = yaml.load(text) as Json;
    const steps = (job: Json): Json[] => job.steps as Json[];
    const runOf = (job: Json): string => steps(job).map((s) => String(s.run ?? '')).join('\n');

    it('has these jobs, runs on pull requests, pushes to main and weekly, and may only read', () => {
        expect(Object.keys(ci.jobs)).toEqual(['checks', 'image', 'image-podman', 'chart', 'chart-install']);
        const on = (ci.on ?? ci.true) as Json;
        expect(Object.keys(on).sort()).toEqual(['pull_request', 'push', 'schedule']);
        expect(on.push).toEqual({ branches: ['main'] });
        expect(ci.permissions).toEqual({ contents: 'read' });
        for (const job of Object.values(ci.jobs as Record<string, Json>)) expect(job.permissions).toBeUndefined();
        // Nothing is pushed anywhere, and no registry is logged in to.
        expect(text).not.toMatch(/docker push|docker login|podman push|imagetools create|gh release|cosign sign/);
    });

    it('audits and licence-checks the production dependencies before anything is built, and fails closed', () => {
        const names = steps(ci.jobs.checks).map((s) => String(s.name ?? s.uses));
        const at = (needle: string) => names.findIndex((n) => n.includes(needle));
        expect(at('npm audit')).toBeGreaterThan(at('Install'));
        expect(at('licences')).toBeGreaterThan(at('Install'));
        expect(at('Lint')).toBeGreaterThan(at('licences'));
        const audit = steps(ci.jobs.checks)[at('npm audit')].run as string;
        expect(audit).toContain('npm audit --omit=dev --audit-level=moderate --json > audit.json');
        expect(audit).toContain('for attempt in 1 2 3 4; do');
        // No report after the retries is a failure, not a pass.
        expect(audit).toMatch(/the gate fails closed" >&2\n\s*cat audit\.err >&2 \|\| true\n\s*exit 1\s*$/);
        expect(steps(ci.jobs.checks)[at('licences')].run).toBe('node scripts/check-licences.js');
        expect(runOf(ci.jobs.checks)).toContain('node scripts/check-reproducible-build.js');
    });

    it('scans the image with two scanners, both blocking, on fixed findings of high severity and above', () => {
        for (const wf of [ci, yaml.load(read('.github/workflows/release.yml')) as Json]) {
            const job = (wf.jobs.image ?? wf.jobs.build) as Json;
            const trivy = steps(job).find((s) => String(s.uses ?? '').startsWith('aquasecurity/trivy-action@'));
            expect(trivy?.with).toMatchObject({ 'exit-code': '1', severity: 'CRITICAL,HIGH', 'ignore-unfixed': true });
            const grype = steps(job).find((s) => String(s.uses ?? '').startsWith('anchore/scan-action@'));
            expect(grype?.with).toMatchObject({ 'fail-build': true, 'severity-cutoff': 'high', 'only-fixed': true });
            expect(String(grype?.with['grype-version'])).toMatch(/^v\d+\.\d+\.\d+$/);
            for (const step of [trivy, grype]) expect(step?.['continue-on-error']).toBeUndefined();
        }
    });

    it('no step of any workflow is allowed to fail quietly', () => {
        for (const file of fs.readdirSync(abs('.github/workflows'))) {
            expect(read(`.github/workflows/${file}`)).not.toMatch(/continue-on-error/);
        }
    });

    it('runs the smoke test under Podman as the invoking user, and says which step that run leaves out', () => {
        const job = ci.jobs['image-podman'] as Json;
        const smoke = steps(job).find((s) => String(s.run ?? '').includes('deploy/smoke.sh'));
        expect(smoke?.env).toEqual({ CONTAINER_RUNTIME: 'podman', SMOKE_SKIP_COMPOSE: '1' });
        expect(runOf(job)).toContain('docker save "${DOCKER_REF}" | podman load');
        // The Docker job leaves nothing out.
        const docker = steps(ci.jobs.image).find((s) => String(s.run ?? '').includes('deploy/smoke.sh'));
        expect(docker?.env).toBeUndefined();
    });

    it('installs the chart on kind from an image built in the job, with the kind version pinned', () => {
        const job = ci.jobs['chart-install'] as Json;
        const kind = steps(job).find((s) => String(s.uses ?? '').startsWith('helm/kind-action@'));
        expect(kind?.with).toEqual({ version: expect.stringMatching(/^v\d+\.\d+\.\d+$/), cluster_name: 'scanent', wait: '120s' });
        const text = runOf(job);
        expect(text).toContain('docker build -f deploy/Dockerfile -t "${IMAGE_REPOSITORY}:${IMAGE_TAG}" .');
        expect(text).toContain('kind load docker-image "${IMAGE_REPOSITORY}:${IMAGE_TAG}" --name scanent');
        expect(text).toContain('deploy/kind-test.sh "${IMAGE_REPOSITORY}" "${IMAGE_TAG}"');
        // Registry-less: the image name cannot be pulled from anywhere.
        expect(job.env.IMAGE_REPOSITORY).toBe('scanent');
    });
});

describe('the other workflows', () => {
    const load = (name: string): Json => yaml.load(read(`.github/workflows/${name}`)) as Json;

    it('are exactly these five', () => {
        expect(fs.readdirSync(abs('.github/workflows')).sort()).toEqual(['ci.yml', 'codeql.yml', 'long-tests.yml', 'release.yml', 'scorecard.yml']);
    });

    it('CodeQL analyses the TypeScript on pull requests, pushes to main and weekly, and may write security events only', () => {
        const wf = load('codeql.yml');
        const on = (wf.on ?? wf.true) as Json;
        expect(Object.keys(on).sort()).toEqual(['pull_request', 'push', 'schedule']);
        expect(wf.permissions).toEqual({ contents: 'read' });
        expect(wf.jobs.analyze.permissions).toEqual({ contents: 'read', 'security-events': 'write' });
        const init = (wf.jobs.analyze.steps as Json[]).find((s) => String(s.uses ?? '').startsWith('github/codeql-action/init@'));
        expect(init?.with).toMatchObject({ languages: 'javascript-typescript', 'build-mode': 'none' });
        expect((wf.jobs.analyze.steps as Json[]).some((s) => String(s.uses ?? '').startsWith('github/codeql-action/analyze@'))).toBe(true);
    });

    it('Scorecard runs weekly and on main, publishes nothing, and may write security events only', () => {
        const wf = load('scorecard.yml');
        const on = (wf.on ?? wf.true) as Json;
        expect(Object.keys(on).sort()).toEqual(['push', 'schedule']);
        expect(wf.permissions).toEqual({});
        expect(wf.jobs.analysis.permissions).toEqual({ contents: 'read', actions: 'read', 'security-events': 'write' });
        const scorecard = (wf.jobs.analysis.steps as Json[]).find((s) => String(s.uses ?? '').startsWith('ossf/scorecard-action@'));
        // Publishing is the owner's decision, and would also need id-token: write.
        expect(scorecard?.with).toEqual({ results_file: 'results.sarif', results_format: 'sarif', publish_results: false });
    });

    it('the long tests run by hand and weekly, never on a pull request or a push, and may only read', () => {
        const wf = load('long-tests.yml');
        const on = (wf.on ?? wf.true) as Json;
        expect(Object.keys(on).sort()).toEqual(['schedule', 'workflow_dispatch']);
        expect(wf.permissions).toEqual({ contents: 'read' });
        const run = (wf.jobs.long.steps as Json[]).map((s) => String(s.run ?? '')).join('\n');
        expect(run).toContain('npm run test:long');
        const scripts = (JSON.parse(read('package.json')) as { scripts: Record<string, string> }).scripts;
        expect(scripts['test:long']).toContain('SCANENT_LONG=1');
        // And `npm test`, which CI's normal job runs, does not set it.
        expect(scripts.test).toBe('jest');
        expect(read('.github/workflows/ci.yml')).not.toMatch(/SCANENT_LONG|test:long\b(?! )/);
        // A seed typed into the form reaches the tests as a value of the environment, never as script text.
        expect(wf.jobs.long.env.FUZZ_SEED).toBe("${{ github.event_name == 'schedule' && github.run_id || inputs.seed }}");
        expect(run).not.toContain('${{');
    });

    it('no workflow puts an expression of the event inside a script', () => {
        for (const file of fs.readdirSync(abs('.github/workflows'))) {
            const wf = load(file);
            for (const job of Object.values(wf.jobs as Record<string, Json>)) {
                for (const step of job.steps as Json[]) {
                    // `${{ }}` belongs in `env:` and `with:`. In a script it is text the shell would run.
                    expect(`${file}: ${String(step.run ?? '').includes('${{')}`).toBe(`${file}: false`);
                }
            }
        }
    });
});

describe('deploy/kind-test.sh', () => {
    const script = read('deploy/kind-test.sh');

    it('is executable, pulls and pushes nothing, and installs the chart with the code-only values and the image it is given', () => {
        expect(execFileSync('git', ['ls-files', '-s', 'deploy/kind-test.sh'], { cwd: REPO_ROOT, encoding: 'utf8' })).toMatch(/^100755 /);
        expect(script).not.toMatch(/\b(curl|wget)\b|docker (pull|push|build)|helm (push|repo)|kubectl (cp|exec)\b/);
        expect(script).toContain('helm install scanent "$CHART" --namespace "$NS" -f "$CHART/ci/base-values.yaml"');
        expect(script).toContain('--set image.repository="$REPOSITORY" --set image.tag="$TAG" --set image.pullPolicy=Never --set strict=true');
        // The names it relies on are the ones the base values give.
        const base = yaml.load(read(`${CHART}/ci/base-values.yaml`)) as Json;
        expect(script).toContain(`kubectl -n "$NS" create secret generic ${base.secrets.existingSecret} --from-file=signing-key.pem=`);
        expect(script).toContain(`name: ${base.codeRoots[0].existingClaim}\n`);
        expect(script).toContain(`"${base.codeRoots[0].existingClaim}:${base.codeRoots[0].mountPath}"`);
    });

    it('makes the signing key with scanent keygen, and leaves no copy of it behind', () => {
        expect(script).toMatch(/"\$IMAGE" keygen --out \/key\/signing-key\.pem/);
        expect(script).toContain('rm -f "$WORK/key/signing-key.pem"');
        expect(script).toContain('docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges');
    });

    it('has the five steps, in order, and the probe that proves nothing fails', () => {
        expect([...script.matchAll(/^echo "== (\d+)\. /gm)].map((m) => Number(m[1]))).toEqual([1, 2, 3, 4, 5]);
        expect(script).toContain('so the probe proves nothing"');
        expect(script).toContain('the NetworkPolicy is not enforced here"');
        // A cluster that does not enforce policy is said, never passed.
        expect(script).toContain('echo "SKIPPED the NetworkPolicy was NOT tested');
        // The labels the probe carries are the ones the chart's policy selects.
        const helpers = read(`${CHART}/templates/_helpers.tpl`);
        expect(helpers).toContain('app.kubernetes.io/name: {{ include "scanent.name" . }}');
        expect(helpers).toContain('app.kubernetes.io/instance: {{ .Release.Name }}');
        expect(script).toContain('app.kubernetes.io/name: scanent\n    app.kubernetes.io/instance: scanent\n    app.kubernetes.io/component: scanner');
    });

    it('every pod it starts runs non-root, read-only, with nothing added, from the image it was given', () => {
        expect(script).toContain('runAsNonRoot: true\n    runAsUser: 1000');
        expect(script).toContain('readOnlyRootFilesystem: true\n        allowPrivilegeEscalation: false\n        capabilities:\n          drop: [ALL]');
        expect(script).toContain('imagePullPolicy: Never');
        expect(script.match(/^\s+image: /gm)).toEqual(['      image: ']);
        expect(script).toContain('      image: $IMAGE\n');
    });
});

describe('the CI chart job', () => {
    const ci = yaml.load(read('.github/workflows/ci.yml')) as Json;

    it('lints the chart with every value set and runs this suite with helm required', () => {
        const job = ci.jobs.chart as Json;
        const text = (job.steps as Json[]).map((s) => (s.run as string | undefined) ?? '').join('\n');
        expect(text).toContain('helm version --short');
        expect(text).toContain('helm lint --strict');
        const sets = fs
            .readdirSync(abs(`${CHART}/ci`))
            .map((f) => f.replace('-values.yaml', ''))
            .sort();
        expect(sets).toEqual(['base', 'cilium', 'egress-proxy', 'proxy-and-ca']);
        for (const set of sets.filter((s) => s !== 'base')) expect(text).toMatch(new RegExp(`for set in [^;]*\\b${set}\\b`));
        const jest = (job.steps as Json[]).find((s) => typeof s.run === 'string' && s.run.includes('deploy-templates.test.ts'));
        expect(jest?.env).toEqual({ REQUIRE_HELM: '1' });
    });
});

describe('deploy/smoke.sh', () => {
    const smoke = read('deploy/smoke.sh');

    it('runs every container without a network, read-only, with nothing added', () => {
        // One place starts a container to test the scanner, and it carries the hardening.
        expect(smoke).toContain('"$RUNTIME" run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges "$@"');
        const starts = smoke.split('\n').filter((line) => /"\$RUNTIME" run|docker run/.test(line) && !line.trimStart().startsWith('#'));
        // Two others, neither of which runs the scanner. One removes what the image's user wrote, at exit: with the
        // image's node since Phase 4, because the image has no shell to run `rm` with. The other is the proof of
        // that: it asks for a shell, and passes only when none starts.
        expect(starts).toHaveLength(3);
        expect(starts.filter((line) => line.includes('--entrypoint node') && line.includes('rmSync(p, { recursive: true, force: true })'))).toHaveLength(1);
        expect(starts.filter((line) => line.startsWith('if "$RUNTIME" run --rm --network none --entrypoint sh "$IMAGE" -c true'))).toHaveLength(1);
        for (const line of starts) expect(line).toContain('--network none');
        expect(smoke).not.toMatch(/--privileged|--cap-add|--network host/);
    });

    it('needs nothing inside the image but node: no shell, no coreutils', () => {
        const entrypoints = [...smoke.matchAll(/--entrypoint (\S+)/g)].map((m) => m[1]);
        expect(entrypoints.length).toBeGreaterThan(8);
        // `sh` is asked for once, by the check that it is not there.
        expect(entrypoints.filter((e) => e !== 'node')).toEqual(['sh']);
        expect(smoke).not.toMatch(/--entrypoint (id|ls|cat|find|sha256sum|test)\b/);
    });

    it('step 11 runs the two Compose files a site uses, with this image, and proves the proxy is the only way out', () => {
        // The site's own files, and one more that names the image and the stand-in server.
        expect(smoke).toContain('-f "$HERE/compose.yaml" -f "$HERE/compose.egress.yaml" -f "$WORK/overlay/compose.smoke.yaml" "$@"');
        // The stand-in server runs from the image, hardened as the scanner is, on the proxy's outer network only.
        expect(smoke).toMatch(/smoke-mcp:\n {4}image: \$IMAGE\n {4}entrypoint: \["node", "\/smoke\/smoke-mcp-server\.js"\]/);
        expect(smoke).toMatch(/smoke-mcp:[\s\S]*?read_only: true\n {4}cap_drop: \[ALL\]\n {4}security_opt: \["no-new-privileges:true"\]/);
        expect(smoke).toMatch(/networks:\n {6}scanent-egress:\n {8}aliases: \[\$MCP_HOST\]/);
        // Allowed, then refused, and in between the direct route is tried and must not exist.
        const order = [
            'export EGRESS_ALLOW="$MCP_HOST"',
            '[ "$allowed" = "COMPLETE - smoke_close_ticket,smoke_lookup_ticket" ]',
            '[ "$asked" = "message initialize;message notifications/initialized;message tools/list;" ]',
            '[ "$direct" = "NO_ROUTE name=unresolved" ]',
            'export EGRESS_ALLOW=other.smoke.example',
            '[ "$refused" = "INCOMPLETE UNREACHABLE -" ]',
            '\\"msg\\":\\"egress refused\\",\\"reason\\":\\"HOST_NOT_ALLOWED\\",\\"host\\":\\"$MCP_HOST\\"',
        ];
        const at = order.map((needle) => smoke.indexOf(needle));
        expect(at.every((i) => i >= 0)).toBe(true);
        expect([...at].sort((a, b) => a - b)).toEqual(at);
        // Leaving the step out is said, never passed off as a pass.
        expect(smoke).toContain('echo "SKIPPED step 11 was left out by SMOKE_SKIP_COMPOSE=1: the egress overlay was NOT tested"');
        expect(smoke).toContain('echo "smoke: passed, without step 11"');
        expect(smoke).toContain('compose down --volumes --remove-orphans');
    });

    it('the stand-in MCP server speaks the three declared messages and refuses every other', () => {
        const server = read('deploy/smoke-mcp-server.js');
        for (const method of ['initialize', 'notifications/initialized', 'tools/list']) expect(server).toContain(`method === '${method}'`);
        expect(server).toContain("error: { code: -32601, message: 'Method not found' }");
        expect(server).not.toMatch(/tools\/call|child_process|require\('node:(net|http)'\)/);
    });

    it('scans as the invoking user into a 0700 directory and reads the run back without the container', () => {
        expect(smoke).toContain('AS_ME=(--user "$(id -u):$(id -g)")');
        // Podman needs both: `keep-id` alone leaves the image's uid 1000, which failed on a runner whose user is 1001.
        expect(smoke).toContain('AS_ME=(--userns=keep-id --user "$(id -u):$(id -g)")');
        expect(smoke).not.toContain('AS_ME=(--userns=keep-id)');
        expect(smoke).toContain('mkdir -m 0700 "$WORK/mine"');
        expect(smoke).toContain('= "750 $(id -u)"');
        expect(smoke).toContain('= "640 $(id -u)"');
        // Read back by this process, not through the image.
        expect(smoke).toMatch(/grep -q '<html' "\$WORK\/mine\/runs\/\$mine\/summary\.html"/);
    });

    it('has the eleven steps, in order', () => {
        // Ten until Phase 4; the eleventh is the MCP server through the Compose egress overlay.
        const steps = [...smoke.matchAll(/^echo "== (\d+)\. /gm)].map((m) => Number(m[1]));
        expect(steps).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    });
});
