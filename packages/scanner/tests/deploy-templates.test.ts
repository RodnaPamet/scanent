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
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { looksLikeSecret } from '@scanent/contract/harness-contract-rules';
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
                'docs/quick-start.md',
                'docs/scanner.md',
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
        expect(fs.readFileSync(path.join(tree, 'sbom/README.txt'), 'utf8')).toBe('No SBOM in this bundle. Phase 4 adds one.\n');
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
    });

    describe('verify.sh and load.sh, on a built bundle', () => {
        let tree: string;
        const verify = () => sh(path.join(tree, 'verify.sh'), []);
        const load = (machine: string) => sh(path.join(tree, 'load.sh'), [], { STUB_MACHINE: machine });

        beforeEach(() => {
            expect(build(path.join(work, 'out')).status).toBe(0);
            tree = path.join(work, 'out', `scanent-${VERSION}-airgap`);
            fs.writeFileSync(stubLog, '');
        });

        it('verify passes on the bundle as built, and says how many files it checked', () => {
            const out = verify();
            expect(out.status).toBe(0);
            expect(out.stdout).toBe(`verify: ${treeFiles(tree).length - 1} files match SHA256SUMS\n`);
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
            const out = sh(path.join(tree, 'load.sh'), [], { CONTAINER_RUNTIME: 'podman' });
            expect(out.status).toBe(0);
            // The stub logs under the name `docker`; what matters is which file ran, and the hint names it.
            expect(out.stdout).toContain('podman run --rm');
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
    });

    it('may read the repository everywhere and write packages in the publishing job alone', () => {
        expect(release.permissions).toEqual({ contents: 'read' });
        expect(release.jobs.publish.permissions).toEqual({ contents: 'read', packages: 'write' });
        expect(release.jobs.build.permissions).toBeUndefined();
        expect(release.jobs.bundle.permissions).toBeUndefined();
        // `release` is new with the review: the one job that may write a release, and it may write nothing else.
        expect(Object.keys(release.jobs)).toEqual(['build', 'publish', 'bundle', 'release']);
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
        expect(release.jobs.publish.needs).toEqual(['build', 'bundle']);
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
        expect(job.needs).toEqual(['build', 'bundle', 'publish']);
        // The artifact it attaches is the one the bundle job checked and uploaded.
        const upload = steps(release.jobs.bundle).find((s) => String(s.uses ?? '').startsWith('actions/upload-artifact'));
        const download = steps(job).find((s) => String(s.uses ?? '').startsWith('actions/download-artifact'));
        expect(download?.with.name).toBe(upload?.with.name);
        const text = scripts(job);
        expect(text).toContain('sha256sum "scanent-${VERSION}-airgap.tar" > "scanent-${VERSION}-airgap.tar.sha256"');
        expect(text).toMatch(/gh release create "\$REF_NAME" --verify-tag[\s\S]*"scanent-\$\{VERSION\}-airgap\.tar" "scanent-\$\{VERSION\}-airgap\.tar\.sha256"/);
        // No third-party action, and the token is the job's own.
        expect(steps(job).filter((s) => s.uses !== undefined).map((s) => String(s.uses).split('@')[0])).toEqual(['actions/download-artifact']);
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
        expect(extra).toEqual(['actions/download-artifact']);
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
        // The other one only removes what the image's user wrote, at exit.
        expect(starts).toHaveLength(2);
        expect(starts.filter((line) => line.includes('rm -rf /out/runs'))).toHaveLength(1);
        expect(smoke).not.toMatch(/--privileged|--cap-add|--network host/);
    });

    it('scans as the invoking user into a 0700 directory and reads the run back without the container', () => {
        expect(smoke).toContain('AS_ME=(--user "$(id -u):$(id -g)")');
        expect(smoke).toContain('AS_ME=(--userns=keep-id)');
        expect(smoke).toContain('mkdir -m 0700 "$WORK/mine"');
        expect(smoke).toContain('= "750 $(id -u)"');
        expect(smoke).toContain('= "640 $(id -u)"');
        // Read back by this process, not through the image.
        expect(smoke).toMatch(/grep -q '<html' "\$WORK\/mine\/runs\/\$mine\/summary\.html"/);
    });

    it('has the ten steps, in order', () => {
        const steps = [...smoke.matchAll(/^echo "== (\d+)\. /gm)].map((m) => Number(m[1]));
        expect(steps).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    });
});
