/**
 * The integrations scanner with all three readers, Entra, Okta and GitHub, run
 * on its own and end to end against the fake estate.
 *
 *   1. One report of the three products, which the contract verifies.
 *   2. Every output says which product each application came from, and why
 *      each product leaves a question not concluded: results.json, both CSVs,
 *      the page and the PDF. The webhooks are listed by host.
 *   3. Nothing a webhook's URL carries beyond its host, nor who consented to
 *      an Okta grant, nor a secret the products return, reaches any file the
 *      run writes or the log; a secret planted in a webhook URL neither.
 *   4. A second run: the comparison names each application's product, and a
 *      product read in part concludes nothing gone.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { verifyAndParseIntegrationsReport } from '@rodnapamet/scanent-contract/integrations-contract';
import { parseRunResults } from '@scanent/report/results/schema';
import type { IntegrationsOnlyResults } from '@scanent/report/results/types';

import { parseScannerConfig, type ScannerConfig } from '../src/config';
import { runDiff } from '../src/diff-command';
import { resolveOutputs, scanAndDeliver, type DeliveryResult } from '../src/outputs';
import { rawPublicKeyHex } from '../src/report';
import { loadSigningKey } from '../src/scan';
import { OKTA_GRANT_MARKERS, OKTA_TOKEN_VALUE, oktaFixture } from './helpers/agent-harness-source-fakes';
import { SIGNING_PEM } from './helpers/doctor-world';
import {
    createEstateWorld,
    estateEnv,
    GITHUB_HOOK_MARKERS,
    GITHUB_INTEGRATIONS_TOKEN_VALUE,
    githubInstallation,
    githubOrgFixture,
    INTEGRATIONS_ESTATE_SOURCES,
    PUBLIC_RESOLVER,
    type EstateWorld,
} from './helpers/estate-world';
import { CANARIES, capturedLog, pdfTextOf } from './helpers/output-fixtures';

const NOW = Date.parse('2026-10-19T03:00:00.000Z');
const DAY = 86_400_000;
const PUBLIC = rawPublicKeyHex(loadSigningKey(SIGNING_PEM).publicKey);

const CONFIG: ScannerConfig = parseScannerConfig({
    estate: 'acme-apps',
    scanner: { agentId: 'agt_scanner_acme', signingKeyEnv: 'SCANNER_SIGNING_KEY' },
    outputs: [{ kind: 'file', dir: '/out' }],
    schedule: { everyHours: 24 },
    sources: Object.values(INTEGRATIONS_ESTATE_SOURCES),
});

let dir: string;
beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scanent-three-products-'));
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

async function scanOut(at: number, world: EstateWorld = createEstateWorld()): Promise<{ result: DeliveryResult; log: ReturnType<typeof capturedLog> }> {
    const log = capturedLog();
    const result = await scanAndDeliver({ config: CONFIG, env: estateEnv(), log: log.log, fetchImpl: world.fetchImpl, resolveHost: PUBLIC_RESOLVER, now: () => at, outputs: resolveOutputs(CONFIG, { out: dir }), loadInventory: () => null });
    expect(result.ok).toBe(true);
    return { result, log };
}

const runDir = (scanId: string) => path.join(dir, 'runs', scanId);
const read = (scanId: string, name: string) => fs.readFileSync(path.join(runDir(scanId), name), 'utf8');

/** RFC 4180 rows: each cell unquoted, a doubled quote one quote. Enough for the files the run writes. */
function csvRows(text: string): string[][] {
    const rows: string[][] = [];
    let row: string[] = [];
    let cell = '';
    let quoted = false;
    const body = text.replace(/^\uFEFF/, '');
    for (let k = 0; k < body.length; k++) {
        const ch = body[k];
        if (quoted) {
            if (ch === '"' && body[k + 1] === '"') {
                cell += '"';
                k += 1;
            } else if (ch === '"') quoted = false;
            else cell += ch;
        } else if (ch === '"') quoted = true;
        else if (ch === ',') {
            row.push(cell);
            cell = '';
        } else if (ch === '\r' && body[k + 1] === '\n') {
            row.push(cell);
            rows.push(row);
            row = [];
            cell = '';
            k += 1;
        } else cell += ch;
    }
    if (cell !== '' || row.length > 0) rows.push([...row, cell]);
    return rows;
}

/** Every file of a run as text, the PDF's text extracted. */
function filesOf(scanId: string): [string, string][] {
    return fs.readdirSync(runDir(scanId)).map((name) => {
        const bytes = fs.readFileSync(path.join(runDir(scanId), name));
        return [name, name.endsWith('.pdf') ? pdfTextOf(bytes).joined : bytes.toString('utf8')];
    });
}

describe('1. one report of three products', () => {
    it('verifies, lists each source complete, and holds each product\'s applications and the organisation\'s webhooks', async () => {
        const { result } = await scanOut(NOW);
        const parsed = verifyAndParseIntegrationsReport(result.scan.integrations?.raw ?? '', [PUBLIC]);
        expect(parsed).toMatchObject({ ok: true, complete: true });
        if (!parsed.ok) throw new Error('unreachable');
        expect(parsed.body.sources.map((s) => [s.kind, s.status, s.signInActivity.status])).toEqual([
            ['entra-integrations', 'COMPLETE', 'COMPLETE'],
            ['okta-integrations', 'COMPLETE', 'NOT_READ'],
            ['github-integrations', 'COMPLETE', 'NOT_READ'],
        ]);
        const kinds = parsed.body.applications.map((a) => a.sourceKind);
        expect(kinds.filter((k) => k === 'entra-integrations')).toHaveLength(3);
        expect(kinds.filter((k) => k === 'okta-integrations')).toHaveLength(5);
        expect(kinds.filter((k) => k === 'github-integrations')).toHaveLength(3);
        expect(parsed.body.webhooks?.hooks.map((h) => h.host)).toEqual(['hooks.chat.example', '10.20.30.40']);
    });
});

describe('2. each output names the product, and why a product leaves a question open', () => {
    it('results.json: each application in its product\'s shape, the not-exposed questions per source, the webhooks by host', async () => {
        const { result } = await scanOut(NOW);
        const json = JSON.parse(read(result.scan.scanId, 'results.json')) as IntegrationsOnlyResults;
        expect(parseRunResults(json)).toMatchObject({ ok: true });
        const i = json.integrations;
        // What each source left out on purpose, with the count: the product's own applications. GitHub leaves out nothing.
        expect(i.sources.map((x) => [x.kind, x.excluded?.count ?? null])).toEqual([
            ['entra-integrations', expect.any(Number)],
            ['okta-integrations', 3],
            ['github-integrations', null],
        ]);
        expect(i.sources[1].excluded?.what).toContain('the Okta Admin Console, the Okta End-User Dashboard and the Okta Browser Plugin');
        expect(i.sources[0].excluded?.what).toContain("Microsoft's own first-party applications");
        expect(i.notConcluded.filter((n) => n.applicationId === null && n.sourceKind !== 'entra-integrations').map((n) => `${n.sourceKind} ${n.code} ${n.why}`)).toEqual([
            'github-integrations INTEGRATION_UNVERIFIED_PUBLISHER PUBLISHER_NOT_EXPOSED',
            'github-integrations INTEGRATION_NO_OWNER OWNER_NOT_EXPOSED',
            'github-integrations INTEGRATION_UNUSED SIGN_IN_NOT_EXPOSED',
            'okta-integrations INTEGRATION_UNVERIFIED_PUBLISHER PUBLISHER_NOT_EXPOSED',
            'okta-integrations INTEGRATION_NO_OWNER OWNER_NOT_EXPOSED',
            'okta-integrations INTEGRATION_UNUSED SIGN_IN_NOT_EXPOSED',
        ]);
        expect(i.webhooks).toEqual({
            read: true,
            hooks: [
                { id: 'github:acme:hook:7', sourceKind: 'github-integrations', host: 'hooks.chat.example', events: ['pull_request', 'push'], active: true, created: '2026-01-04' },
                { id: 'github:acme:hook:8', sourceKind: 'github-integrations', host: '10.20.30.40', events: ['*'], active: false, created: '2025-12-01' },
            ],
        });
        const findings = i.findings.map((f) => `${f.code} ${f.applicationId ?? f.sourceRef}`);
        expect(findings).toContain('INTEGRATION_HIGH_PRIVILEGE_GRANT github:acme:installation:41');
        expect(findings).toContain('INTEGRATION_HIGH_PRIVILEGE_GRANT okta:acme.okta.com:app:0oaService1');
        // Okta and GitHub raise none of the three findings their APIs cannot answer.
        expect(i.findings.filter((f) => f.applicationId !== null && !f.applicationId.startsWith('entra:')).map((f) => f.code)).toEqual(
            Array(4).fill('INTEGRATION_HIGH_PRIVILEGE_GRANT'),
        );
        expect(i.unknownPermissions.filter((u) => u.via !== 'DELEGATED' && u.via !== 'APPLICATION')).toEqual([
            { via: 'GITHUB_PERMISSION', resourceAppId: null, name: 'repository_projects:read' },
            { via: 'OKTA_SCOPE', resourceAppId: null, name: 'okta.myAccount.email.read' },
        ]);
    });

    it('the CSVs: a product column on every row; a question the product does not answer is NOT_EXPOSED, never empty', async () => {
        const { result } = await scanOut(NOW);
        const [header, ...apps] = csvRows(read(result.scan.scanId, 'integrations.csv'));
        expect(header.slice(0, 3)).toEqual(['applicationId', 'product', 'displayName']);
        const col = (row: string[] | undefined, name: string) => row?.[header.indexOf(name)];
        const row = (id: string) => apps.find((r) => r[0] === id);
        const okta = row('okta:acme.okta.com:app:0oaService1');
        expect(['product', 'owners', 'publisherVerified', 'signInRead', 'lastSignIn', 'oktaScopes', 'delegatedGrantsRead'].map((c) => col(okta, c))).toEqual([
            'Okta',
            'NOT_EXPOSED',
            'NOT_EXPOSED',
            'NOT_EXPOSED',
            'NOT_EXPOSED',
            'okta.logs.read;okta.users.read',
            'n/a',
        ]);
        const github = row('github:acme:installation:41');
        expect(['product', 'displayName', 'githubPermissions', 'repositorySelection', 'status', 'credentials'].map((c) => col(github, c))).toEqual([
            'GitHub',
            'acme-deploy-bot',
            'contents:write;metadata:read;pull_requests:write',
            'selected',
            'ACTIVE',
            'n/a',
        ]);
        expect(col(row('github:acme:installation:43'), 'status')).toBe('SUSPENDED');
        expect(apps.filter((r) => r[0].startsWith('entra:')).map((r) => col(r, 'product'))).toEqual(Array(3).fill('Microsoft Entra ID'));
        // No cell a product does not answer is empty.
        for (const r of apps) for (const c of ['owners', 'publisherVerified', 'signInRead', 'origin', 'credentials']) expect([r[0], c, col(r, c) !== '']).toEqual([r[0], c, true]);
        const [fHeader, ...findings] = csvRows(read(result.scan.scanId, 'integration-findings.csv'));
        expect(fHeader.slice(0, 5)).toEqual(['code', 'severity', 'sourceRef', 'product', 'applicationId']);
        expect([...new Set(findings.map((r) => r[3]))].sort()).toEqual(['GitHub', 'Microsoft Entra ID', 'Okta']);
    });

    it('the page and the PDF: the product beside each application, the open questions under each product, the webhooks by host', async () => {
        const { result } = await scanOut(NOW);
        const page = read(result.scan.scanId, 'summary.html');
        for (const text of ['<h4>Okta</h4>', '<h4>GitHub</h4>', 'Not exposed by Okta', 'Not exposed by GitHub', 'GitHub organisation webhooks (2)', '<code>hooks.chat.example</code>', '<code>10.20.30.40</code>']) {
            expect([text, page.includes(text)]).toEqual([text, true]);
        }
        expect(page).toContain('the product&#39;s API records no owner of an application');
        expect(page).toContain('Okta: 3 applications read and left out as Okta&#39;s own apps (the Okta Admin Console');
        const pdf = pdfTextOf(fs.readFileSync(path.join(runDir(result.scan.scanId), 'report.pdf'))).joined;
        for (const text of ['GitHub organisation webhooks (2)', 'hooks.chat.example', 'Not exposed by Okta', 'OWNER_NOT_EXPOSED', 'Okta', 'read and left out as Okta']) expect([text, pdf.includes(text)]).toEqual([text, true]);
    });
});

describe('3. what never reaches an output', () => {
    it('a webhook URL beyond its host, a hook\'s secret, who consented to a grant, and every credential the run used', async () => {
        const { result, log } = await scanOut(NOW);
        const forbidden = [...Object.values(GITHUB_HOOK_MARKERS), ...Object.values(OKTA_GRANT_MARKERS), 'hooks.chat.example/services', OKTA_TOKEN_VALUE, GITHUB_INTEGRATIONS_TOKEN_VALUE, estateEnv().ENTRA_CLIENT_SECRET];
        for (const [name, text] of filesOf(result.scan.scanId)) for (const marker of forbidden) expect(`${name} ${marker}: ${text.includes(marker)}`).toBe(`${name} ${marker}: false`);
        for (const marker of forbidden) expect(log.text()).not.toContain(marker);
    });

    it.each(CANARIES)('%s in a webhook\'s URL, in its path, query or host, reaches no output', async (_name, canary) => {
        const orgs = githubOrgFixture();
        const hook = (orgs.acme.hooks[0][0] as { config: { url: string } }).config;
        hook.url = `https://hooks.chat.example/${encodeURIComponent(canary)}?k=${encodeURIComponent(canary)}`;
        (orgs.acme.hooks[0][1] as { config: { url: string } }).config.url = canary;
        const { result, log } = await scanOut(NOW, createEstateWorld({ githubOrgs: orgs }));
        for (const [name, text] of filesOf(result.scan.scanId)) {
            for (const v of [canary, encodeURIComponent(canary)]) expect(`${name}: ${text.includes(v)}`).toBe(`${name}: false`);
        }
        expect(log.text()).not.toContain(canary);
    });
});

describe('4. a second run, compared', () => {
    it('names each application\'s product, and an application of a product read in part is not concluded gone', async () => {
        const first = await scanOut(NOW);
        // A day later: an Okta app is gone, a GitHub app is installed, and GitHub rate-limits its webhooks.
        const okta = oktaFixture();
        okta.allApps = [[...(okta.allApps?.[0] ?? [])], [(okta.allApps?.[1] ?? [])[0]]];
        const orgs = githubOrgFixture();
        orgs.acme.installations[1].push(githubInstallation({ id: 44, app_slug: 'new-linter', permissions: { metadata: 'read', checks: 'write' } }));
        const later = createEstateWorld({ fakes: { okta }, githubOrgs: orgs });
        const second = await scanOut(NOW + DAY, later);
        const ids = [first.result.scan.scanId, second.result.scan.scanId];
        const out: string[] = [];
        const files = ids.map((id) => path.join(runDir(id), 'results.json'));
        runDiff(files, { stdout: (t) => void out.push(t), stderr: (t) => void out.push(t) });
        const text = out.join('');
        expect(text).toContain('new        github:acme:installation:44  [GitHub]');
        expect(text).toContain('gone       okta:acme.okta.com:app:0oaSaml1  [Okta]');
        const page = read(ids[1], 'summary.html');
        expect(page).toContain('GitHub: <code class="id">github:acme:installation:44</code>');
        expect(page).toContain('Okta: <code class="id">okta:acme.okta.com:app:0oaSaml1</code> (its source was read in full)');

        // A third run in which the Okta listing stops: its applications are not seen, and none is concluded gone.
        const third = createEstateWorld({ fakes: { okta } });
        third.inject = (req) => (req.host === 'acme.okta.com' && req.path === '/api/v1/apps' && req.query.includes('after=1') ? { status: 429, body: { errorCode: 'E0000047' }, headers: { 'x-rate-limit-remaining': '0' } } : undefined);
        const run3 = await scanOut(NOW + 2 * DAY, third);
        const out3: string[] = [];
        runDiff([files[1], path.join(runDir(run3.result.scan.scanId), 'results.json')], { stdout: (t) => void out3.push(t), stderr: (t) => void out3.push(t) });
        expect(out3.join('')).toContain('not seen   okta:acme.okta.com:app:0oaService2  [Okta]  (its source was not read in full; nothing is concluded)');
        expect(out3.join('')).not.toMatch(/gone {7}okta:/);
    });
});
