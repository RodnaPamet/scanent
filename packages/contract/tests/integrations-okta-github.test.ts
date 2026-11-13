/**
 * Okta and GitHub in `scanent-integrations/1`: each product's own strict arm,
 * the webhooks list that reports a host and never a URL, the two
 * classification tables, and the planner's per-product answers. A report of
 * Entra alone reads as it did before either joined.
 */
import { generateKeyPairSync, sign } from 'crypto';

import { harnessSignedMessage } from '../src/harness-contract';
import {
    applicationName,
    IntegrationsReportBodyV1Schema,
    isApplicationId,
    productOfApplicationId,
    sourceKindOfApplicationId,
    verifyAndParseIntegrationsReport,
    type IntegrationsReportApplication,
} from '../src/integrations-contract';
import { INTEGRATION_NOT_CONCLUDED_WHY, planIntegrationsScan, type IntegrationsPlan } from '../src/integrations-findings';
import {
    classifyGithubPermission,
    classifyOktaScope,
    GITHUB_PERMISSION_CLASSES,
    OKTA_SCOPE_CLASSES,
    PERMISSION_CLASSES,
} from '../src/integrations-scopes';
import { application, body, githubInstallation, oktaApplication, threeProductBody, webhooks } from './helpers/integrations-bodies';

const issuesOf = (b: unknown): string[] => {
    const r = IntegrationsReportBodyV1Schema.safeParse(b);
    return r.success ? [] : r.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`);
};
const codes = (plan: IntegrationsPlan) => plan.findings.map((f) => f.code);

describe('the schema: one arm per product', () => {
    it('accepts a body of all three products, and a body of Entra alone exactly as step 1 wrote it', () => {
        expect(issuesOf(threeProductBody())).toEqual([]);
        expect(issuesOf(body())).toEqual([]);
        expect(Object.keys(body())).not.toContain('webhooks');
    });

    it('holds each arm to its own members: no Entra member on an Okta or GitHub application, and the reverse', () => {
        const okta = { ...oktaApplication(), owners: [] } as unknown as IntegrationsReportApplication;
        const github = { ...githubInstallation(), signIn: { read: false, lastSeen: null } } as unknown as IntegrationsReportApplication;
        const entra = { ...application(), scopeGrants: oktaApplication().scopeGrants } as unknown as IntegrationsReportApplication;
        for (const app of [okta, github, entra]) expect(issuesOf(threeProductBody({ applications: [app] }))).not.toEqual([]);
        // An id of one product under another's kind.
        expect(issuesOf(threeProductBody({ applications: [oktaApplication({ id: application().id })] }))).not.toEqual([]);
    });

    it('a GitHub permission is a name and a level GitHub writes; each once', () => {
        const perms = (grants: unknown) => githubInstallation({ permissions: { read: true, grants: grants as never, unreadable: 0 } });
        expect(issuesOf(threeProductBody({ applications: [perms([{ name: 'contents', level: 'owner' }])] }))).not.toEqual([]);
        expect(issuesOf(threeProductBody({ applications: [perms([{ name: 'contents', level: 'read' }, { name: 'contents', level: 'write' }])] }))).not.toEqual([]);
        expect(issuesOf(threeProductBody({ applications: [githubInstallation({ events: ['push', 'push'] })] }))).not.toEqual([]);
    });

    it('an Okta or GitHub source never claims sign-in activity', () => {
        const b = threeProductBody();
        const sources = b.sources.map((s) => (s.kind === 'okta-integrations' ? { ...s, signInActivity: { status: 'COMPLETE' as const, rows: 1 } } : s));
        expect(issuesOf({ ...b, sources })).toContainEqual(expect.stringContaining('only an Entra source reads sign-in activity'));
    });

    it('the webhooks member goes with a GitHub source, and only with one', () => {
        const b = threeProductBody();
        const { webhooks: _omit, ...withoutHooks } = b;
        void _omit;
        expect(issuesOf(withoutHooks)).toContainEqual(expect.stringContaining('the webhooks member goes with'));
        expect(issuesOf(body({ webhooks: webhooks() }))).toContainEqual(expect.stringContaining('the webhooks member goes with'));
        const hook = webhooks().hooks[0];
        expect(issuesOf(threeProductBody({ webhooks: webhooks({ hooks: [hook, hook] }) }))).toContainEqual(expect.stringContaining('a webhook id appears once'));
    });

    it('a webhook carries a host and never a URL, a path, a query or a secret', () => {
        const withHost = (host: string | null) => threeProductBody({ webhooks: webhooks({ hooks: [{ ...webhooks().hooks[0], host }] }) });
        for (const host of ['hooks.chat.example', '10.0.0.7', '[2001:db8::1]', null]) expect([host, issuesOf(withHost(host))]).toEqual([host, []]);
        const token = ['gh', 'p_', 'C3'.repeat(12)].join('');
        for (const bad of ['https://hooks.chat.example/x', 'hooks.chat.example/services/T0/B0', 'hooks.chat.example?token=1', 'user@hooks.chat.example', token]) {
            expect([bad, issuesOf(withHost(bad))]).not.toEqual([bad, []]);
        }
        const withUrl = { ...webhooks().hooks[0], url: 'https://hooks.chat.example/abc' };
        expect(issuesOf(threeProductBody({ webhooks: webhooks({ hooks: [withUrl as never] }) }))).not.toEqual([]);
    });

    it('verifies a signed three-product report and derives completeness from every source', () => {
        const keys = generateKeyPairSync('ed25519');
        const pub = keys.publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('hex');
        const wire = JSON.parse(JSON.stringify(threeProductBody())) as Record<string, unknown>;
        const raw = JSON.stringify({ ...wire, signature: { alg: 'ed25519', signerKey: pub, sig: sign(null, harnessSignedMessage(wire), keys.privateKey).toString('hex') } });
        expect(verifyAndParseIntegrationsReport(raw, [pub])).toMatchObject({ ok: true, complete: true });
    });

    it('an id says which product it came from', () => {
        expect(productOfApplicationId(application().id)).toBe('Microsoft Entra ID');
        expect(productOfApplicationId(oktaApplication().id)).toBe('Okta');
        expect(productOfApplicationId(githubInstallation().id)).toBe('GitHub');
        expect(productOfApplicationId('other:1')).toBe('Unknown product');
        expect(sourceKindOfApplicationId('github:acme:installation:1')).toBe('github-integrations');
        expect([application().id, oktaApplication().id, githubInstallation().id].every(isApplicationId)).toBe(true);
        expect(isApplicationId('github:acme:hook:7')).toBe(false);
        expect(applicationName(githubInstallation())).toBe('acme-deploy-bot');
        expect(applicationName(oktaApplication())).toBe('Acme Provisioning');
    });
});

describe('the Okta table', () => {
    it('is explicit: every .manage writes, and a write carries the class its read carries', () => {
        const entries = Object.entries(OKTA_SCOPE_CLASSES);
        expect(entries.length).toBeGreaterThanOrEqual(50);
        for (const [name, classes] of entries) {
            expect(name.startsWith('okta.')).toBe(true);
            expect(classes.every((c) => (PERMISSION_CLASSES as readonly string[]).includes(c))).toBe(true);
            const writes = /\.manage(\.self)?$/.test(name) || name === 'okta.clients.register';
            expect([name, classes.includes('WRITE')]).toEqual([name, writes]);
            const read = name.replace(/\.manage$/, '.read');
            if (writes && read !== name && read in OKTA_SCOPE_CLASSES) expect([name, classes.filter((c) => c !== 'WRITE')]).toEqual([name, OKTA_SCOPE_CLASSES[read]]);
        }
    });

    it('directory reads are high; logs, the org and the signed-in person\'s own profile are not; anything else is unknown', () => {
        for (const name of ['okta.users.read', 'okta.groups.read', 'okta.apps.read', 'okta.roles.read', 'okta.policies.read']) expect([name, classifyOktaScope(name)]).toEqual([name, { known: true, classes: ['DIRECTORY'], high: true }]);
        for (const name of ['okta.users.manage', 'okta.groups.manage']) expect([name, classifyOktaScope(name)]).toEqual([name, { known: true, classes: ['DIRECTORY', 'WRITE'], high: true }]);
        for (const name of ['okta.logs.read', 'okta.orgs.read', 'okta.users.read.self']) expect([name, classifyOktaScope(name)]).toEqual([name, { known: true, classes: [], high: false }]);
        // A name's spelling is not a classification: an unlisted .manage is unknown, as Graph's unlisted ReadWrite is.
        for (const name of ['okta.widgets.manage', 'okta.sessions.read', 'custom.scope', 'constructor']) expect([name, classifyOktaScope(name)]).toEqual([name, { known: false }]);
        expect(classifyOktaScope(null)).toEqual({ known: false });
    });
});

describe('the GitHub table', () => {
    it('is explicit, and every write or admin level is high whatever the name', () => {
        expect(Object.keys(GITHUB_PERMISSION_CLASSES).length).toBeGreaterThanOrEqual(30);
        for (const [name, classes] of Object.entries(GITHUB_PERMISSION_CLASSES)) {
            expect(classes.includes('WRITE')).toBe(false);
            for (const level of ['write', 'admin']) expect([name, level, classifyGithubPermission(name, level)]).toEqual([name, level, { known: true, classes: [...classes, 'WRITE'], high: true }]);
        }
        expect(classifyGithubPermission('a_permission_github_adds_later', 'write')).toEqual({ known: true, classes: ['WRITE'], high: true });
    });

    it('content and directory reads are high; metadata and secrets\' names are not; anything else is unknown', () => {
        // Issues and discussions are what people write in a repository: its content, as pull requests are.
        for (const name of ['contents', 'pull_requests', 'issues', 'discussions', 'actions', 'secret_scanning_alerts']) expect([name, classifyGithubPermission(name, 'read')]).toEqual([name, { known: true, classes: ['FILES'], high: true }]);
        for (const name of ['members', 'administration', 'organization_administration']) expect([name, classifyGithubPermission(name, 'read')]).toEqual([name, { known: true, classes: ['DIRECTORY'], high: true }]);
        for (const name of ['metadata', 'secrets', 'organization_secrets', 'checks', 'statuses']) expect([name, classifyGithubPermission(name, 'read')]).toEqual([name, { known: true, classes: [], high: false }]);
        for (const name of ['repository_projects', 'team_discussions', 'organization_hooks', 'environments', 'constructor']) expect([name, classifyGithubPermission(name, 'read')]).toEqual([name, { known: false }]);
        expect(classifyGithubPermission('contents', 'owner')).toEqual({ known: false });
    });
});

describe('the planner, per product', () => {
    it('Okta: a high scope raises the grant finding; publisher, owner and use are not concluded for the source, and never raised', () => {
        const plan = planIntegrationsScan(threeProductBody({ applications: [oktaApplication()] }));
        expect(codes(plan)).toEqual(['INTEGRATION_EMPTY_INVENTORY', 'INTEGRATION_EMPTY_INVENTORY', 'INTEGRATION_HIGH_PRIVILEGE_GRANT']);
        expect(plan.findings.find((f) => f.applicationId === oktaApplication().id)?.description).toContain('okta.users.read (Okta scope)');
        expect(plan.notConcluded.filter((n) => n.sourceKind === 'okta-integrations')).toEqual([
            { code: 'INTEGRATION_UNVERIFIED_PUBLISHER', applicationId: null, sourceKind: 'okta-integrations', why: 'PUBLISHER_NOT_EXPOSED' },
            { code: 'INTEGRATION_NO_OWNER', applicationId: null, sourceKind: 'okta-integrations', why: 'OWNER_NOT_EXPOSED' },
            { code: 'INTEGRATION_UNUSED', applicationId: null, sourceKind: 'okta-integrations', why: 'SIGN_IN_NOT_EXPOSED' },
        ]);
        expect(plan.applications[0]).toMatchObject({ privilege: 'HIGH', classes: ['DIRECTORY'], usage: 'NOT_CONCLUDED', daysSinceSignIn: null });
    });

    it('Okta: low scopes read in full are not high; grants read in part, unknown or unreadable scopes conclude nothing', () => {
        const low = (over: Partial<ReturnType<typeof oktaApplication>['scopeGrants']>) => oktaApplication({ scopeGrants: { read: true, scopes: ['okta.logs.read'], unreadableScopes: 0, ...over } });
        expect(planIntegrationsScan(threeProductBody({ applications: [low({})] })).applications[0].privilege).toBe('NOT_HIGH');
        const cases: [Partial<ReturnType<typeof oktaApplication>['scopeGrants']>, string][] = [
            [{ read: false }, 'GRANTS_NOT_READ_IN_FULL'],
            [{ scopes: ['okta.sessions.read'] }, 'ONLY_UNKNOWN_PERMISSIONS'],
            [{ unreadableScopes: 1 }, 'ONLY_UNKNOWN_PERMISSIONS'],
        ];
        for (const [over, reason] of cases) {
            const plan = planIntegrationsScan(threeProductBody({ applications: [low(over)] }));
            expect([reason, plan.applications[0].privilege]).toEqual([reason, 'NOT_CONCLUDED']);
            expect(plan.notConcluded).toContainEqual({ code: 'INTEGRATION_HIGH_PRIVILEGE_GRANT', applicationId: oktaApplication().id, sourceKind: 'okta-integrations', why: reason });
        }
        const unknown = planIntegrationsScan(threeProductBody({ applications: [low({ scopes: ['okta.sessions.read'] })] }));
        expect(unknown.unknownPermissionNames).toEqual([{ via: 'OKTA_SCOPE', resourceAppId: null, name: 'okta.sessions.read' }]);
    });

    it('GitHub: a write is high; metadata alone is not; an unknown read is listed', () => {
        const plan = planIntegrationsScan(threeProductBody({ applications: [githubInstallation()] }));
        expect(plan.applications[0]).toMatchObject({ privilege: 'HIGH', classes: ['FILES', 'WRITE'] });
        expect(plan.findings.find((f) => f.applicationId !== null)?.description).toContain('contents:write (installation permission)');
        const meta = githubInstallation({ permissions: { read: true, grants: [{ name: 'metadata', level: 'read' }], unreadable: 0 } });
        expect(planIntegrationsScan(threeProductBody({ applications: [meta] })).applications[0].privilege).toBe('NOT_HIGH');
        const projects = githubInstallation({ permissions: { read: true, grants: [{ name: 'metadata', level: 'read' }, { name: 'repository_projects', level: 'read' }], unreadable: 0 } });
        const p = planIntegrationsScan(threeProductBody({ applications: [projects] }));
        expect(p.applications[0].privilege).toBe('NOT_CONCLUDED');
        expect(p.unknownPermissionNames).toEqual([{ via: 'GITHUB_PERMISSION', resourceAppId: null, name: 'repository_projects:read' }]);
        const issues = githubInstallation({ permissions: { read: true, grants: [{ name: 'metadata', level: 'read' }, { name: 'issues', level: 'read' }], unreadable: 0 } });
        expect(planIntegrationsScan(threeProductBody({ applications: [issues] })).applications[0]).toMatchObject({ privilege: 'HIGH', classes: ['FILES'] });
        expect(p.notConcluded.filter((n) => n.sourceKind === 'github-integrations').map((n) => n.why)).toEqual(['PUBLISHER_NOT_EXPOSED', 'OWNER_NOT_EXPOSED', 'SIGN_IN_NOT_EXPOSED', 'ONLY_UNKNOWN_PERMISSIONS']);
    });

    it('an empty Okta or GitHub source read in full is a finding, in its product\'s words; read in part, not concluded', () => {
        const b = threeProductBody({ applications: [application()] });
        const plan = planIntegrationsScan(b);
        const empty = plan.findings.filter((f) => f.code === 'INTEGRATION_EMPTY_INVENTORY');
        expect(empty.map((f) => f.sourceRef)).toEqual(['INTEGRATION_EMPTY_INVENTORY:github-integrations', 'INTEGRATION_EMPTY_INVENTORY:okta-integrations']);
        // The owner's decision of 2026-11-13: an empty GitHub organisation is LOW; an empty Okta org stays HIGH, as an empty directory does.
        expect(empty.map((f) => f.severity)).toEqual(['LOW', 'HIGH']);
        expect(empty[0].description).toContain('An organisation with no app installed is possible');
        expect(empty[0].description).toContain('Confirm the token can see installations');
        // The fixture's organisation has a webhook, and the finding says so.
        expect(empty[0].description).toContain('the organisation has one webhook');
        const bare = planIntegrationsScan({ ...b, webhooks: webhooks({ hooks: [] }) }).findings.find((f) => f.sourceRef.endsWith(':github-integrations'));
        expect(bare?.description).toContain('and the organisation has no webhook either');
        expect(planIntegrationsScan(body({ applications: [] })).findings[0].severity).toBe('HIGH');
        expect(empty[0].description).toContain('wrong organisation');
        expect(empty[1].description).toContain('wrong org');
        // No application: the not-exposed entries are not written, there being nothing they are about.
        expect(plan.notConcluded.filter((n) => n.sourceKind !== 'entra-integrations')).toEqual([]);
        const partial = planIntegrationsScan({ ...b, sources: b.sources.map((s) => (s.kind === 'github-integrations' ? { ...s, status: 'INCOMPLETE' as const, reason: 'RATE_LIMITED' as const } : s)) });
        expect(partial.notConcluded).toContainEqual({ code: 'INTEGRATION_EMPTY_INVENTORY', applicationId: null, sourceKind: 'github-integrations', why: 'SOURCE_INCOMPLETE' });
    });

    it('Entra in a three-product body plans exactly as it does alone', () => {
        const alone = planIntegrationsScan(body());
        const together = planIntegrationsScan(threeProductBody());
        expect(together.findings.filter((f) => f.applicationId === application().id)).toEqual(alone.findings);
        expect(together.notConcluded.filter((n) => n.sourceKind === 'entra-integrations')).toEqual(alone.notConcluded);
    });

    it('every reason a question is not concluded is one the contract lists', () => {
        const plan = planIntegrationsScan(threeProductBody());
        for (const n of plan.notConcluded) expect(INTEGRATION_NOT_CONCLUDED_WHY).toContain(n.why);
    });
});
