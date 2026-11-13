/**
 * The integrations planner: exactly the owner's four findings and the empty
 * inventory, each concluded only on what was read, and every question it could
 * not answer listed with its reason. And the classification table it reads.
 */
import {
    DEFAULT_UNUSED_DAYS,
    INTEGRATION_FINDING_CODES,
    planIntegrationsScan,
    type IntegrationsPlan,
} from '../src/integrations-findings';
import { classifyPermission, GRAPH_PERMISSION_CLASSES, MICROSOFT_GRAPH_APP_ID, PERMISSION_CLASSES } from '../src/integrations-scopes';
import type { IntegrationsReportApplication } from '../src/integrations-contract';
import { application, body, GRAPH } from './helpers/integrations-bodies';

const OTHER_API = '9e9e9e9e-0000-4000-8000-000000003686';
const codes = (plan: IntegrationsPlan) => plan.findings.map((f) => f.code);
const why = (plan: IntegrationsPlan, code: string) => plan.notConcluded.filter((n) => n.code === code).map((n) => n.why);
const lowOnly = (over: Partial<IntegrationsReportApplication> = {}): IntegrationsReportApplication =>
    application({
        delegatedGrants: { read: true, grants: [{ resourceAppId: GRAPH, consentType: 'AllPrincipals', principalCount: null, scopes: ['User.Read', 'openid'], unreadableScopes: 0 }] },
        applicationPermissions: { read: true, permissions: [] },
        owners: [{ kind: 'user', id: 'c0000001-0000-4000-8000-000000003686' }],
        signIn: { read: true, lastSeen: '2026-10-18' },
        origin: 'THIS_DIRECTORY',
        ...over,
    });

describe('the classification table', () => {
    it('is explicit: every entry is classed from the four classes, and the rule\'s spelling holds for each name', () => {
        const entries = Object.entries(GRAPH_PERMISSION_CLASSES);
        expect(entries.length).toBeGreaterThanOrEqual(100);
        for (const [name, classes] of entries) {
            expect(classes.every((c) => (PERMISSION_CLASSES as readonly string[]).includes(c))).toBe(true);
            expect(new Set(classes).size).toBe(classes.length);
            // Any write is high: a name that says it writes, sends, creates, manages or acts as the user carries WRITE.
            if (/(^|\.)(ReadWrite|Send|Create|Manage|FullControl|AccessAsUser|EnableDisableAccount|Invite|ManageIdentities)(\.|$)/.test(name)) expect([name, classes.includes('WRITE')]).toEqual([name, true]);
            if (/^(Mail|MailboxSettings|IMAP|POP|SMTP|EWS)\./.test(name)) expect([name, classes.includes('MAIL')]).toEqual([name, true]);
            if (/^(Files|Sites)\./.test(name)) expect([name, classes.includes('FILES')]).toEqual([name, true]);
            if (/^(Directory|RoleManagement|Application|AppRoleAssignment|Group|GroupMember|Policy)\./.test(name)) expect([name, classes.includes('DIRECTORY')]).toEqual([name, true]);
            // The owner's decision of 2026-11-13: reading chat or calendar content is high, as mail and files are.
            if (/^(Chat|ChatMessage|ChannelMessage)\./.test(name) && name !== 'Chat.Create') expect([name, classes.includes('CHAT')]).toEqual([name, true]);
            if (/^Calendars\./.test(name)) expect([name, classes.includes('CALENDAR')]).toEqual([name, true]);
        }
    });

    it('answers in three ways, never two: low, high, or unknown', () => {
        expect(classifyPermission(MICROSOFT_GRAPH_APP_ID, 'User.Read')).toEqual({ known: true, classes: [], high: false });
        expect(classifyPermission(MICROSOFT_GRAPH_APP_ID, 'Mail.ReadWrite')).toEqual({ known: true, classes: ['MAIL', 'WRITE'], high: true });
        expect(classifyPermission(MICROSOFT_GRAPH_APP_ID, 'Directory.Read.All')).toEqual({ known: true, classes: ['DIRECTORY'], high: true });
        expect(classifyPermission(MICROSOFT_GRAPH_APP_ID, 'Sites.Read.All')).toEqual({ known: true, classes: ['FILES'], high: true });
        // The owner's decision of 2026-11-13: chat, calendar and site content is high; profiles and logs are not, and are known.
        for (const name of ['Chat.Read.All', 'ChatMessage.Read.All', 'Chat.Read', 'ChannelMessage.Read.All']) expect([name, classifyPermission(MICROSOFT_GRAPH_APP_ID, name)]).toEqual([name, { known: true, classes: ['CHAT'], high: true }]);
        for (const name of ['Calendars.Read', 'Calendars.ReadBasic.All', 'Calendars.Read.Shared']) expect([name, classifyPermission(MICROSOFT_GRAPH_APP_ID, name)]).toEqual([name, { known: true, classes: ['CALENDAR'], high: true }]);
        expect(classifyPermission(MICROSOFT_GRAPH_APP_ID, 'Sites.Read.All')).toMatchObject({ known: true, high: true });
        for (const name of ['User.Read.All', 'AuditLog.Read.All']) expect([name, classifyPermission(MICROSOFT_GRAPH_APP_ID, name)]).toEqual([name, { known: true, classes: [], high: false }]);
        expect(classifyPermission(MICROSOFT_GRAPH_APP_ID, 'Contacts.Read')).toEqual({ known: false });
        // A name Graph might add tomorrow is not high by its looks: it is unknown until the table says otherwise.
        expect(classifyPermission(MICROSOFT_GRAPH_APP_ID, 'Widgets.ReadWrite.All')).toEqual({ known: false });
        // Graph's names on another API mean nothing here.
        expect(classifyPermission(OTHER_API, 'Mail.ReadWrite')).toEqual({ known: false });
        expect(classifyPermission(null, 'Mail.ReadWrite')).toEqual({ known: false });
        expect(classifyPermission(MICROSOFT_GRAPH_APP_ID, null)).toEqual({ known: false });
        expect(classifyPermission(MICROSOFT_GRAPH_APP_ID, 'constructor')).toEqual({ known: false });
    });
});

describe('each finding', () => {
    it('raises all four on a third party with a high grant, no verified publisher, no owner and an old sign-in, in a fixed order', () => {
        const plan = planIntegrationsScan(body());
        expect(codes(plan)).toEqual(['INTEGRATION_HIGH_PRIVILEGE_GRANT', 'INTEGRATION_UNVERIFIED_PUBLISHER', 'INTEGRATION_NO_OWNER', 'INTEGRATION_UNUSED']);
        expect(plan.findings.map((f) => f.severity)).toEqual(['HIGH', 'HIGH', 'MEDIUM', 'LOW']);
        const high = plan.findings[0];
        expect(high.description).toContain('mail, a write');
        expect(high.description).toContain('Mail.ReadWrite (application)');
        expect(high.sourceRef).toBe(`INTEGRATION_HIGH_PRIVILEGE_GRANT:${application().id}`);
        expect(plan.applications[0]).toMatchObject({ privilege: 'HIGH', classes: ['MAIL', 'WRITE'], anyGrant: true, usage: 'UNUSED', daysSinceSignIn: 231 });
        expect(plan.notConcluded).toEqual([]);
    });

    it('raises none on an owned application with low grants used last week', () => {
        const plan = planIntegrationsScan(body({ applications: [lowOnly()] }));
        expect(plan.findings).toEqual([]);
        expect(plan.applications[0]).toMatchObject({ privilege: 'NOT_HIGH', usage: 'USED', daysSinceSignIn: 1 });
        expect(plan.notConcluded).toEqual([]);
    });

    it('INTEGRATION_HIGH_PRIVILEGE_GRANT: any of the four classes, delegated or application', () => {
        for (const scope of ['Directory.Read.All', 'Mail.Read', 'Files.Read.All', 'Chat.Read.All', 'Calendars.Read', 'Contacts.ReadWrite']) {
            const app = lowOnly({ delegatedGrants: { read: true, grants: [{ resourceAppId: GRAPH, consentType: 'AllPrincipals', principalCount: null, scopes: [scope], unreadableScopes: 0 }] } });
            expect([scope, codes(planIntegrationsScan(body({ applications: [app] })))]).toEqual([scope, ['INTEGRATION_HIGH_PRIVILEGE_GRANT']]);
        }
    });

    it('INTEGRATION_UNVERIFIED_PUBLISHER: only beside a high grant, never for the directory\'s own application, and never on an unknown publisher', () => {
        expect(codes(planIntegrationsScan(body({ applications: [application({ origin: 'THIS_DIRECTORY', owners: [{ kind: 'user', id: 'c0000001-0000-4000-8000-000000003686' }] })] })))).toEqual([
            'INTEGRATION_HIGH_PRIVILEGE_GRANT',
            'INTEGRATION_UNUSED',
        ]);
        expect(codes(planIntegrationsScan(body({ applications: [lowOnly({ origin: 'OTHER_DIRECTORY', publisherVerified: false })] })))).toEqual([]);
        expect(codes(planIntegrationsScan(body({ applications: [application({ publisherVerified: true })] })))).not.toContain('INTEGRATION_UNVERIFIED_PUBLISHER');
        const unknown = planIntegrationsScan(body({ applications: [application({ publisherVerified: null })] }));
        expect(codes(unknown)).not.toContain('INTEGRATION_UNVERIFIED_PUBLISHER');
        expect(why(unknown, 'INTEGRATION_UNVERIFIED_PUBLISHER')).toEqual(['PUBLISHER_NOT_KNOWN']);
        // An application whose registering directory is not stated is not its own: the rule applies.
        expect(codes(planIntegrationsScan(body({ applications: [application({ origin: 'UNKNOWN' })] })))).toContain('INTEGRATION_UNVERIFIED_PUBLISHER');
    });

    it('INTEGRATION_NO_OWNER: any grant at all, a low one included, and owners read as none', () => {
        expect(codes(planIntegrationsScan(body({ applications: [lowOnly({ owners: [] })] })))).toEqual(['INTEGRATION_NO_OWNER']);
        // No grant: no finding, however unowned.
        const bare = lowOnly({ owners: [], delegatedGrants: { read: true, grants: [] } });
        expect(codes(planIntegrationsScan(body({ applications: [bare] })))).toEqual([]);
        // A grant whose every scope was unreadable is still a grant.
        const unreadable = lowOnly({ owners: [], delegatedGrants: { read: true, grants: [{ resourceAppId: GRAPH, consentType: 'AllPrincipals', principalCount: null, scopes: [], unreadableScopes: 2 }] } });
        expect(codes(planIntegrationsScan(body({ applications: [unreadable] })))).toEqual(['INTEGRATION_NO_OWNER']);
    });

    it('INTEGRATION_UNUSED: never signed in, or outside the window the client set, which counts in whole days', () => {
        expect(codes(planIntegrationsScan(body({ applications: [lowOnly({ signIn: { read: true, lastSeen: null } })] })))).toEqual(['INTEGRATION_UNUSED']);
        const ninety = lowOnly({ signIn: { read: true, lastSeen: '2026-07-21' } });
        expect(planIntegrationsScan(body({ applications: [ninety] })).applications[0]).toMatchObject({ daysSinceSignIn: 90, usage: 'USED' });
        expect(codes(planIntegrationsScan(body({ applications: [lowOnly({ signIn: { read: true, lastSeen: '2026-07-20' } })] })))).toEqual(['INTEGRATION_UNUSED']);
        expect(codes(planIntegrationsScan(body({ applications: [ninety] }), { unusedDays: 30 }))).toEqual(['INTEGRATION_UNUSED']);
        expect(planIntegrationsScan(body()).unusedDays).toBe(DEFAULT_UNUSED_DAYS);
        expect(() => planIntegrationsScan(body(), { unusedDays: 0 })).toThrow(RangeError);
        expect(() => planIntegrationsScan(body(), { unusedDays: 1.5 })).toThrow(RangeError);
    });

    it('INTEGRATION_EMPTY_INVENTORY: a source read in full with no application, and says why that is suspicious', () => {
        const plan = planIntegrationsScan(body({ applications: [] }));
        expect(codes(plan)).toEqual(['INTEGRATION_EMPTY_INVENTORY']);
        expect(plan.findings[0]).toMatchObject({ severity: 'HIGH', applicationId: null, sourceRef: 'INTEGRATION_EMPTY_INVENTORY:entra-integrations' });
        expect(plan.findings[0].description).toContain('not a clean result');
        expect(plan.findings[0].description).toContain('wrong directory');
    });

    it('raises nothing but the five codes', () => {
        const all = new Set<string>();
        for (const b of [body(), body({ applications: [] }), body({ applications: [lowOnly({ owners: [] })] })]) for (const f of planIntegrationsScan(b).findings) all.add(f.code);
        expect([...all].sort()).toEqual([...INTEGRATION_FINDING_CODES].sort());
    });
});

describe('what is not concluded, and why', () => {
    it('an empty inventory from a partial read is not a finding, and not clean', () => {
        const plan = planIntegrationsScan(body({ applications: [], sources: [{ kind: 'entra-integrations', status: 'INCOMPLETE', reason: 'RATE_LIMITED', rows: 40, signInActivity: { status: 'NOT_READ' } }] }));
        expect(plan.findings).toEqual([]);
        expect(plan.notConcluded).toEqual([{ code: 'INTEGRATION_EMPTY_INVENTORY', applicationId: null, sourceKind: 'entra-integrations', why: 'SOURCE_INCOMPLETE' }]);
    });

    it('grants read in part: a high grant seen still raises; its absence concludes nothing', () => {
        const seen = planIntegrationsScan(body({ applications: [application({ applicationPermissions: { read: false, permissions: application().applicationPermissions.permissions } })] }));
        expect(codes(seen)).toContain('INTEGRATION_HIGH_PRIVILEGE_GRANT');
        const partial = lowOnly({ owners: [], origin: 'OTHER_DIRECTORY', publisherVerified: false, delegatedGrants: { read: false, grants: [] }, applicationPermissions: { read: false, permissions: [] } });
        const plan = planIntegrationsScan(body({ applications: [partial] }));
        expect(codes(plan)).toEqual([]);
        expect(why(plan, 'INTEGRATION_HIGH_PRIVILEGE_GRANT')).toEqual(['GRANTS_NOT_READ_IN_FULL']);
        expect(why(plan, 'INTEGRATION_UNVERIFIED_PUBLISHER')).toEqual(['GRANTS_NOT_READ_IN_FULL']);
        expect(why(plan, 'INTEGRATION_NO_OWNER')).toEqual(['GRANTS_NOT_READ_IN_FULL']);
        expect(plan.applications[0].privilege).toBe('NOT_CONCLUDED');
    });

    it('only unknown permissions: listed, never high, never low', () => {
        const app = lowOnly({
            origin: 'OTHER_DIRECTORY',
            publisherVerified: false,
            delegatedGrants: { read: true, grants: [{ resourceAppId: OTHER_API, consentType: 'AllPrincipals', principalCount: null, scopes: ['records.read'], unreadableScopes: 0 }] },
            applicationPermissions: { read: true, permissions: [{ resourceAppId: GRAPH, roleId: 'f0000001-0000-4000-8000-000000003686', name: null }] },
        });
        const plan = planIntegrationsScan(body({ applications: [app] }));
        expect(codes(plan)).toEqual([]);
        expect(plan.applications[0]).toMatchObject({ privilege: 'NOT_CONCLUDED', unknownPermissions: [expect.objectContaining({ name: 'records.read' }), expect.objectContaining({ name: null })] });
        expect(why(plan, 'INTEGRATION_HIGH_PRIVILEGE_GRANT')).toEqual(['ONLY_UNKNOWN_PERMISSIONS']);
        expect(why(plan, 'INTEGRATION_UNVERIFIED_PUBLISHER')).toEqual(['ONLY_UNKNOWN_PERMISSIONS']);
        expect(plan.unknownPermissionNames).toEqual([
            { resourceAppId: GRAPH, name: 'role:f0000001-0000-4000-8000-000000003686' },
            { resourceAppId: OTHER_API, name: 'records.read' },
        ]);
    });

    it('owners not read: no finding, and said', () => {
        const plan = planIntegrationsScan(body({ applications: [lowOnly({ owners: null })] }));
        expect(codes(plan)).toEqual([]);
        expect(why(plan, 'INTEGRATION_NO_OWNER')).toEqual(['OWNERS_NOT_READ']);
    });

    it('sign-in not configured: "unused" is not concluded for the source, once, and nothing is called unused', () => {
        const sources = [{ kind: 'entra-integrations' as const, status: 'COMPLETE' as const, rows: 12, signInActivity: { status: 'NOT_READ' as const } }];
        const plan = planIntegrationsScan(body({ sources, applications: [lowOnly({ signIn: { read: false, lastSeen: null } }), application({ id: 'entra:0d1e2c3b-0000-4000-8000-000000003686:sp:a0000009-0000-4000-8000-000000003686', signIn: { read: false, lastSeen: null } })] }));
        expect(codes(plan)).not.toContain('INTEGRATION_UNUSED');
        expect(plan.notConcluded.filter((n) => n.code === 'INTEGRATION_UNUSED')).toEqual([{ code: 'INTEGRATION_UNUSED', applicationId: null, sourceKind: 'entra-integrations', why: 'SIGN_IN_NOT_READ' }]);
        expect(plan.applications.map((a) => a.usage)).toEqual(['NOT_CONCLUDED', 'NOT_CONCLUDED']);
    });

    it('sign-in read in part: an application in what was read is judged, one outside it is not concluded', () => {
        const sources = [{ kind: 'entra-integrations' as const, status: 'COMPLETE' as const, rows: 12, signInActivity: { status: 'INCOMPLETE' as const, reason: 'RATE_LIMITED' as const, rows: 1 } }];
        const plan = planIntegrationsScan(body({ sources, applications: [lowOnly({ signIn: { read: false, lastSeen: null } })] }));
        expect(codes(plan)).toEqual([]);
        expect(why(plan, 'INTEGRATION_UNUSED')).toEqual(['SIGN_IN_READ_INCOMPLETE']);
        const judged = planIntegrationsScan(body({ sources, applications: [lowOnly({ signIn: { read: true, lastSeen: '2025-01-01' } })] }));
        expect(codes(judged)).toEqual(['INTEGRATION_UNUSED']);
    });
});
