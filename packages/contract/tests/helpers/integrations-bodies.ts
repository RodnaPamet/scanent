/**
 * Integrations report bodies for the contract's tests: one application of
 * every member, and a body around it, each with whatever a test changes.
 */
import {
    INTEGRATIONS_CONTRACT_V1,
    type EntraIntegrationsApplication,
    type GitHubInstallation,
    type IntegrationsReportBody,
    type IntegrationsWebhooks,
    type OktaIntegrationsApplication,
} from '../../src/integrations-contract';

export const DIR = '0d1e2c3b-0000-4000-8000-000000003686';
export const SP = 'a0000006-0000-4000-8000-000000003686';
export const GRAPH = '00000003-0000-0000-c000-000000000000';

export function application(over: Partial<EntraIntegrationsApplication> = {}): EntraIntegrationsApplication {
    return {
        id: `entra:${DIR}:sp:${SP}`,
        sourceKind: 'entra-integrations',
        appId: 'e0000006-0000-4000-8000-000000003686',
        displayName: 'Acme Mail Sync',
        origin: 'OTHER_DIRECTORY',
        publisherVerified: false,
        owners: [],
        delegatedGrants: { read: true, grants: [{ resourceAppId: GRAPH, consentType: 'Principal', principalCount: 2, scopes: ['Mail.Read'], unreadableScopes: 0 }] },
        applicationPermissions: { read: true, permissions: [{ resourceAppId: GRAPH, roleId: 'e2a3a72e-5f79-4c64-b1b1-878b674786c9', name: 'Mail.ReadWrite' }] },
        signIn: { read: true, lastSeen: '2026-03-02' },
        credentials: [{ ref: `entra://${DIR}/servicePrincipals/${SP}/password/d0000006-0000-4000-8000-000000003686`, ageDays: 18, expires: true }],
        ...over,
    };
}

export function body(over: Partial<IntegrationsReportBody> = {}): IntegrationsReportBody {
    return {
        contract: INTEGRATIONS_CONTRACT_V1,
        scan: { id: 'acme-20261019T030000Z-0a1b2c3d', asOf: '2026-10-19T03:00:00.000Z', scanner: { agentId: 'agt_scanner', version: '0.14.0', manifestHash: `sha256:${'a'.repeat(64)}` } },
        sources: [{ kind: 'entra-integrations', status: 'COMPLETE', rows: 12, signInActivity: { status: 'COMPLETE', rows: 3 } }],
        applications: [application()],
        ...over,
    };
}


export const OKTA_HOST = 'acme.okta.com';

export function oktaApplication(over: Partial<OktaIntegrationsApplication> = {}): OktaIntegrationsApplication {
    return {
        id: `okta:${OKTA_HOST}:app:0oa1abcdEFGH23ijk456`,
        sourceKind: 'okta-integrations',
        appId: '0oa1abcdEFGH23ijk456',
        displayName: 'Acme Provisioning',
        status: 'ACTIVE',
        signOnMode: 'OPENID_CONNECT',
        scopeGrants: { read: true, scopes: ['okta.users.read', 'okta.logs.read'], unreadableScopes: 0 },
        ...over,
    };
}

export function githubInstallation(over: Partial<GitHubInstallation> = {}): GitHubInstallation {
    return {
        id: 'github:acme:installation:41',
        sourceKind: 'github-integrations',
        appId: 9001,
        appSlug: 'acme-deploy-bot',
        repositorySelection: 'selected',
        suspended: false,
        events: ['push', 'pull_request'],
        permissions: { read: true, grants: [{ name: 'metadata', level: 'read' }, { name: 'contents', level: 'write' }], unreadable: 0 },
        ...over,
    };
}

export function webhooks(over: Partial<IntegrationsWebhooks> = {}): IntegrationsWebhooks {
    return {
        read: true,
        hooks: [{ id: 'github:acme:hook:7', sourceKind: 'github-integrations', host: 'hooks.chat.example', events: ['push'], active: true, created: '2026-01-04' }],
        ...over,
    };
}

/** A body of all three products: one source and one application each, and the GitHub source's webhooks. */
export function threeProductBody(over: Partial<IntegrationsReportBody> = {}): IntegrationsReportBody {
    return body({
        sources: [
            { kind: 'entra-integrations', status: 'COMPLETE', rows: 12, signInActivity: { status: 'COMPLETE', rows: 3 } },
            { kind: 'okta-integrations', status: 'COMPLETE', rows: 4, signInActivity: { status: 'NOT_READ' } },
            { kind: 'github-integrations', status: 'COMPLETE', rows: 3, signInActivity: { status: 'NOT_READ' } },
        ],
        applications: [application(), githubInstallation(), oktaApplication()],
        webhooks: webhooks(),
        ...over,
    });
}
