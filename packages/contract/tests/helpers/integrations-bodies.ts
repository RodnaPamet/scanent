/**
 * Integrations report bodies for the contract's tests: one application of
 * every member, and a body around it, each with whatever a test changes.
 */
import { INTEGRATIONS_CONTRACT_V1, type IntegrationsReportApplication, type IntegrationsReportBody } from '../../src/integrations-contract';

export const DIR = '0d1e2c3b-0000-4000-8000-000000003686';
export const SP = 'a0000006-0000-4000-8000-000000003686';
export const GRAPH = '00000003-0000-0000-c000-000000000000';

export function application(over: Partial<IntegrationsReportApplication> = {}): IntegrationsReportApplication {
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

