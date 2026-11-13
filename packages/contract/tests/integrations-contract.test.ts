/**
 * `scanent-integrations/1`: a strict schema of its own, verified by the agent
 * report's own rules and order, and read by nothing that reads an agent
 * report.
 */
import { generateKeyPairSync, sign } from 'crypto';

import { harnessSignedMessage, verifyAndParseHarnessReport } from '../src/harness-contract';
import {
    IntegrationsReportBodyV1Schema,
    isIntegrationsScanComplete,
    MAX_OWNERS_PER_APPLICATION,
    verifyAndParseIntegrationsReport,
    type IntegrationsReportApplication,
} from '../src/integrations-contract';
import { firstSecretShapedMember } from '../src/harness-findings';
import { validV3ReportBody } from './helpers/agent-harness-fake-scanner';
import { application, body, DIR } from './helpers/integrations-bodies';

const keys = generateKeyPairSync('ed25519');
const PUBLIC = keys.publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('hex');
function signed(b: unknown): string {
    const wire = JSON.parse(JSON.stringify(b)) as Record<string, unknown>;
    return JSON.stringify({ ...wire, signature: { alg: 'ed25519', signerKey: PUBLIC, sig: sign(null, harnessSignedMessage(wire), keys.privateKey).toString('hex') } });
}

const issuesOf = (b: unknown): string[] => {
    const r = IntegrationsReportBodyV1Schema.safeParse(b);
    return r.success ? [] : r.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`);
};

describe('the strict schema', () => {
    it('accepts a body as the scanner writes it', () => {
        expect(issuesOf(body())).toEqual([]);
        expect(issuesOf(body({ applications: [] }))).toEqual([]);
    });

    it('refuses an unknown member anywhere: a webhook URL, a consenting person, a level', () => {
        expect(issuesOf({ ...body(), findings: [] })).not.toEqual([]);
        expect(issuesOf(body({ applications: [{ ...application(), webhookUrl: 'https://hooks.example/abc' } as IntegrationsReportApplication] }))).not.toEqual([]);
        const grant = { ...application().delegatedGrants.grants[0], principals: ['jane@example.com'] };
        expect(issuesOf(body({ applications: [application({ delegatedGrants: { read: true, grants: [grant] as never } })] }))).not.toEqual([]);
        expect(issuesOf({ ...body(), complete: true })).not.toEqual([]);
    });

    it('keeps a count of people with a grant for named people, and none with a grant for everyone', () => {
        const g = application().delegatedGrants.grants[0];
        expect(issuesOf(body({ applications: [application({ delegatedGrants: { read: true, grants: [{ ...g, consentType: 'AllPrincipals', principalCount: 3 }] } })] }))).not.toEqual([]);
        expect(issuesOf(body({ applications: [application({ delegatedGrants: { read: true, grants: [{ ...g, consentType: 'Principal', principalCount: null }] } })] }))).not.toEqual([]);
        expect(issuesOf(body({ applications: [application({ delegatedGrants: { read: true, grants: [{ ...g, consentType: 'AllPrincipals', principalCount: null }] } })] }))).toEqual([]);
    });

    it('refuses a secret where a name, a scope or a credential reference goes', () => {
        const token = ['gh', 'p_', 'A1'.repeat(12)].join('');
        expect(issuesOf(body({ applications: [application({ displayName: `sync ${token}` })] }))).not.toEqual([]);
        expect(issuesOf(body({ applications: [application({ delegatedGrants: { read: true, grants: [{ ...application().delegatedGrants.grants[0], scopes: [token] }] } })] }))).not.toEqual([]);
        expect(issuesOf(body({ applications: [application({ credentials: [{ ref: 'not-a-reference', ageDays: 1, expires: null }] })] }))).not.toEqual([]);
        expect(firstSecretShapedMember(body({ applications: [application({ displayName: token })] }))).toBe('applications[0].displayName');
    });

    it('holds the cross-member rules: ids once, kinds once, a listed source, a sign-in read only where it was asked for', () => {
        expect(issuesOf(body({ applications: [application(), application()] }))).toContainEqual(expect.stringContaining('an application id appears once'));
        const source = body().sources[0];
        expect(issuesOf(body({ sources: [source, source] }))).toContainEqual(expect.stringContaining('each source kind appears once'));
        expect(issuesOf(body({ sources: [{ ...source, signInActivity: { status: 'NOT_READ' } }] }))).toContainEqual(expect.stringContaining('a sign-in is read only'));
        expect(issuesOf(body({ applications: [application({ signIn: { read: false, lastSeen: '2026-01-01' } })] }))).not.toEqual([]);
        expect(issuesOf(body({ sources: [] }))).not.toEqual([]);
        expect(issuesOf(body({ sources: [{ ...source, status: 'INCOMPLETE' }] }))).toContainEqual(expect.stringContaining('must name its reason'));
        expect(issuesOf(body({ sources: [{ ...source, reason: 'TIME_BOX' }] }))).toContainEqual(expect.stringContaining('cannot carry'));
        expect(issuesOf(body({ applications: [application({ id: `entra:${DIR}:sp:not-a-guid` })] }))).not.toEqual([]);
        const owners = Array.from({ length: MAX_OWNERS_PER_APPLICATION + 1 }, (_, i) => ({ kind: 'user' as const, id: `c00000${String(i).padStart(2, '0')}-0000-4000-8000-000000003686` }));
        expect(issuesOf(body({ applications: [application({ owners })] }))).not.toEqual([]);
    });
});

describe('verification: the agent report\'s checks, in its order, then this schema', () => {
    it('accepts a report signed by a trusted key, and derives completeness', () => {
        const result = verifyAndParseIntegrationsReport(signed(body()), [PUBLIC]);
        expect(result).toMatchObject({ ok: true, complete: true, signerKey: PUBLIC });
        expect(isIntegrationsScanComplete(body({ sources: [{ kind: 'entra-integrations', status: 'COMPLETE', rows: 1, signInActivity: { status: 'INCOMPLETE', reason: 'AUTH_FAILED', rows: 0 } }] }))).toBe(false);
        expect(isIntegrationsScanComplete(body({ sources: [{ kind: 'entra-integrations', status: 'COMPLETE', rows: 1, signInActivity: { status: 'NOT_READ' } }] }))).toBe(true);
        expect(isIntegrationsScanComplete({ sources: [] })).toBe(false);
    });

    it('refuses as the agent verifier does: an untrusted signer, a body changed after signing, a body that is not this schema', () => {
        expect(verifyAndParseIntegrationsReport(signed(body()), [])).toMatchObject({ ok: false, reason: 'UNTRUSTED_SIGNER' });
        const tampered = JSON.parse(signed(body())) as Record<string, unknown>;
        tampered.applications = [];
        expect(verifyAndParseIntegrationsReport(JSON.stringify(tampered), [PUBLIC])).toMatchObject({ ok: false, reason: 'BAD_SIGNATURE' });
        expect(verifyAndParseIntegrationsReport(signed({ ...body(), extra: 1 }), [PUBLIC])).toMatchObject({ ok: false, reason: 'SCHEMA' });
        expect(verifyAndParseIntegrationsReport('{', [PUBLIC])).toMatchObject({ ok: false, reason: 'NOT_JSON' });
        expect(verifyAndParseIntegrationsReport(JSON.stringify(body()), [PUBLIC])).toMatchObject({ ok: false, reason: 'UNSIGNED' });
    });

    it('neither verifier reads the other\'s report', () => {
        expect(verifyAndParseHarnessReport(signed(body()), [PUBLIC])).toMatchObject({ ok: false, reason: 'SCHEMA' });
        expect(verifyAndParseIntegrationsReport(signed(validV3ReportBody()), [PUBLIC])).toEqual({ ok: false, reason: 'SCHEMA', issues: ['contract: not a contract id this verifier accepts'] });
    });

    it('names no value in a refusal: an unknown member is counted, never named', () => {
        const secretKey = ['gh', 'p_', 'B2'.repeat(12)].join('');
        const result = verifyAndParseIntegrationsReport(signed({ ...body(), [secretKey]: 1 }), [PUBLIC]);
        expect(result.ok).toBe(false);
        expect(JSON.stringify(result)).not.toContain(secretKey);
    });
});
