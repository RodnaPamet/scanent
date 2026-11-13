/**
 * The wire contract `scanent-integrations/1`: what the integrations scanner
 * reports about the applications a directory has granted access to.
 *
 * A strict schema of its own, beside `inflect-agent-harness/*`, and held to
 * that contract's rules rather than a copy of them: the same byte cap, the same
 * signature over the same canonical JSON (`verifySignedEnvelope`), the same
 * refusal codes in the same order, and the same walk for a secret's shape over
 * every string member. A report of one contract is never read by the other's
 * verifier.
 *
 * ‾‾‾ WHAT THE REPORT DELIBERATELY CANNOT SAY ‾‾‾
 *
 *   • WHO CONSENTED. A delegated grant carries its scopes, its consent type and
 *     how many people it was granted for. Never a person's id, name or e-mail
 *     address: a grant for named people is a count.
 *   • A CREDENTIAL. A credential is a `scheme://locator` reference with its age
 *     and whether it expires, as in an agent report.
 *   • A URL. No member is a URL; a webhook target, when a later reader reports
 *     one, is a host, because a URL's path and query can carry a secret.
 *   • A FINDING. Whether a grant is high-privilege, whether an application is
 *     unused, is planned by the reader (`planIntegrationsScan`), never stated
 *     by the scanner.
 *   • COMPLETENESS IT DID NOT ESTABLISH. Each source says COMPLETE or
 *     INCOMPLETE with a reason, and so does its sign-in read; whether the scan
 *     is complete is derived (`isIntegrationsScanComplete`). Each application
 *     says, per member, whether what it lists was read in full: a list read in
 *     part is what was seen, never the whole.
 */
import { z } from 'zod';

import {
    describeReportSchemaIssue,
    INCOMPLETE_REASONS_V2,
    MAX_ID_CHARS,
    verifySignedEnvelope,
    type HarnessRefusal,
} from './harness-contract';
import { looksLikeSecret } from './harness-contract-rules';
import {
    APPLICATION_ORIGINS,
    CONSENT_TYPES,
    ENTRA_APPLICATION_ID,
    ENTRA_OBJECT_ID,
    INTEGRATIONS_CONTRACT_V1,
    INTEGRATIONS_SOURCE_KINDS,
    isIntegrationsScanComplete,
    ISO_DATE,
    MAX_APPLICATION_PERMISSIONS_PER_APPLICATION,
    MAX_APPLICATIONS,
    MAX_CREDENTIALS_PER_APPLICATION,
    MAX_DELEGATED_GRANTS_PER_APPLICATION,
    MAX_DISPLAY_NAME_CHARS,
    MAX_INTEGRATIONS_SOURCES,
    MAX_OWNERS_PER_APPLICATION,
    MAX_SCOPES_PER_GRANT,
    OWNER_KINDS,
    PERMISSION_NAME,
} from './integrations-contract-rules';

export * from './integrations-contract-rules';

const SHA256_HEX = /^sha256:[0-9a-f]{64}$/;
const REFERENCE = /^[a-z][a-z0-9+.-]{1,31}:\/\/\S{1,480}$/;

const id = z.string().min(1).max(MAX_ID_CHARS);
const guid = z.string().regex(ENTRA_OBJECT_ID);
const permissionName = z
    .string()
    .regex(PERMISSION_NAME)
    .refine((v) => !looksLikeSecret(v), 'a permission name must not have the shape of a secret');
const count = z.number().int().min(0);

const ScanSchema = z
    .object({
        id,
        asOf: z.string().datetime(),
        scanner: z.object({ agentId: id, version: id, manifestHash: z.string().regex(SHA256_HEX) }).strict(),
    })
    .strict();

const reason = z.enum(INCOMPLETE_REASONS_V2);

const SignInActivitySchema = z.discriminatedUnion('status', [
    z.object({ status: z.literal('NOT_READ') }).strict(),
    z.object({ status: z.literal('COMPLETE'), rows: count }).strict(),
    z.object({ status: z.literal('INCOMPLETE'), reason, rows: count }).strict(),
]);

const SourceSchema = z
    .object({
        kind: z.enum(INTEGRATIONS_SOURCE_KINDS),
        status: z.enum(['COMPLETE', 'INCOMPLETE']),
        reason: reason.optional(),
        rows: count,
        signInActivity: SignInActivitySchema,
    })
    .strict()
    .superRefine((s, ctx) => {
        if (s.status === 'INCOMPLETE' && s.reason === undefined) {
            ctx.addIssue({ code: 'custom', message: 'an INCOMPLETE source must name its reason', path: ['reason'] });
        }
        if (s.status === 'COMPLETE' && s.reason !== undefined) {
            ctx.addIssue({ code: 'custom', message: 'a COMPLETE source cannot carry an incompleteness reason', path: ['reason'] });
        }
    });

const OwnerSchema = z.object({ kind: z.enum(OWNER_KINDS), id: guid }).strict();

const DelegatedGrantSchema = z
    .object({
        /** The application whose API the grant is to; null when the read did not find it. */
        resourceAppId: guid.nullable(),
        consentType: z.enum(CONSENT_TYPES),
        /** How many people a `Principal` grant was made for; null for `AllPrincipals`, which is everybody. */
        principalCount: z.number().int().min(1).nullable(),
        scopes: z.array(permissionName).max(MAX_SCOPES_PER_GRANT),
        /** Scope names the read saw and could not report: not a name's shape, or a secret's. */
        unreadableScopes: count,
    })
    .strict()
    .superRefine((g, ctx) => {
        if ((g.consentType === 'AllPrincipals') !== (g.principalCount === null)) {
            ctx.addIssue({ code: 'custom', message: 'a count of people goes with a grant made for named people, and only with one', path: ['principalCount'] });
        }
        if (new Set(g.scopes).size !== g.scopes.length) ctx.addIssue({ code: 'custom', message: 'each scope appears once', path: ['scopes'] });
    });

const ApplicationPermissionSchema = z
    .object({
        resourceAppId: guid.nullable(),
        /** The app role's id, as assigned. */
        roleId: guid,
        /** The app role's value, as the resource names it; null when the read could not resolve it. */
        name: permissionName.nullable(),
    })
    .strict();

const CredentialSchema = z
    .object({
        ref: z
            .string()
            .regex(REFERENCE, 'a credential must be a scheme://locator reference, never a value')
            .refine((v) => !looksLikeSecret(v), 'a credential reference must not contain a secret-shaped value'),
        ageDays: count.nullable(),
        expires: z.boolean().nullable(),
    })
    .strict();

const displayName = z
    .string()
    .min(1)
    .max(MAX_DISPLAY_NAME_CHARS)
    .refine((v) => ![...v].some((ch) => (ch.codePointAt(0) as number) < 0x20 || ((ch.codePointAt(0) as number) >= 0x7f && (ch.codePointAt(0) as number) <= 0x9f)), 'a display name is printable')
    .refine((v) => !looksLikeSecret(v), 'a display name must not have the shape of a secret');

const ApplicationSchema = z
    .object({
        id: z.string().regex(ENTRA_APPLICATION_ID, 'an application id is entra:<directory id>:sp:<object id>'),
        sourceKind: z.enum(INTEGRATIONS_SOURCE_KINDS),
        appId: guid.nullable(),
        displayName: displayName.nullable(),
        origin: z.enum(APPLICATION_ORIGINS),
        /** Whether a verified publisher is recorded for it; null when the read could not tell. */
        publisherVerified: z.boolean().nullable(),
        /** Null: not read. Empty: read, and it has none. */
        owners: z.array(OwnerSchema).max(MAX_OWNERS_PER_APPLICATION).nullable(),
        delegatedGrants: z
            .object({ read: z.boolean(), grants: z.array(DelegatedGrantSchema).max(MAX_DELEGATED_GRANTS_PER_APPLICATION) })
            .strict()
            .superRefine((d, ctx) => {
                const keys = d.grants.map((g) => `${g.resourceAppId ?? ''}\u0000${g.consentType}`);
                if (new Set(keys).size !== keys.length) ctx.addIssue({ code: 'custom', message: 'one grant per resource and consent type', path: ['grants'] });
            }),
        applicationPermissions: z
            .object({ read: z.boolean(), permissions: z.array(ApplicationPermissionSchema).max(MAX_APPLICATION_PERMISSIONS_PER_APPLICATION) })
            .strict()
            .superRefine((a, ctx) => {
                const keys = a.permissions.map((p) => `${p.resourceAppId ?? ''}\u0000${p.roleId}`);
                if (new Set(keys).size !== keys.length) ctx.addIssue({ code: 'custom', message: 'each permission appears once', path: ['permissions'] });
            }),
        signIn: z
            .object({ read: z.boolean(), lastSeen: z.string().regex(ISO_DATE).nullable() })
            .strict()
            .refine((s) => s.read || s.lastSeen === null, 'a sign-in that was not read has no date'),
        credentials: z.array(CredentialSchema).max(MAX_CREDENTIALS_PER_APPLICATION),
    })
    .strict();

/** `scanent-integrations/1`, everything the signature covers. */
export const IntegrationsReportBodyV1Schema = z
    .object({
        contract: z.literal(INTEGRATIONS_CONTRACT_V1),
        scan: ScanSchema,
        sources: z.array(SourceSchema).min(1).max(MAX_INTEGRATIONS_SOURCES),
        applications: z.array(ApplicationSchema).max(MAX_APPLICATIONS),
    })
    .strict()
    .superRefine((r, ctx) => {
        const kinds = r.sources.map((s) => s.kind);
        if (new Set(kinds).size !== kinds.length) ctx.addIssue({ code: 'custom', message: 'each source kind appears once', path: ['sources'] });
        const byKind = new Map(r.sources.map((s) => [s.kind, s]));
        const seen = new Set<string>();
        r.applications.forEach((a, i) => {
            if (seen.has(a.id)) ctx.addIssue({ code: 'custom', message: 'an application id appears once', path: ['applications', i, 'id'] });
            seen.add(a.id);
            const source = byKind.get(a.sourceKind);
            if (source === undefined) {
                ctx.addIssue({ code: 'custom', message: 'an application names a source the report lists', path: ['applications', i, 'sourceKind'] });
            } else if (a.signIn.read && source.signInActivity.status === 'NOT_READ') {
                ctx.addIssue({ code: 'custom', message: 'a sign-in is read only from a source that read sign-in activity', path: ['applications', i, 'signIn'] });
            }
        });
    });

export type IntegrationsReportBodyV1 = z.infer<typeof IntegrationsReportBodyV1Schema>;
export type IntegrationsReportBody = IntegrationsReportBodyV1;
export type IntegrationsReportApplication = IntegrationsReportBody['applications'][number];
export type IntegrationsReportSource = IntegrationsReportBody['sources'][number];
export type IntegrationsDelegatedGrant = IntegrationsReportApplication['delegatedGrants']['grants'][number];
export type IntegrationsApplicationPermission = IntegrationsReportApplication['applicationPermissions']['permissions'][number];

export type IntegrationsParseResult =
    | { ok: true; body: IntegrationsReportBody; signerKey: string; complete: boolean }
    | { ok: false; reason: HarnessRefusal; issues?: string[] };

/**
 * Check a raw integrations report: the harness contract's first seven checks,
 * in its order (`verifySignedEnvelope`), then this contract's strict schema.
 * An agent report given here is a SCHEMA refusal, and so is this report given
 * to `verifyAndParseHarnessReport`: neither reads the other.
 */
export function verifyAndParseIntegrationsReport(raw: string, trustedSignerKeys: readonly string[]): IntegrationsParseResult {
    const envelope = verifySignedEnvelope(raw, trustedSignerKeys);
    if (!envelope.ok) return { ok: false, reason: envelope.reason };
    if (envelope.body.contract !== INTEGRATIONS_CONTRACT_V1) {
        return { ok: false, reason: 'SCHEMA', issues: ['contract: not a contract id this verifier accepts'] };
    }
    const parsed = IntegrationsReportBodyV1Schema.safeParse(envelope.body);
    if (!parsed.success) return { ok: false, reason: 'SCHEMA', issues: parsed.error.issues.map(describeReportSchemaIssue) };
    return { ok: true, body: parsed.data, signerKey: envelope.signerKey, complete: isIntegrationsScanComplete(parsed.data) };
}
