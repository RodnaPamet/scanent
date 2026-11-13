/**
 * The rules of the integrations report contract that need no hashing: its id,
 * its source kinds, its closed lists and its limits.
 *
 * They live apart from `integrations-contract.ts` for the reason the harness's
 * do (`harness-contract-rules.ts`): the integrations planner
 * (`integrations-findings.ts`) is something a browser may run, and the contract
 * verifies signatures with `crypto`. Keep this module free of Node built-ins.
 */

/**
 * The integrations scanner's first contract: what a directory has granted to
 * the applications in it, and who owns them. A strict schema of its own beside
 * `inflect-agent-harness/*`, verified by the same signature and canonical-JSON
 * rules, and read by nothing that reads an agent report.
 */
export const INTEGRATIONS_CONTRACT_V1 = 'scanent-integrations/1';

/** Every id the integrations verifier accepts. */
export const INTEGRATIONS_CONTRACT_IDS = [INTEGRATIONS_CONTRACT_V1] as const;
export type IntegrationsContractId = (typeof INTEGRATIONS_CONTRACT_IDS)[number];

/**
 * Where the integrations scanner looks. A closed list on the wire, as the
 * agent report's kinds are: a reader added later (Okta, GitHub) is a new id.
 */
export const INTEGRATIONS_SOURCE_KINDS = ['entra-integrations'] as const;
export type IntegrationsSourceKind = (typeof INTEGRATIONS_SOURCE_KINDS)[number];

/**
 * Whose application it is, as the directory records it: registered in the
 * directory that was read, registered in another one (a third party's), or
 * not stated. Microsoft's own first-party applications are not reported.
 */
export const APPLICATION_ORIGINS = ['THIS_DIRECTORY', 'OTHER_DIRECTORY', 'UNKNOWN'] as const;
export type ApplicationOrigin = (typeof APPLICATION_ORIGINS)[number];

/** A delegated grant made for every person in the directory, or for named people (counted, never named). */
export const CONSENT_TYPES = ['AllPrincipals', 'Principal'] as const;
export type ConsentType = (typeof CONSENT_TYPES)[number];

/** What owns an application, by the kind of directory object. */
export const OWNER_KINDS = ['user', 'servicePrincipal', 'other'] as const;
export type OwnerKind = (typeof OWNER_KINDS)[number];

/** Whether a source's sign-in activity was read: not asked for, read in full, or read in part. */
export const SIGN_IN_READ_STATES = ['NOT_READ', 'COMPLETE', 'INCOMPLETE'] as const;
export type SignInReadState = (typeof SIGN_IN_READ_STATES)[number];

// ─── Bounds ───

export const MAX_INTEGRATIONS_SOURCES = 10;
export const MAX_APPLICATIONS = 5_000;
/** Owners of one application. Graph returns at most 20 expanded objects, so this is all a read can hold. */
export const MAX_OWNERS_PER_APPLICATION = 20;
export const MAX_DELEGATED_GRANTS_PER_APPLICATION = 200;
export const MAX_SCOPES_PER_GRANT = 300;
export const MAX_APPLICATION_PERMISSIONS_PER_APPLICATION = 1_000;
export const MAX_CREDENTIALS_PER_APPLICATION = 100;
/** A display name, in characters. A longer one is not reported. */
export const MAX_DISPLAY_NAME_CHARS = 256;
/** A permission or scope name, in characters. */
export const MAX_PERMISSION_NAME_CHARS = 128;

/**
 * A permission or delegated scope name as a report may carry it. Graph's own
 * names (`Mail.Read`, `Directory.ReadWrite.All`, `user_impersonation`) fit;
 * anything else is not reported, and the grant counts it as unreadable.
 */
export const PERMISSION_NAME = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

/** A directory object id, as Entra writes it: a lower-case GUID. */
export const ENTRA_OBJECT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** An application's id in a report: the directory's id and the service principal's, `entra:<directory>:sp:<object>`. */
export const ENTRA_APPLICATION_ID = /^entra:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:sp:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** A calendar date, `YYYY-MM-DD`. A sign-in is reported to the day. */
export const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * Is the integrations scan complete? Derived, never declared: at least one
 * source, every source read in full, and no source's sign-in activity read in
 * part. Sign-in activity that was not asked for leaves a scan complete; it
 * leaves "unused" unconcluded instead.
 */
export function isIntegrationsScanComplete(body: {
    readonly sources: ReadonlyArray<{ readonly status: string; readonly signInActivity: { readonly status: string } }>;
}): boolean {
    return body.sources.length > 0 && body.sources.every((s) => s.status === 'COMPLETE' && s.signInActivity.status !== 'INCOMPLETE');
}
