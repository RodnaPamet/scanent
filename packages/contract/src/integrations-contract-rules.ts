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
 * agent report's kinds are. `okta-integrations` and `github-integrations`
 * joined `/1` before any report of it was released: each has an application
 * shape of its own beside Entra's, which is unchanged, so every report written
 * with Entra alone reads as it did (docs/contract.md, "Why /1 grew").
 */
export const INTEGRATIONS_SOURCE_KINDS = ['entra-integrations', 'okta-integrations', 'github-integrations'] as const;
export type IntegrationsSourceKind = (typeof INTEGRATIONS_SOURCE_KINDS)[number];

/** The product each kind reads, in words, for the outputs. */
export const INTEGRATIONS_PRODUCT_TITLE: Readonly<Record<IntegrationsSourceKind, string>> = Object.freeze({
    'entra-integrations': 'Microsoft Entra ID',
    'okta-integrations': 'Okta',
    'github-integrations': 'GitHub',
});

/** An application id's prefix, by kind: the id itself says which product it came from. */
export const APPLICATION_ID_PREFIX: Readonly<Record<IntegrationsSourceKind, string>> = Object.freeze({
    'entra-integrations': 'entra:',
    'okta-integrations': 'okta:',
    'github-integrations': 'github:',
});

/** The kind an application id belongs to, by its prefix; null for an id of none. */
export function sourceKindOfApplicationId(id: string): IntegrationsSourceKind | null {
    for (const kind of INTEGRATIONS_SOURCE_KINDS) if (id.startsWith(APPLICATION_ID_PREFIX[kind])) return kind;
    return null;
}

/** The product an application id came from, in words; `Unknown product` for an id of none. */
export function productOfApplicationId(id: string): string {
    const kind = sourceKindOfApplicationId(id);
    return kind === null ? 'Unknown product' : INTEGRATIONS_PRODUCT_TITLE[kind];
}

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
/** Okta scopes granted to one application. Okta's management API has fewer than this. */
export const MAX_OKTA_SCOPES_PER_APPLICATION = 300;
/** Permissions of one GitHub App installation. GitHub defines fewer than this. */
export const MAX_GITHUB_PERMISSIONS_PER_INSTALLATION = 200;
/** Events one installation or webhook subscribes to. */
export const MAX_EVENTS = 300;
/** Webhooks of one organisation. */
export const MAX_WEBHOOKS = 1_000;

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

/** An Okta org's host, as the configuration names it: on Okta's own domains, lower-case. */
export const OKTA_ORG_HOST = /^[a-z0-9](?:[a-z0-9-]{0,62})(?:\.[a-z0-9](?:[a-z0-9-]{0,62}))*\.(?:okta|oktapreview)\.com$/;

/** An Okta object id (an app's): letters and digits, as Okta writes them. */
export const OKTA_OBJECT_ID = /^[A-Za-z0-9]{1,64}$/;

/** An Okta application in a report: `okta:<org host>:app:<app id>`. */
export const OKTA_APPLICATION_ID = /^okta:[a-z0-9.-]{1,253}:app:[A-Za-z0-9]{1,64}$/;

/** A GitHub organisation's login, lower-cased: GitHub compares logins without case. */
export const GITHUB_ORGANIZATION = /^[a-z0-9](?:[a-z0-9-]{0,38})$/;

/** A GitHub App installation in a report: `github:<organisation>:installation:<installation id>`. */
export const GITHUB_INSTALLATION_ID = /^github:[a-z0-9][a-z0-9-]{0,38}:installation:[1-9][0-9]{0,19}$/;

/** An organisation webhook in a report: `github:<organisation>:hook:<hook id>`. */
export const GITHUB_WEBHOOK_ID = /^github:[a-z0-9][a-z0-9-]{0,38}:hook:[1-9][0-9]{0,19}$/;

/** A GitHub App's slug, as GitHub writes it. */
export const GITHUB_APP_SLUG = /^[a-z0-9][a-z0-9-]{0,99}$/;

/** A webhook or installation event name, or `*` for every event. */
export const EVENT_NAME = /^(?:\*|[a-z][a-z0-9_.]{0,63})$/;

/**
 * A webhook's target HOST, and nothing more: a lower-case DNS name, an IPv4
 * address, or an IPv6 address in brackets. Never a URL: a URL's path and query
 * can carry a secret, so the reader reduces it to this before it keeps it.
 */
export const WEBHOOK_HOST = /^(?:(?:[a-z0-9_](?:[a-z0-9_-]{0,62})\.)*[a-z0-9_](?:[a-z0-9_-]{0,62})|\[[0-9a-f:.]{2,45}\])$/;

/** Every application id a report may carry, whatever its product. */
export function isApplicationId(id: string): boolean {
    return ENTRA_APPLICATION_ID.test(id) || OKTA_APPLICATION_ID.test(id) || GITHUB_INSTALLATION_ID.test(id);
}

/** An Okta application's status, as Okta's apps listing gives it. `DELETED` is never listed. */
export const OKTA_APP_STATUSES = ['ACTIVE', 'INACTIVE'] as const;

/** An Okta application's sign-on mode, Okta's own documented list. */
export const OKTA_SIGN_ON_MODES = [
    'AUTO_LOGIN',
    'BASIC_AUTH',
    'BOOKMARK',
    'BROWSER_PLUGIN',
    'OPENID_CONNECT',
    'SAML_1_1',
    'SAML_2_0',
    'SECURE_PASSWORD_STORE',
    'WS_FEDERATION',
] as const;

/** A GitHub App permission's access level, as an installation's `permissions` map writes it. */
export const GITHUB_PERMISSION_LEVELS = ['read', 'write', 'admin'] as const;
export type GitHubPermissionLevel = (typeof GITHUB_PERMISSION_LEVELS)[number];

/** Which repositories an installation reaches: every one of the organisation's, or those selected. */
export const REPOSITORY_SELECTIONS = ['all', 'selected'] as const;

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
