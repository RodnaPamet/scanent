/**
 * THE INTEGRATIONS PLANNER — what a `scanent-integrations/1` report means.
 *
 * Pure and browser-safe: a body in, the findings and what could not be
 * concluded out. The owner decided four findings on 2026-11-13, and the
 * planner raises those four and the empty-inventory finding, and nothing else:
 *
 *   INTEGRATION_HIGH_PRIVILEGE_GRANT  HIGH    the application holds a grant the
 *                                             classification table calls high:
 *                                             directory, mail, files, chats,
 *                                             calendars, or a write
 *   INTEGRATION_UNVERIFIED_PUBLISHER  HIGH    it holds one, it is another
 *                                             directory's, and no verified
 *                                             publisher is recorded for it
 *   INTEGRATION_NO_OWNER              MEDIUM  it holds a grant of any kind, and
 *                                             nobody owns it
 *   INTEGRATION_UNUSED                LOW     it has not signed in within the
 *                                             window the client set
 *   INTEGRATION_EMPTY_INVENTORY       HIGH    a source read in full found no
 *                                             application at all; LOW for a
 *                                             GitHub organisation, which can
 *                                             truly have no app installed
 *
 * THE HONESTY RULES, the agent planner's, applied here:
 *
 *   • A PRESENCE COUNTS ON ANY READ; AN ABSENCE ONLY ON A WHOLE ONE. A grant the
 *     scanner saw is real even when the listing it was on stopped early, so it
 *     raises its finding. "No high-privilege grant", "no grant at all" and "no
 *     sign-in" are concluded only from a list read in full; otherwise they are
 *     NOT CONCLUDED, with the reason, never treated as clean.
 *   • UNKNOWN IS NOT AN ANSWER. A permission the table does not know is not
 *     called high and not called low: every unknown name is listed, and an
 *     application whose only grants are unknown is not concluded either way.
 *     A publisher the read could not establish concludes no finding.
 *   • ZERO IS NEVER CLEAN. A source read in full that holds no application is
 *     a finding: every directory in use holds some, and an empty answer is what
 *     a read of the wrong directory, or through a filtered view, looks like.
 *   • A FINDING IS ABOUT WHAT WAS SEEN. An application absent from a report is
 *     not concluded gone, unused or clean.
 *   • WHAT A PRODUCT DOES NOT EXPOSE IS NOT CONCLUDED, PER PRODUCT. Okta's
 *     documented app object has no owner, no publisher verification and no
 *     last use; GitHub's installation response has none of the three either.
 *     For those products the three findings are not concluded, once per
 *     source, with a reason saying the product does not expose it, and never
 *     raised: "no owner recorded" is not something either API can say.
 */
import { applicationName, type IntegrationsReportApplication, type IntegrationsReportBody } from './integrations-contract';
import { INTEGRATIONS_PRODUCT_TITLE, type IntegrationsSourceKind } from './integrations-contract-rules';
import { classifyGithubPermission, classifyOktaScope, classifyPermission, type PermissionClass, type PermissionClassification } from './integrations-scopes';

export const INTEGRATION_FINDING_CODES = [
    'INTEGRATION_HIGH_PRIVILEGE_GRANT',
    'INTEGRATION_UNVERIFIED_PUBLISHER',
    'INTEGRATION_NO_OWNER',
    'INTEGRATION_UNUSED',
    'INTEGRATION_EMPTY_INVENTORY',
] as const;
export type IntegrationFindingCode = (typeof INTEGRATION_FINDING_CODES)[number];

export type IntegrationSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export const INTEGRATION_FINDING_SEVERITY: Readonly<Record<IntegrationFindingCode, IntegrationSeverity>> = Object.freeze({
    INTEGRATION_HIGH_PRIVILEGE_GRANT: 'HIGH',
    INTEGRATION_UNVERIFIED_PUBLISHER: 'HIGH',
    INTEGRATION_NO_OWNER: 'MEDIUM',
    INTEGRATION_UNUSED: 'LOW',
    INTEGRATION_EMPTY_INVENTORY: 'HIGH',
});

/**
 * An empty inventory's severity, by the product it is about. HIGH for a
 * directory and an Okta org, which in use always hold applications. LOW for a
 * GitHub organisation: an organisation with no app
 * installed is possible, so the finding asks for the token to be confirmed
 * rather than calling the read wrong (docs/design/scanners.md, Decisions).
 */
export const EMPTY_INVENTORY_SEVERITY: Readonly<Record<IntegrationsSourceKind, IntegrationSeverity>> = Object.freeze({
    'entra-integrations': 'HIGH',
    'okta-integrations': 'HIGH',
    'github-integrations': 'LOW',
});

/** A finding's severity for a product: `INTEGRATION_FINDING_SEVERITY`, but for an empty inventory, which is the product's. */
export function integrationFindingSeverity(code: IntegrationFindingCode, kind: IntegrationsSourceKind): IntegrationSeverity {
    return code === 'INTEGRATION_EMPTY_INVENTORY' ? EMPTY_INVENTORY_SEVERITY[kind] : INTEGRATION_FINDING_SEVERITY[code];
}

/** The window "unused" is measured over when the client sets none: the owner's default. */
export const DEFAULT_UNUSED_DAYS = 90;
export const MIN_UNUSED_DAYS = 1;
export const MAX_UNUSED_DAYS = 3_650;

/** Why a finding could not be concluded either way. */
export const INTEGRATION_NOT_CONCLUDED_WHY = [
    /** The application's grants were not all read, and what was read raises nothing. */
    'GRANTS_NOT_READ_IN_FULL',
    /** Every grant it holds is on a permission the table does not know. */
    'ONLY_UNKNOWN_PERMISSIONS',
    /** It holds a high-privilege grant, and the read could not tell whether its publisher is verified. */
    'PUBLISHER_NOT_KNOWN',
    /** It holds a grant, and its owners were not read. */
    'OWNERS_NOT_READ',
    /** Sign-in activity was not asked for: the source is configured without it. */
    'SIGN_IN_NOT_READ',
    /** Sign-in activity was asked for and not read in full, and this application was not in what was read. */
    'SIGN_IN_READ_INCOMPLETE',
    /** The source was not read in full and found nothing: an empty answer from a partial read concludes nothing. */
    'SOURCE_INCOMPLETE',
    /** The product's API records no owner of an application (Okta, GitHub): "no owner" cannot be read from it. */
    'OWNER_NOT_EXPOSED',
    /** The product's API records no publisher verification (Okta, GitHub). */
    'PUBLISHER_NOT_EXPOSED',
    /** The product's API records no last use of an application, short of reading its logs (Okta, GitHub). */
    'SIGN_IN_NOT_EXPOSED',
] as const;
export type IntegrationNotConcludedWhy = (typeof INTEGRATION_NOT_CONCLUDED_WHY)[number];

export interface PlannedIntegrationFinding {
    readonly code: IntegrationFindingCode;
    readonly sourceRef: string;
    readonly severity: IntegrationSeverity;
    /** The application it is about; null for a finding about a source. */
    readonly applicationId: string | null;
    readonly title: string;
    readonly description: string;
}

export interface IntegrationNotConcluded {
    readonly code: IntegrationFindingCode;
    /** Null when it holds for every application of a source, which `sourceKind` names. */
    readonly applicationId: string | null;
    readonly sourceKind: string;
    readonly why: IntegrationNotConcludedWhy;
}

/**
 * How an application holds a permission: an Entra delegated grant or
 * application permission, an Okta API scope consented to it, or a GitHub App
 * installation's permission at a level.
 */
export const PERMISSION_VIAS = ['DELEGATED', 'APPLICATION', 'OKTA_SCOPE', 'GITHUB_PERMISSION'] as const;
export type PermissionVia = (typeof PERMISSION_VIAS)[number];

/** One permission an application holds, as the planner read it. */
export interface PlannedPermission {
    readonly via: PermissionVia;
    /** The Entra API the permission is on; null for Okta and GitHub, whose permissions are on the product's own API. */
    readonly resourceAppId: string | null;
    /** The scope or role name, a GitHub permission as `<name>:<level>`; null when the read could not resolve the role. */
    readonly name: string | null;
    readonly roleId: string | null;
    readonly classes: readonly PermissionClass[] | null;
}

/** Where an application stands on each question, as concluded or not. */
export interface PlannedApplication {
    readonly id: string;
    /** HIGH: a high grant was seen. NOT_HIGH: every grant was read and known, and none is high. */
    readonly privilege: 'HIGH' | 'NOT_HIGH' | 'NOT_CONCLUDED';
    readonly highPermissions: readonly PlannedPermission[];
    readonly unknownPermissions: readonly PlannedPermission[];
    readonly classes: readonly PermissionClass[];
    /** Whether any grant was seen. */
    readonly anyGrant: boolean;
    /** USED: signed in within the window. UNUSED: read, and not. */
    readonly usage: 'USED' | 'UNUSED' | 'NOT_CONCLUDED';
    /** Whole days from the last sign-in to the scan; null when there is none or it was not read. */
    readonly daysSinceSignIn: number | null;
}

export interface IntegrationsPlan {
    readonly unusedDays: number;
    readonly applications: readonly PlannedApplication[];
    /** In a fixed order: by application id, then by code. Source findings first. */
    readonly findings: readonly PlannedIntegrationFinding[];
    readonly notConcluded: readonly IntegrationNotConcluded[];
    /** Every permission name the tables do not know, once per product and API, sorted. */
    readonly unknownPermissionNames: readonly { readonly via: PermissionVia; readonly resourceAppId: string | null; readonly name: string }[];
}

/** The findings each product's API cannot answer, and why: the not-concluded entries the planner writes once per source. */
export const NOT_EXPOSED_BY_PRODUCT: Readonly<Record<IntegrationsSourceKind, readonly { readonly code: IntegrationFindingCode; readonly why: IntegrationNotConcludedWhy }[]>> = Object.freeze({
    'entra-integrations': [],
    'okta-integrations': [
        { code: 'INTEGRATION_UNVERIFIED_PUBLISHER', why: 'PUBLISHER_NOT_EXPOSED' },
        { code: 'INTEGRATION_NO_OWNER', why: 'OWNER_NOT_EXPOSED' },
        { code: 'INTEGRATION_UNUSED', why: 'SIGN_IN_NOT_EXPOSED' },
    ],
    'github-integrations': [
        { code: 'INTEGRATION_UNVERIFIED_PUBLISHER', why: 'PUBLISHER_NOT_EXPOSED' },
        { code: 'INTEGRATION_NO_OWNER', why: 'OWNER_NOT_EXPOSED' },
        { code: 'INTEGRATION_UNUSED', why: 'SIGN_IN_NOT_EXPOSED' },
    ],
});

const byString = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

const PERMISSION_CLASS_ORDER: readonly PermissionClass[] = ['DIRECTORY', 'MAIL', 'FILES', 'CHAT', 'CALENDAR', 'WRITE'];

/** Each class in words, for a finding's description. */
export const CLASS_WORDS: Readonly<Record<PermissionClass, string>> = Object.freeze({
    DIRECTORY: 'the directory',
    MAIL: 'mail',
    FILES: 'files',
    CHAT: 'chats',
    CALENDAR: 'calendars',
    WRITE: 'a write',
});

const classesOf = (c: PermissionClassification): readonly PermissionClass[] | null => (c.known ? c.classes : null);

/** The permissions an application holds, as read: Entra's delegated then application, Okta's scopes, GitHub's permissions. */
export function permissionsOf(app: IntegrationsReportApplication): PlannedPermission[] {
    const out: PlannedPermission[] = [];
    if (app.sourceKind === 'okta-integrations') {
        for (const scope of app.scopeGrants.scopes) out.push({ via: 'OKTA_SCOPE', resourceAppId: null, name: scope, roleId: null, classes: classesOf(classifyOktaScope(scope)) });
        return out;
    }
    if (app.sourceKind === 'github-integrations') {
        for (const g of app.permissions.grants) {
            out.push({ via: 'GITHUB_PERMISSION', resourceAppId: null, name: `${g.name}:${g.level}`, roleId: null, classes: classesOf(classifyGithubPermission(g.name, g.level)) });
        }
        return out;
    }
    for (const g of app.delegatedGrants.grants) {
        for (const scope of g.scopes) {
            out.push({ via: 'DELEGATED', resourceAppId: g.resourceAppId, name: scope, roleId: null, classes: classesOf(classifyPermission(g.resourceAppId, scope)) });
        }
    }
    for (const p of app.applicationPermissions.permissions) {
        out.push({ via: 'APPLICATION', resourceAppId: p.resourceAppId, name: p.name, roleId: p.roleId, classes: classesOf(classifyPermission(p.resourceAppId, p.name)) });
    }
    return out;
}

/** Whether every grant of an application was read, in its product's terms. */
export function grantsReadInFull(app: IntegrationsReportApplication): boolean {
    if (app.sourceKind === 'okta-integrations') return app.scopeGrants.read;
    if (app.sourceKind === 'github-integrations') return app.permissions.read;
    return app.delegatedGrants.read && app.applicationPermissions.read;
}

/** Permissions seen that could not be reported, in its product's terms. */
export function unreadablePermissionsOf(app: IntegrationsReportApplication): number {
    if (app.sourceKind === 'okta-integrations') return app.scopeGrants.unreadableScopes;
    if (app.sourceKind === 'github-integrations') return app.permissions.unreadable;
    return app.delegatedGrants.grants.reduce((n, g) => n + g.unreadableScopes, 0);
}

/** Whole days between two instants, never negative. */
function wholeDays(fromIsoDate: string, asOf: string): number {
    const from = Date.parse(`${fromIsoDate}T00:00:00.000Z`);
    const to = Date.parse(asOf);
    return Math.max(0, Math.floor((to - from) / 86_400_000));
}

/** `INTEGRATION_*:<application id>`, or `:<source kind>` for a finding about a source. */
export function integrationFindingRef(code: IntegrationFindingCode, subject: string): string {
    return `${code}:${subject}`;
}

/** How a permission is held, in words. */
export const VIA_WORDS: Readonly<Record<PermissionVia, string>> = Object.freeze({
    DELEGATED: 'delegated',
    APPLICATION: 'application',
    OKTA_SCOPE: 'Okta scope',
    GITHUB_PERMISSION: 'installation permission',
});

const permissionWords = (p: PlannedPermission): string => `${p.name ?? `role ${p.roleId ?? 'unknown'}`} (${VIA_WORDS[p.via]})`;

function nameOf(app: IntegrationsReportApplication): string {
    const name = applicationName(app);
    return name === null ? app.id : `${name} (${app.id})`;
}

/** Why an empty inventory is not clean, in each product's words. */
const EMPTY_INVENTORY_WHY: Readonly<Record<IntegrationsSourceKind, string>> = Object.freeze({
    'entra-integrations':
        'That is not a clean result: a directory in use holds applications, and an empty answer is what a read of the wrong directory, ' +
        'or one made through a credential that sees a filtered view, looks like. Check the directory id and the permissions the reading application holds.',
    'okta-integrations':
        'That is not a clean result: an Okta org in use holds applications, and an empty answer is what a read of the wrong org, ' +
        'or one made with a token whose administrator sees a filtered view, looks like. Check the org URL and the role of the token\'s administrator.',
    'github-integrations':
        'An organisation with no app installed is possible, so this is a low finding, and still not a clean result: an empty answer is also what ' +
        'a read of the wrong organisation, or one made with a token that cannot see its installations, looks like. Confirm the token can see ' +
        "installations: it must be an organisation owner's, holding Administration: Read-only for the organisation. Then confirm in the " +
        "organisation's settings (GitHub Apps) that no app is installed.",
});

/**
 * Plan one integrations report. `unusedDays` is the client's window for
 * "unused"; the report does not carry it, because it is the reader's setting
 * and not something the scanner observed.
 */
export function planIntegrationsScan(body: IntegrationsReportBody, opts: { readonly unusedDays?: number } = {}): IntegrationsPlan {
    const unusedDays = opts.unusedDays ?? DEFAULT_UNUSED_DAYS;
    if (!Number.isInteger(unusedDays) || unusedDays < MIN_UNUSED_DAYS || unusedDays > MAX_UNUSED_DAYS) {
        throw new RangeError(`unusedDays must be a whole number from ${MIN_UNUSED_DAYS} to ${MAX_UNUSED_DAYS}`);
    }
    const findings: PlannedIntegrationFinding[] = [];
    const notConcluded: IntegrationNotConcluded[] = [];
    const unknown = new Map<string, { via: PermissionVia; resourceAppId: string | null; name: string }>();

    // ── The sources: an empty inventory, and sign-in activity not read ──
    for (const source of [...body.sources].sort((a, b) => byString(a.kind, b.kind))) {
        const apps = body.applications.filter((a) => a.sourceKind === source.kind);
        if (apps.length === 0) {
            if (source.status === 'COMPLETE') {
                findings.push({
                    code: 'INTEGRATION_EMPTY_INVENTORY',
                    sourceRef: integrationFindingRef('INTEGRATION_EMPTY_INVENTORY', source.kind),
                    severity: integrationFindingSeverity('INTEGRATION_EMPTY_INVENTORY', source.kind),
                    applicationId: null,
                    title: `${source.kind} was read in full and holds no application`,
                    description:
                        `The source ${source.kind} (${INTEGRATIONS_PRODUCT_TITLE[source.kind]}) was read in full (${source.rows} rows) and reported no application it has granted access to` +
                        (source.kind === 'github-integrations' && body.webhooks !== undefined
                            ? body.webhooks.hooks.length === 0
                                ? ', and the organisation has no webhook either. '
                                : `; the organisation has ${body.webhooks.hooks.length === 1 ? 'one webhook' : `${body.webhooks.hooks.length} webhooks`}. `
                            : '. ') +
                        EMPTY_INVENTORY_WHY[source.kind],
                });
            } else {
                notConcluded.push({ code: 'INTEGRATION_EMPTY_INVENTORY', applicationId: null, sourceKind: source.kind, why: 'SOURCE_INCOMPLETE' });
            }
        }
        if (apps.length === 0) continue;
        const notExposed = NOT_EXPOSED_BY_PRODUCT[source.kind];
        // What the product cannot answer is said once for every application of the source.
        for (const n of notExposed) notConcluded.push({ code: n.code, applicationId: null, sourceKind: source.kind, why: n.why });
        if (notExposed.length === 0 && source.signInActivity.status === 'NOT_READ') {
            notConcluded.push({ code: 'INTEGRATION_UNUSED', applicationId: null, sourceKind: source.kind, why: 'SIGN_IN_NOT_READ' });
        }
    }

    // ── Each application ──
    const planned: PlannedApplication[] = [];
    for (const app of [...body.applications].sort((a, b) => byString(a.id, b.id))) {
        const permissions = permissionsOf(app);
        const high = permissions.filter((p) => p.classes !== null && p.classes.length > 0);
        const unknownHere = permissions.filter((p) => p.classes === null);
        for (const p of unknownHere) {
            const name = p.name ?? `role:${p.roleId ?? ''}`;
            unknown.set(`${p.via}\u0000${p.resourceAppId ?? ''}\u0000${name}`, { via: p.via, resourceAppId: p.resourceAppId, name });
        }
        const allRead = grantsReadInFull(app);
        const unreadable = unreadablePermissionsOf(app);
        const anyGrant = permissions.length > 0 || unreadable > 0;
        const classes = PERMISSION_CLASS_ORDER.filter((c) => high.some((p) => p.classes?.includes(c)));
        const privilege: PlannedApplication['privilege'] = high.length > 0 ? 'HIGH' : allRead && unknownHere.length === 0 && unreadable === 0 ? 'NOT_HIGH' : 'NOT_CONCLUDED';
        const notHere = (code: IntegrationFindingCode, why: IntegrationNotConcludedWhy) =>
            notConcluded.push({ code, applicationId: app.id, sourceKind: app.sourceKind, why });

        // HIGH_PRIVILEGE_GRANT: a presence; its absence only from a whole, known read.
        if (privilege === 'HIGH') {
            findings.push({
                code: 'INTEGRATION_HIGH_PRIVILEGE_GRANT',
                sourceRef: integrationFindingRef('INTEGRATION_HIGH_PRIVILEGE_GRANT', app.id),
                severity: INTEGRATION_FINDING_SEVERITY.INTEGRATION_HIGH_PRIVILEGE_GRANT,
                applicationId: app.id,
                title: `${nameOf(app)} holds a high-privilege grant`,
                description:
                    `It holds ${high.length === 1 ? 'a permission that reaches' : `${high.length} permissions that reach`} ${classes.map((c) => CLASS_WORDS[c]).join(', ')}: ` +
                    `${high.slice(0, 10).map(permissionWords).join(', ')}${high.length > 10 ? `, and ${high.length - 10} more` : ''}. ` +
                    'An application holding such a grant can read or change what it names for as long as the grant stands.',
            });
        } else if (privilege === 'NOT_CONCLUDED') {
            notHere('INTEGRATION_HIGH_PRIVILEGE_GRANT', allRead ? 'ONLY_UNKNOWN_PERMISSIONS' : 'GRANTS_NOT_READ_IN_FULL');
        }

        // Publisher, owner and sign-in are Entra's to answer; for the other products the source-wide entries above say why not.
        if (app.sourceKind !== 'entra-integrations') {
            planned.push({ id: app.id, privilege, highPermissions: high, unknownPermissions: unknownHere, classes, anyGrant, usage: 'NOT_CONCLUDED', daysSinceSignIn: null });
            continue;
        }

        // UNVERIFIED_PUBLISHER: only for another directory's application, and only on a high grant.
        if (app.origin !== 'THIS_DIRECTORY' && app.publisherVerified !== true) {
            if (privilege === 'HIGH') {
                if (app.publisherVerified === false) {
                    findings.push({
                        code: 'INTEGRATION_UNVERIFIED_PUBLISHER',
                        sourceRef: integrationFindingRef('INTEGRATION_UNVERIFIED_PUBLISHER', app.id),
                        severity: INTEGRATION_FINDING_SEVERITY.INTEGRATION_UNVERIFIED_PUBLISHER,
                        applicationId: app.id,
                        title: `${nameOf(app)} holds a high-privilege grant and its publisher is not verified`,
                        description:
                            'The directory records no verified publisher for this application, which is registered outside the directory that was read. ' +
                            'Nobody has shown who publishes it, and it holds a grant that reaches the directory, mail, files, chats, calendars or a write.',
                    });
                } else {
                    notHere('INTEGRATION_UNVERIFIED_PUBLISHER', 'PUBLISHER_NOT_KNOWN');
                }
            } else if (privilege === 'NOT_CONCLUDED') {
                notHere('INTEGRATION_UNVERIFIED_PUBLISHER', allRead ? 'ONLY_UNKNOWN_PERMISSIONS' : 'GRANTS_NOT_READ_IN_FULL');
            }
        }

        // NO_OWNER: any grant seen, and owners read and empty.
        if (anyGrant) {
            if (app.owners === null) {
                notHere('INTEGRATION_NO_OWNER', 'OWNERS_NOT_READ');
            } else if (app.owners.length === 0) {
                findings.push({
                    code: 'INTEGRATION_NO_OWNER',
                    sourceRef: integrationFindingRef('INTEGRATION_NO_OWNER', app.id),
                    severity: INTEGRATION_FINDING_SEVERITY.INTEGRATION_NO_OWNER,
                    applicationId: app.id,
                    title: `${nameOf(app)} holds a grant and has no owner`,
                    description:
                        'The application holds access granted in the directory, and the directory records no owner for it. ' +
                        'Nobody is on record to say whether it still needs that access, or to answer for it.',
                });
            }
        } else if (!allRead && (app.owners === null || app.owners.length === 0)) {
            notHere('INTEGRATION_NO_OWNER', 'GRANTS_NOT_READ_IN_FULL');
        }

        // UNUSED: only where sign-in activity was read for this application.
        let usage: PlannedApplication['usage'] = 'NOT_CONCLUDED';
        let daysSinceSignIn: number | null = null;
        if (app.signIn.read) {
            daysSinceSignIn = app.signIn.lastSeen === null ? null : wholeDays(app.signIn.lastSeen, body.scan.asOf);
            usage = daysSinceSignIn !== null && daysSinceSignIn <= unusedDays ? 'USED' : 'UNUSED';
            if (usage === 'UNUSED') {
                findings.push({
                    code: 'INTEGRATION_UNUSED',
                    sourceRef: integrationFindingRef('INTEGRATION_UNUSED', app.id),
                    severity: INTEGRATION_FINDING_SEVERITY.INTEGRATION_UNUSED,
                    applicationId: app.id,
                    title: `${nameOf(app)} has not signed in within ${unusedDays} days`,
                    description:
                        (app.signIn.lastSeen === null
                            ? 'The directory records no sign-in by this application.'
                            : `Its last recorded sign-in was on ${app.signIn.lastSeen}, ${daysSinceSignIn} days before the scan.`) +
                        ` That is outside the ${unusedDays}-day window the client set. An application nobody uses still holds whatever it was granted.`,
                });
            }
        } else {
            const source = body.sources.find((s) => s.kind === app.sourceKind);
            // Not configured is said once per source, above; a partial read is said per application.
            if (source !== undefined && source.signInActivity.status === 'INCOMPLETE') notHere('INTEGRATION_UNUSED', 'SIGN_IN_READ_INCOMPLETE');
        }

        planned.push({ id: app.id, privilege, highPermissions: high, unknownPermissions: unknownHere, classes, anyGrant, usage, daysSinceSignIn });
    }

    const order = (code: IntegrationFindingCode) => INTEGRATION_FINDING_CODES.indexOf(code);
    findings.sort((a, b) => (a.applicationId === null) !== (b.applicationId === null) ? (a.applicationId === null ? -1 : 1) : byString(a.applicationId ?? a.sourceRef, b.applicationId ?? b.sourceRef) || order(a.code) - order(b.code));
    return {
        unusedDays,
        applications: planned,
        findings,
        notConcluded,
        unknownPermissionNames: [...unknown.values()].sort((a, b) => byString(a.via, b.via) || byString(a.resourceAppId ?? '', b.resourceAppId ?? '') || byString(a.name, b.name)),
    };
}
