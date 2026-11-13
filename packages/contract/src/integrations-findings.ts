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
 *                                             application at all
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
 */
import type { IntegrationsReportApplication, IntegrationsReportBody } from './integrations-contract';
import { classifyPermission, type PermissionClass } from './integrations-scopes';

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

/** One permission an application holds, as the planner read it. */
export interface PlannedPermission {
    readonly via: 'DELEGATED' | 'APPLICATION';
    readonly resourceAppId: string | null;
    /** The scope or role name; null when the read could not resolve the role. */
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
    /** Every permission name the table does not know, once per API, sorted. */
    readonly unknownPermissionNames: readonly { readonly resourceAppId: string | null; readonly name: string }[];
}

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

/** The permissions an application holds, delegated then application, as read. */
export function permissionsOf(app: Pick<IntegrationsReportApplication, 'delegatedGrants' | 'applicationPermissions'>): PlannedPermission[] {
    const out: PlannedPermission[] = [];
    for (const g of app.delegatedGrants.grants) {
        for (const scope of g.scopes) {
            const c = classifyPermission(g.resourceAppId, scope);
            out.push({ via: 'DELEGATED', resourceAppId: g.resourceAppId, name: scope, roleId: null, classes: c.known ? c.classes : null });
        }
    }
    for (const p of app.applicationPermissions.permissions) {
        const c = classifyPermission(p.resourceAppId, p.name);
        out.push({ via: 'APPLICATION', resourceAppId: p.resourceAppId, name: p.name, roleId: p.roleId, classes: c.known ? c.classes : null });
    }
    return out;
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

const permissionWords = (p: PlannedPermission): string => `${p.name ?? `role ${p.roleId ?? 'unknown'}`} (${p.via === 'DELEGATED' ? 'delegated' : 'application'})`;

function nameOf(app: IntegrationsReportApplication): string {
    return app.displayName === null ? app.id : `${app.displayName} (${app.id})`;
}

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
    const unknown = new Map<string, { resourceAppId: string | null; name: string }>();

    // ── The sources: an empty inventory, and sign-in activity not read ──
    for (const source of [...body.sources].sort((a, b) => byString(a.kind, b.kind))) {
        const apps = body.applications.filter((a) => a.sourceKind === source.kind);
        if (apps.length === 0) {
            if (source.status === 'COMPLETE') {
                findings.push({
                    code: 'INTEGRATION_EMPTY_INVENTORY',
                    sourceRef: integrationFindingRef('INTEGRATION_EMPTY_INVENTORY', source.kind),
                    severity: INTEGRATION_FINDING_SEVERITY.INTEGRATION_EMPTY_INVENTORY,
                    applicationId: null,
                    title: `${source.kind} was read in full and holds no application`,
                    description:
                        `The source ${source.kind} was read in full (${source.rows} rows) and reported no application a directory has granted access to. ` +
                        'That is not a clean result: a directory in use holds applications, and an empty answer is what a read of the wrong directory, ' +
                        'or one made through a credential that sees a filtered view, looks like. Check the directory id and the permissions the reading application holds.',
                });
            } else {
                notConcluded.push({ code: 'INTEGRATION_EMPTY_INVENTORY', applicationId: null, sourceKind: source.kind, why: 'SOURCE_INCOMPLETE' });
            }
        }
        if (source.signInActivity.status === 'NOT_READ' && apps.length > 0) {
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
            unknown.set(`${p.resourceAppId ?? ''}\u0000${name}`, { resourceAppId: p.resourceAppId, name });
        }
        const allRead = app.delegatedGrants.read && app.applicationPermissions.read;
        const anyGrant = permissions.length > 0 || app.delegatedGrants.grants.some((g) => g.unreadableScopes > 0);
        const classes = PERMISSION_CLASS_ORDER.filter((c) => high.some((p) => p.classes?.includes(c)));
        const privilege: PlannedApplication['privilege'] = high.length > 0 ? 'HIGH' : allRead && unknownHere.length === 0 && !app.delegatedGrants.grants.some((g) => g.unreadableScopes > 0) ? 'NOT_HIGH' : 'NOT_CONCLUDED';
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
        unknownPermissionNames: [...unknown.values()].sort((a, b) => byString(a.resourceAppId ?? '', b.resourceAppId ?? '') || byString(a.name, b.name)),
    };
}
