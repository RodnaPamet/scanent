/**
 * `integrations.csv` and `integration-findings.csv` — the integrations
 * scanner's results for a spreadsheet, written only by a run that configured
 * it.
 *
 * The agent CSVs' rules, by the agent CSVs' own function (`csvFile`, which
 * writes every cell through `csvCell`): RFC 4180, a byte-order mark, a cell a
 * spreadsheet would read as a formula shown and never evaluated. A display
 * name is the directory's, written by whoever registered the application, and
 * is held to that rule like every other cell.
 *
 * A value that was not read is written as `NOT_READ`, never as an empty cell
 * or a zero: an empty list of owners and owners nobody read are two answers.
 */
import type { LocalApplicationPermission, LocalApplicationResult, LocalIntegrationsResults } from '../results/types';
import { csvFile } from './csv';

export const INTEGRATIONS_CSV_COLUMNS = [
    'applicationId',
    'displayName',
    'appId',
    'source',
    'origin',
    'publisherVerified',
    'owners',
    'ownerRefs',
    'delegatedGrantsRead',
    'delegatedScopes',
    'grantedFor',
    'applicationPermissionsRead',
    'applicationPermissions',
    'privilege',
    'classes',
    'highPermissions',
    'unknownPermissions',
    'signInRead',
    'lastSignIn',
    'daysSinceSignIn',
    'usage',
    'credentials',
    'findings',
] as const;

/** A permission in a cell: `<name>` on Microsoft Graph's own table, else `<api app id>/<name>`. */
const permissionCell = (p: LocalApplicationPermission): string => `${p.resourceAppId === null ? 'unknown-api' : p.resourceAppId}/${p.name ?? 'unresolved-role'} (${p.via === 'DELEGATED' ? 'delegated' : 'application'})`;

function applicationRow(app: LocalApplicationResult, findings: readonly string[]): (string | number)[] {
    const grants = app.delegatedGrants.grants;
    return [
        app.id,
        app.displayName ?? '',
        app.appId ?? '',
        app.sourceKind,
        app.origin,
        app.publisherVerified === null ? 'unknown' : app.publisherVerified ? 'yes' : 'no',
        app.owners === null ? 'NOT_READ' : app.owners.length,
        app.owners === null ? '' : app.owners.map((o) => `${o.kind}:${o.id}`).join(';'),
        app.delegatedGrants.read ? 'yes' : 'no',
        grants.flatMap((g) => g.scopes.map((s) => `${g.resourceAppId ?? 'unknown-api'}/${s}`)).join(';'),
        // Who a grant was made for, counted and never named.
        grants.map((g) => (g.consentType === 'AllPrincipals' ? 'everyone' : `${g.principalCount ?? 0} people`)).join(';'),
        app.applicationPermissions.read ? 'yes' : 'no',
        app.applicationPermissions.permissions.map((p) => `${p.resourceAppId ?? 'unknown-api'}/${p.name ?? `role:${p.roleId}`}`).join(';'),
        app.privilege,
        app.classes.join(';'),
        app.highPermissions.map(permissionCell).join(';'),
        app.unknownPermissions.map(permissionCell).join(';'),
        app.signIn.read ? 'yes' : 'no',
        app.signIn.read ? (app.signIn.lastSeen ?? 'never') : 'NOT_READ',
        app.signIn.daysSince ?? '',
        app.usage,
        app.credentials,
        findings.join(';'),
    ];
}

/** One row per application; a header and no rows for an empty inventory. */
export function renderIntegrationsCsv(integrations: LocalIntegrationsResults): string {
    const byApp = new Map<string, string[]>();
    for (const f of integrations.findings) if (f.applicationId !== null) byApp.set(f.applicationId, [...(byApp.get(f.applicationId) ?? []), f.code]);
    return csvFile(INTEGRATIONS_CSV_COLUMNS, integrations.applications.map((a) => applicationRow(a, byApp.get(a.id) ?? [])));
}

export const INTEGRATION_FINDINGS_CSV_COLUMNS = ['code', 'severity', 'sourceRef', 'applicationId', 'displayName', 'title', 'description'] as const;

/** One row per finding, in the planner's order. */
export function renderIntegrationFindingsCsv(integrations: LocalIntegrationsResults): string {
    const names = new Map(integrations.applications.map((a) => [a.id, a.displayName ?? '']));
    return csvFile(
        INTEGRATION_FINDINGS_CSV_COLUMNS,
        integrations.findings.map((f) => [f.code, f.severity, f.sourceRef, f.applicationId ?? '', f.applicationId === null ? '' : (names.get(f.applicationId) ?? ''), f.title, f.description]),
    );
}
