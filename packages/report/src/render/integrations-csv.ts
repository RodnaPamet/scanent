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
 * A question the application's product does not answer is `NOT_EXPOSED`, and
 * another product's column is `n/a`. Each row names its product.
 */
import {
    INTEGRATIONS_PRODUCT_TITLE,
    INTEGRATIONS_SOURCE_KINDS,
    productOfApplicationId,
    type IntegrationsSourceKind,
} from '@rodnapamet/scanent-contract/integrations-contract-rules';

import type { LocalApplicationPermission, LocalApplicationResult, LocalIntegrationsResults } from '../results/types';
import { csvFile } from './csv';

export const INTEGRATIONS_CSV_COLUMNS = [
    'applicationId',
    'product',
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
    'oktaScopesRead',
    'oktaScopes',
    'githubPermissionsRead',
    'githubPermissions',
    'repositorySelection',
    'status',
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

/**
 * A cell the product does not have: `NOT_EXPOSED` for a question its API does
 * not answer (an owner, a publisher, a sign-in), `n/a` for another product's
 * member. Neither is an empty cell, which would read as "none".
 */
const NOT_EXPOSED = 'NOT_EXPOSED';
const NA = 'n/a';

/** A permission in a cell: `<api app id>/<name>` for Entra, `okta/<scope>` and `github/<name>:<level>` for the others. */
const permissionCell = (p: LocalApplicationPermission): string =>
    p.via === 'OKTA_SCOPE'
        ? `okta/${p.name ?? 'unreadable'} (scope)`
        : p.via === 'GITHUB_PERMISSION'
            ? `github/${p.name ?? 'unreadable'} (installation)`
            : `${p.resourceAppId === null ? 'unknown-api' : p.resourceAppId}/${p.name ?? 'unresolved-role'} (${p.via === 'DELEGATED' ? 'delegated' : 'application'})`;

const yesNo = (v: boolean): string => (v ? 'yes' : 'no');

function applicationRow(app: LocalApplicationResult, findings: readonly string[]): (string | number)[] {
    const entra = app.sourceKind === 'entra-integrations' ? app : null;
    const okta = app.sourceKind === 'okta-integrations' ? app : null;
    const github = app.sourceKind === 'github-integrations' ? app : null;
    const notEntra = entra === null ? NOT_EXPOSED : null;
    const grants = entra?.delegatedGrants.grants ?? [];
    return [
        app.id,
        INTEGRATIONS_PRODUCT_TITLE[app.sourceKind],
        app.displayName ?? '',
        app.appId ?? '',
        app.sourceKind,
        entra?.origin ?? NA,
        notEntra ?? (entra?.publisherVerified === null ? 'unknown' : entra?.publisherVerified ? 'yes' : 'no'),
        notEntra ?? (entra?.owners === null || entra === null ? 'NOT_READ' : entra.owners.length),
        entra?.owners === null || entra === null ? '' : entra.owners.map((o) => `${o.kind}:${o.id}`).join(';'),
        entra === null ? NA : yesNo(entra.delegatedGrants.read),
        grants.flatMap((g) => g.scopes.map((sc) => `${g.resourceAppId ?? 'unknown-api'}/${sc}`)).join(';'),
        // Who a grant was made for, counted and never named.
        grants.map((g) => (g.consentType === 'AllPrincipals' ? 'everyone' : `${g.principalCount ?? 0} people`)).join(';'),
        entra === null ? NA : yesNo(entra.applicationPermissions.read),
        (entra?.applicationPermissions.permissions ?? []).map((p) => `${p.resourceAppId ?? 'unknown-api'}/${p.name ?? `role:${p.roleId}`}`).join(';'),
        okta === null ? NA : yesNo(okta.scopeGrants.read),
        (okta?.scopeGrants.scopes ?? []).join(';'),
        github === null ? NA : yesNo(github.permissions.read),
        (github?.permissions.grants ?? []).map((g) => `${g.name}:${g.level}`).join(';'),
        github === null ? NA : (github.repositorySelection ?? 'unknown'),
        okta !== null ? (okta.status ?? 'unknown') : github !== null ? (github.suspended === null ? 'unknown' : github.suspended ? 'SUSPENDED' : 'ACTIVE') : NA,
        app.privilege,
        app.classes.join(';'),
        app.highPermissions.map(permissionCell).join(';'),
        app.unknownPermissions.map(permissionCell).join(';'),
        notEntra ?? (entra?.signIn.read ? 'yes' : 'no'),
        notEntra ?? (entra?.signIn.read ? (entra.signIn.lastSeen ?? 'never') : 'NOT_READ'),
        entra?.signIn.daysSince ?? '',
        app.usage,
        entra === null ? NA : entra.credentials,
        findings.join(';'),
    ];
}

/** One row per application; a header and no rows for an empty inventory. */
export function renderIntegrationsCsv(integrations: LocalIntegrationsResults): string {
    const byApp = new Map<string, string[]>();
    for (const f of integrations.findings) if (f.applicationId !== null) byApp.set(f.applicationId, [...(byApp.get(f.applicationId) ?? []), f.code]);
    return csvFile(INTEGRATIONS_CSV_COLUMNS, integrations.applications.map((a) => applicationRow(a, byApp.get(a.id) ?? [])));
}

export const INTEGRATION_FINDINGS_CSV_COLUMNS = ['code', 'severity', 'sourceRef', 'product', 'applicationId', 'displayName', 'title', 'description'] as const;

/** The product a finding is about: its application's, or for a finding about a source, the source's. */
function findingProduct(f: { readonly applicationId: string | null; readonly sourceRef: string }): string {
    if (f.applicationId !== null) return productOfApplicationId(f.applicationId);
    const kind = f.sourceRef.slice(f.sourceRef.lastIndexOf(':') + 1);
    return (INTEGRATIONS_SOURCE_KINDS as readonly string[]).includes(kind) ? INTEGRATIONS_PRODUCT_TITLE[kind as IntegrationsSourceKind] : 'Unknown product';
}

/** One row per finding, in the planner's order. */
export function renderIntegrationFindingsCsv(integrations: LocalIntegrationsResults): string {
    const names = new Map(integrations.applications.map((a) => [a.id, a.displayName ?? '']));
    return csvFile(
        INTEGRATION_FINDINGS_CSV_COLUMNS,
        integrations.findings.map((f) => [f.code, f.severity, f.sourceRef, findingProduct(f), f.applicationId ?? '', f.applicationId === null ? '' : (names.get(f.applicationId) ?? ''), f.title, f.description]),
    );
}
