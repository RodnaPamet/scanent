/**
 * THE INTEGRATIONS SCANNER'S LOCAL RESULTS — the `integrations` section of
 * `results.json`, from one `scanent-integrations/1` body.
 *
 * Every conclusion is the contract's planner's (`planIntegrationsScan`): this
 * module arranges what the planner decided beside what the report read, and
 * decides nothing of its own. Pure: the caller hands it the hash of the signed
 * bytes, the window "unused" is measured over, and what the sources said about
 * a read that stopped.
 */
import type { IntegrationsReportBody } from '@rodnapamet/scanent-contract/integrations-contract';
import { isIntegrationsScanComplete } from '@rodnapamet/scanent-contract/integrations-contract-rules';
import { planIntegrationsScan } from '@rodnapamet/scanent-contract/integrations-findings';

import type { LocalApplicationPermission, LocalIntegrationsResults, SourceNote } from './types';

export interface IntegrationsScoreInput {
    readonly body: IntegrationsReportBody;
    readonly unusedDays: number;
    /** The file the signed report is written as, and the SHA-256 (hex) of its bytes. */
    readonly report: { readonly file: string; readonly sha256: string };
    /** The run's own words about a read that stopped. Absent when scored without the run. */
    readonly sourceNotes?: readonly SourceNote[];
}

const permission = (p: { readonly via: 'DELEGATED' | 'APPLICATION'; readonly resourceAppId: string | null; readonly name: string | null }): LocalApplicationPermission => ({
    via: p.via,
    resourceAppId: p.resourceAppId,
    name: p.name,
});

export function scoreIntegrationsLocally(input: IntegrationsScoreInput): LocalIntegrationsResults {
    const { body } = input;
    const plan = planIntegrationsScan(body, { unusedDays: input.unusedDays });
    const planned = new Map(plan.applications.map((a) => [a.id, a]));
    const notes = new Map((input.sourceNotes ?? []).map((n) => [n.kind, n]));
    const applications = [...body.applications]
        .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
        .map((app) => {
            const p = planned.get(app.id);
            if (p === undefined) throw new Error('the planner left out an application of the report');
            return {
                id: app.id,
                sourceKind: app.sourceKind,
                appId: app.appId,
                displayName: app.displayName,
                origin: app.origin,
                publisherVerified: app.publisherVerified,
                owners: app.owners === null ? null : app.owners.map((o) => ({ kind: o.kind, id: o.id })),
                delegatedGrants: {
                    read: app.delegatedGrants.read,
                    grants: app.delegatedGrants.grants.map((g) => ({
                        resourceAppId: g.resourceAppId,
                        consentType: g.consentType,
                        principalCount: g.principalCount,
                        scopes: [...g.scopes],
                        unreadableScopes: g.unreadableScopes,
                    })),
                },
                applicationPermissions: {
                    read: app.applicationPermissions.read,
                    permissions: app.applicationPermissions.permissions.map((x) => ({ resourceAppId: x.resourceAppId, roleId: x.roleId, name: x.name })),
                },
                privilege: p.privilege,
                classes: [...p.classes],
                highPermissions: p.highPermissions.map(permission),
                unknownPermissions: p.unknownPermissions.map(permission),
                signIn: { read: app.signIn.read, lastSeen: app.signIn.lastSeen, daysSince: p.daysSinceSignIn },
                usage: p.usage,
                credentials: app.credentials.length,
            };
        });
    const count = (code: string) => plan.findings.filter((f) => f.code === code).length;
    return {
        contract: body.contract,
        report: { file: input.report.file, sha256: input.report.sha256 },
        complete: isIntegrationsScanComplete(body),
        unusedDays: plan.unusedDays,
        sources: body.sources.map((s) => {
            const detail = notes.get(s.kind)?.detail ?? null;
            const stopped = s.status !== 'COMPLETE' || s.signInActivity.status === 'INCOMPLETE';
            return {
                kind: s.kind,
                status: s.status,
                reason: s.reason ?? null,
                rows: s.rows,
                applications: body.applications.filter((a) => a.sourceKind === s.kind).length,
                signInActivity: {
                    status: s.signInActivity.status,
                    reason: s.signInActivity.status === 'INCOMPLETE' ? s.signInActivity.reason : null,
                    rows: s.signInActivity.status === 'NOT_READ' ? null : s.signInActivity.rows,
                },
                ...(stopped && detail !== null ? { detail } : {}),
            };
        }),
        applications,
        findings: plan.findings.map((f) => ({ code: f.code, sourceRef: f.sourceRef, severity: f.severity, applicationId: f.applicationId, title: f.title, description: f.description })),
        notConcluded: plan.notConcluded.map((n) => ({ code: n.code, applicationId: n.applicationId, sourceKind: n.sourceKind, why: n.why })),
        unknownPermissions: plan.unknownPermissionNames.map((u) => ({ resourceAppId: u.resourceAppId, name: u.name })),
        counts: {
            applications: applications.length,
            highPrivilege: count('INTEGRATION_HIGH_PRIVILEGE_GRANT'),
            unverifiedPublisher: count('INTEGRATION_UNVERIFIED_PUBLISHER'),
            noOwner: count('INTEGRATION_NO_OWNER'),
            unused: count('INTEGRATION_UNUSED'),
        },
    };
}
