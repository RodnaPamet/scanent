/**
 * FROM INTEGRATIONS SOURCE READS TO A SIGNED `scanent-integrations/1` REPORT.
 *
 * Built against the contract's own schema and checked with it before it is
 * signed, as the agent report is (`report.ts`): a body the contract would
 * refuse is refused here, and the signing is the agent report's own
 * (`signCheckedBody`): the secret-shape walk, the wire bytes, the byte cap.
 *
 * What the builder decides:
 *
 *   • EVERY SOURCE IS LISTED, read or not, with its sign-in read's own status.
 *     Whether the scan was complete is derived by the reader.
 *   • NOTHING IS MERGED ACROSS SCANNERS. The agent report and this one share a
 *     scan id, a time and a key, and nothing else: an application here is not
 *     an agent there, and linking the two is not in this version.
 *   • NO FINDING IS STATED. The planner (`planIntegrationsScan`) is the
 *     reader's; a report carries what was read.
 */
import type { KeyObject } from 'crypto';

import {
    INTEGRATIONS_CONTRACT_V1,
    INTEGRATIONS_SOURCE_KINDS,
    IntegrationsReportBodyV1Schema,
    type IntegrationsReportBody,
} from '@rodnapamet/scanent-contract/integrations-contract';

import type { IntegrationsSourceRead } from './integrations-source';
import { ReportRefusedLocally, signCheckedBody, type ScanIdentity } from './report';
import { SCANNER_VERSION, scannerManifestHash } from './scanner-surface';

const kindOrder = (k: string) => (INTEGRATIONS_SOURCE_KINDS as readonly string[]).indexOf(k);

/** Build the report body. Pure: no clock, no I/O. */
export function buildIntegrationsReportBody(identity: ScanIdentity, reads: readonly IntegrationsSourceRead[]): IntegrationsReportBody {
    const ordered = [...reads].sort((a, b) => kindOrder(a.kind) - kindOrder(b.kind));
    return {
        contract: INTEGRATIONS_CONTRACT_V1,
        scan: {
            id: identity.scanId,
            asOf: identity.asOf.toISOString(),
            scanner: { agentId: identity.scannerAgentId, version: SCANNER_VERSION, manifestHash: scannerManifestHash() },
        },
        sources: ordered.map((r) => ({
            kind: r.kind,
            status: r.status,
            ...(r.status === 'INCOMPLETE' ? { reason: r.reason ?? 'UNREACHABLE' } : {}),
            rows: r.rows,
            signInActivity:
                r.signInActivity.status === 'NOT_READ'
                    ? { status: 'NOT_READ' as const }
                    : r.signInActivity.status === 'COMPLETE'
                        ? { status: 'COMPLETE' as const, rows: r.signInActivity.rows }
                        : { status: 'INCOMPLETE' as const, reason: r.signInActivity.reason, rows: r.signInActivity.rows },
        })),
        applications: ordered.flatMap((r) => r.applications).sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
    };
}

/** Check the body against `scanent-integrations/1`, then sign it as every report is signed. Paths only in a refusal. */
export function signIntegrationsReport(body: IntegrationsReportBody, keys: { privateKey: KeyObject; publicKey: KeyObject }): string {
    const parsed = IntegrationsReportBodyV1Schema.safeParse(body);
    if (!parsed.success) {
        throw new ReportRefusedLocally(parsed.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.code}`));
    }
    return signCheckedBody(parsed.data, keys);
}
