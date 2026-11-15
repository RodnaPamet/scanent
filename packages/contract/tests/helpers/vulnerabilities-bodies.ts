/**
 * Bodies of `scanent-vulnerabilities/1` reports, as a scanner would write
 * them, for the contract's and the planner's tests.
 */
import type { VulnerabilitiesReportBody, VulnerabilityFinding } from '../../src/vulnerabilities-contract';

export const HASH = `sha256:${'a'.repeat(64)}`;

export function finding(over: Partial<VulnerabilityFinding> = {}): VulnerabilityFinding {
    return {
        id: '0123456789abcdef',
        attackClass: 'injection',
        title: 'User-supplied name reaches a SQL query unescaped',
        trace: [
            { kind: 'entrypoint', locator: 'code://shop/src/routes/users.ts#L6-L7' },
            { kind: 'sink', locator: 'code://shop/src/routes/users.ts#L8-L9' },
        ],
        cwe: 'CWE-89',
        owasp: 'A03',
        owaspApi: null,
        attack: 'T1190',
        verdict: 'confirmed',
        confidence: 'high',
        severity: 'HIGH',
        condition: 'Any caller of the search route controls the name query parameter.',
        remediation: 'Pass the name as a bound parameter of the query.',
        toValidate: null,
        ...over,
    };
}

export function body(over: Partial<VulnerabilitiesReportBody> = {}): VulnerabilitiesReportBody {
    return {
        contract: 'scanent-vulnerabilities/1',
        scan: { id: 'scan-1', asOf: '2026-11-15T10:00:00.000Z', scanner: { agentId: 'scanner-1', version: '0.17.0', manifestHash: HASH } },
        run: {
            status: 'COMPLETE',
            model: { provider: 'anthropic', host: 'api.anthropic.com', model: 'claude-test', revision: 'claude-test-20261101' },
            evaluation: { recordDigest: HASH, corpusDigest: HASH },
            budgets: { tokens: 100000, files: 50, seconds: 600 },
            used: { tokens: 1200, files: 2, seconds: 30 },
        },
        repositories: [{ label: 'shop', status: 'REVIEWED', selectedFiles: 2 }],
        notReviewed: [],
        sent: ['code://shop/src/routes/users.ts#L1-L11'],
        counts: { candidates: 2, rejected: 1, discarded: 0 },
        findings: [finding()],
        ...over,
    };
}

/** A run that did not run because no model is configured: the default. */
export function notRunBody(): VulnerabilitiesReportBody {
    return body({
        run: { status: 'NOT_RUN', reason: 'MODEL_NOT_CONFIGURED', model: null, evaluation: null, budgets: { tokens: 0, files: 0, seconds: 0 }, used: { tokens: 0, files: 0, seconds: 0 } },
        repositories: [{ label: 'shop', status: 'NOT_REVIEWED', selectedFiles: 0 }],
        sent: [],
        counts: { candidates: 0, rejected: 0, discarded: 0 },
        findings: [],
    });
}
