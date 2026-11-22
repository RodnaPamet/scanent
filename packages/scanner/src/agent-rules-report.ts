/**
 * FROM THE `mcp` SOURCE'S RULE FINDINGS TO A SIGNED `scanent-agent-rules/1` REPORT.
 *
 * Built against the contract's own schema and checked with it before it is
 * signed, as the agent and integrations reports are: a body the contract would
 * refuse is refused here, and the signing is theirs (`signCheckedBody`): the
 * secret-shape walk, the wire bytes, the byte cap.
 *
 * What the builder decides:
 *
 *   • THE POPULATION SAYS HOW MUCH WAS READ. One `mcp-tool` entry: COMPLETE only
 *     when every `mcp` read reached the end and no field was longer than the
 *     rules scan. Otherwise INCOMPLETE with the read's own reason, or BYTE_CAP
 *     for a field past the cap. A partial read keeps its findings — what was
 *     read is real — and concludes nothing clean.
 *   • NO TEXT, EVER. The source never handed the text over: a finding here is
 *     a code, a rule, a subject and a locator.
 *   • PAST THE FINDINGS CAP, THE MOST SEVERE ARE KEPT, and the population says
 *     BYTE_CAP, rather than the report failing to sign.
 */
import type { KeyObject } from 'crypto';

import {
    AGENT_RULE_SEVERITIES,
    AGENT_RULES_CONTRACT_V1,
    AgentRulesReportBodyV1Schema,
    MAX_AGENT_RULE_FINDINGS,
    type AgentRuleFinding,
    type AgentRulesReportBody,
} from '@rodnapamet/scanent-contract/agent-rules-contract';

import { ReportRefusedLocally, signCheckedBody, type ScanIdentity } from './report';
import { SCANNER_VERSION, scannerManifestHash } from './scanner-surface';
import type { IncompleteReason, SourceRead } from './source';

const severityRank = (s: AgentRuleFinding['severity']) => AGENT_RULE_SEVERITIES.indexOf(s);

/** Build the report body from the agent scanner's reads. Pure: no clock, no I/O. Reads other than `mcp` are ignored. */
export function buildAgentRulesReportBody(identity: ScanIdentity, reads: readonly SourceRead[]): AgentRulesReportBody {
    const mcp = reads.filter((r) => r.kind === 'mcp');
    const all: AgentRuleFinding[] = mcp
        .flatMap((r) => r.ruleFindings ?? [])
        .map((f) => ({ code: f.code, ruleId: f.ruleId, severity: f.severity, subjectKind: 'mcp-tool' as const, subjectRef: f.subjectRef, locator: f.locator }));

    // Most severe first, then a stable order, so the cap keeps the findings that matter.
    all.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || (a.locator < b.locator ? -1 : a.locator > b.locator ? 1 : 0) || (a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0));
    const capped = all.length > MAX_AGENT_RULE_FINDINGS;
    const findings = capped ? all.slice(0, MAX_AGENT_RULE_FINDINGS) : all;

    const subjects = mcp.reduce((n, r) => n + (r.ruleSubjects ?? 0), 0);
    const stopped = mcp.find((r) => r.status === 'INCOMPLETE');
    const truncated = mcp.some((r) => (r.ruleTextTruncated ?? 0) > 0);
    const reason: IncompleteReason | null = stopped !== undefined ? (stopped.reason ?? 'UNREACHABLE') : truncated || capped ? 'BYTE_CAP' : null;

    return {
        contract: AGENT_RULES_CONTRACT_V1,
        scan: {
            id: identity.scanId,
            asOf: identity.asOf.toISOString(),
            scanner: { agentId: identity.scannerAgentId, version: SCANNER_VERSION, manifestHash: scannerManifestHash() },
        },
        population: [reason === null ? { kind: 'mcp-tool', status: 'COMPLETE', subjects } : { kind: 'mcp-tool', status: 'INCOMPLETE', reason, subjects }],
        findings,
        counts: { subjects, flagged: new Set(findings.map((f) => f.subjectRef)).size },
    };
}

/** Check the body against `scanent-agent-rules/1`, then sign it as every report is signed. Paths only in a refusal. */
export function signAgentRulesReport(body: AgentRulesReportBody, keys: { privateKey: KeyObject; publicKey: KeyObject }): string {
    const parsed = AgentRulesReportBodyV1Schema.safeParse(body);
    if (!parsed.success) {
        throw new ReportRefusedLocally(parsed.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.code}`));
    }
    return signCheckedBody(parsed.data, keys);
}
