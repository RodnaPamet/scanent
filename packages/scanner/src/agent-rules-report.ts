/**
 * FROM THE RULE FINDINGS OF THE `mcp` AND `code` SOURCES TO A SIGNED
 * `scanent-agent-rules/1` REPORT.
 *
 * Built against the contract's own schema and checked with it before it is
 * signed, as the agent and integrations reports are: a body the contract would
 * refuse is refused here, and the signing is theirs (`signCheckedBody`): the
 * secret-shape walk, the wire bytes, the byte cap.
 *
 * What the builder decides:
 *
 *   • THE POPULATION SAYS HOW MUCH WAS READ. One entry per subject kind a
 *     source read — `mcp-tool` from the `mcp` source, `skill` and `skill-file`
 *     from the `code` source — COMPLETE only when every origin of its family
 *     was read in full. Otherwise INCOMPLETE with the first such origin's
 *     reason. A partial read keeps its findings — what was read is real — and
 *     concludes nothing clean.
 *   • NO TEXT, EVER. The source never handed the text over: a finding here is
 *     a code, a rule, a subject and a locator.
 *   • PAST THE FINDINGS CAP, THE MOST SEVERE ARE KEPT, and every population
 *     and every origin says BYTE_CAP, rather than the report failing to sign:
 *     a cut list cannot vouch that any origin's findings are all there, so
 *     none may be closed against.
 *   • EACH ORIGIN IS LISTED with how the rules read it, so a consumer closes a
 *     finding only against an origin read in full.
 */
import type { KeyObject } from 'crypto';

import {
    AGENT_RULE_SEVERITIES,
    AGENT_RULES_CONTRACT_V1,
    AGENT_RULES_SUBJECT_KINDS,
    AgentRulesReportBodyV1Schema,
    MAX_AGENT_RULE_FINDINGS,
    ORIGIN_FAMILY_OF_KIND,
    originFamily,
    type AgentRuleFinding,
    type AgentRulesOrigin,
    type AgentRulesPopulation,
    type AgentRulesReportBody,
    type AgentRulesSubjectKind,
} from '@rodnapamet/scanent-contract/agent-rules-contract';

import { ReportRefusedLocally, signCheckedBody, type ScanIdentity } from './report';
import { SCANNER_VERSION, scannerManifestHash } from './scanner-surface';
import type { SourceRead } from './source';

const severityRank = (s: AgentRuleFinding['severity']) => AGENT_RULE_SEVERITIES.indexOf(s);

/** The source kind that reads each subject kind: an MCP server's tools from `mcp`, a skill and its scripts from `code`. */
const SOURCE_OF_KIND: Readonly<Record<AgentRulesSubjectKind, SourceRead['kind']>> = Object.freeze({
    'mcp-tool': 'mcp',
    skill: 'code',
    'skill-file': 'code',
});

export { runsAgentRules } from './config';

/**
 * What a read of each source kind that carries no rule fields means. The `mcp`
 * source runs the rules on every tool it reads, so an `mcp` read without them
 * could not run them (its token missing): its kind is INCOMPLETE. A `code`
 * source reads skills unless told not to (`skills: false`), so a `code` read
 * without them was told not to, and adds no population.
 */
const UNRUN_IS_INCOMPLETE: Readonly<Record<string, boolean>> = Object.freeze({ mcp: true, code: false });

/**
 * Build the report body from the agent scanner's reads. Pure: no clock, no I/O.
 * A read of a source the rules run in that could not run them — its credential
 * missing, its read stopped before any origin — makes its kinds' populations
 * INCOMPLETE with its reason, over the subjects the other reads counted.
 */
export function buildAgentRulesReportBody(identity: ScanIdentity, reads: readonly SourceRead[]): AgentRulesReportBody {
    const ruled = reads.filter((r) => r.ruleOrigins !== undefined);
    const all: AgentRuleFinding[] = ruled
        .flatMap((r) => r.ruleFindings ?? [])
        .map((f) => ({ code: f.code, ruleId: f.ruleId, severity: f.severity, subjectKind: f.subjectKind, subjectRef: f.subjectRef, originRef: f.originRef, locator: f.locator }));

    // Most severe first, then a stable order, so the cap keeps the findings that matter.
    all.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || (a.locator < b.locator ? -1 : a.locator > b.locator ? 1 : 0) || (a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0));
    const capped = all.length > MAX_AGENT_RULE_FINDINGS;
    const findings = capped ? all.slice(0, MAX_AGENT_RULE_FINDINGS) : all;

    const origins: AgentRulesOrigin[] = ruled
        .flatMap((r) => r.ruleOrigins ?? [])
        .map((o): AgentRulesOrigin => (capped ? { ref: o.ref, status: 'INCOMPLETE', reason: 'BYTE_CAP', subjects: o.subjects } : { ...o }));

    const population: AgentRulesPopulation[] = [];
    for (const kind of AGENT_RULES_SUBJECT_KINDS) {
        const ofSource = reads.filter((r) => r.kind === SOURCE_OF_KIND[kind] && (r.ruleOrigins !== undefined || UNRUN_IS_INCOMPLETE[r.kind] === true));
        if (ofSource.length === 0) continue;
        const subjects = ofSource.reduce((n, r) => n + (r.ruleSubjects?.[kind] ?? 0), 0);
        // A read that could not run the rules says why first; then the first origin read in part.
        const unrun = ofSource.find((r) => r.ruleOrigins === undefined);
        const stopped = origins.find((o) => originFamily(o.ref) === ORIGIN_FAMILY_OF_KIND[kind] && o.status === 'INCOMPLETE');
        const reason = unrun !== undefined ? (unrun.reason ?? 'UNREACHABLE') : capped ? 'BYTE_CAP' : stopped?.reason ?? null;
        population.push(reason === null ? { kind, status: 'COMPLETE', subjects } : { kind, status: 'INCOMPLETE', reason, subjects });
    }

    return {
        contract: AGENT_RULES_CONTRACT_V1,
        scan: {
            id: identity.scanId,
            asOf: identity.asOf.toISOString(),
            scanner: { agentId: identity.scannerAgentId, version: SCANNER_VERSION, manifestHash: scannerManifestHash() },
        },
        population,
        origins,
        findings,
        counts: { subjects: population.reduce((n, p) => n + p.subjects, 0), flagged: new Set(findings.map((f) => f.locator.slice(0, f.locator.lastIndexOf('#')))).size },
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
