/**
 * The rules of the agent-rules report contract that need no hashing: its id,
 * its finding codes, its subject kinds, its severity ceilings and its limits.
 *
 * They live apart from `agent-rules-contract.ts` for the reason the harness's
 * and the integrations' do: the rule engine (`agent-rules.ts`), the planner
 * (`agent-rules-findings.ts`) and the evaluation scorer
 * (`agent-rules-evaluation.ts`) are things a browser may run, and the contract
 * verifies signatures with `crypto`. Keep this module free of Node built-ins.
 *
 * This is the fourth finding kind in the AGENT scanner: static rules over the
 * text the scanner already reads — an MCP tool's description, a skill, an A2A
 * card — re-authored from Cisco AI Defense's three scanners (Apache-2.0; the
 * skill rules from the MIT Agent Threat Rules). The rules run where the text
 * is and never let it leave; only a finding — a code, the rule id, the subject
 * and a locator — travels. No model, no new request. See
 * docs/design/agent-surface-rules.md.
 */

/**
 * The agent-rules scanner's first contract: what static rules found written
 * into an agent's own surface. A strict schema of its own beside the three
 * other contracts, verified by the same signature and canonical-JSON rules,
 * and read by nothing that reads them.
 */
export const AGENT_RULES_CONTRACT_V1 = 'scanent-agent-rules/1';

/** Every id the agent-rules verifier accepts. */
export const AGENT_RULES_CONTRACT_IDS = [AGENT_RULES_CONTRACT_V1] as const;
export type AgentRulesContractId = (typeof AGENT_RULES_CONTRACT_IDS)[number];

/**
 * What a rule reads. A closed list on the wire: version 1 reads an MCP tool's
 * definition text; skills and A2A cards are later versions and later kinds.
 */
export const AGENT_RULES_SUBJECT_KINDS = ['mcp-tool'] as const;
export type AgentRulesSubjectKind = (typeof AGENT_RULES_SUBJECT_KINDS)[number];

/** The subject kind in words, for the outputs. */
export const SUBJECT_KIND_TITLE: Readonly<Record<AgentRulesSubjectKind, string>> = Object.freeze({
    'mcp-tool': 'MCP tool definition',
});

/**
 * The finding codes version 1 raises, all about an MCP tool's text:
 *
 *   MCP_TOOL_POISONING        a hidden second behaviour, different from the
 *                             tool's stated purpose
 *   MCP_PROMPT_INJECTION      an instruction to the model written into the text
 *   MCP_COMMAND_INJECTION     an executable payload — a shell command, a
 *                             reverse shell, a download-and-run — in the text
 *   MCP_DATA_EXFILTRATION     an instruction to send data to an external place
 *   MCP_CREDENTIAL_HARVESTING a reference to reading or taking credentials
 */
export const AGENT_RULES_FINDING_CODES = [
    'MCP_TOOL_POISONING',
    'MCP_PROMPT_INJECTION',
    'MCP_COMMAND_INJECTION',
    'MCP_DATA_EXFILTRATION',
    'MCP_CREDENTIAL_HARVESTING',
] as const;
export type AgentRuleFindingCode = (typeof AGENT_RULES_FINDING_CODES)[number];

/** Severities, lowest first. There is no CRITICAL: no rule finding is ever one. */
export const AGENT_RULE_SEVERITIES = ['INFO', 'LOW', 'MEDIUM', 'HIGH'] as const;
export type AgentRuleSeverity = (typeof AGENT_RULE_SEVERITIES)[number];

const rank = (s: AgentRuleSeverity): number => AGENT_RULE_SEVERITIES.indexOf(s);

/**
 * The highest severity a code may carry. The two
 * codes whose match is an unambiguous attack — an executable payload, a direct
 * instruction to the model — may reach HIGH; the three suggestive ones (a
 * description that reads as poisoning, exfiltration or credential access) are
 * at most MEDIUM. A person confirms every finding either way, and none is
 * CRITICAL. A rule declares its own ceiling, which the code's ceiling bounds.
 */
export const SEVERITY_CEILING: Readonly<Record<AgentRuleFindingCode, AgentRuleSeverity>> = Object.freeze({
    MCP_COMMAND_INJECTION: 'HIGH',
    MCP_PROMPT_INJECTION: 'HIGH',
    MCP_TOOL_POISONING: 'MEDIUM',
    MCP_DATA_EXFILTRATION: 'MEDIUM',
    MCP_CREDENTIAL_HARVESTING: 'MEDIUM',
});

/** Whether `severity` is within its code's ceiling. */
export function withinCeiling(code: AgentRuleFindingCode, severity: AgentRuleSeverity): boolean {
    return rank(severity) <= rank(SEVERITY_CEILING[code]);
}

/**
 * A severity held to its code's ceiling. A value that is not one of the four
 * (CRITICAL included) is taken as the ceiling: a rule that declares higher is
 * lowered, never trusted.
 */
export function capRuleSeverity(code: AgentRuleFindingCode, declared: string): AgentRuleSeverity {
    const ceiling = SEVERITY_CEILING[code];
    const known = (AGENT_RULE_SEVERITIES as readonly string[]).includes(declared) ? (declared as AgentRuleSeverity) : ceiling;
    return rank(known) <= rank(ceiling) ? known : ceiling;
}

/**
 * A rule id: `<source>:<name>`, where source names where it was re-authored
 * from (`cisco-mcp`, `atr`) and name is lower, dotted or hyphenated. It is
 * provenance and a stable key, never the text of the rule.
 */
export const RULE_ID = /^(cisco-mcp|cisco-skill|cisco-a2a|atr):[a-z0-9][a-z0-9._-]{0,80}$/;

/**
 * Where a finding sits: `<subject-kind>:<subject ref>#<field>`. For an MCP
 * tool the subject ref is the tool's discovered id and the field is
 * `description` or `inputSchema`. Never the text itself.
 */
export const AGENT_RULE_LOCATOR = /^(mcp-tool):\S{1,480}#[a-zA-Z][a-zA-Z0-9]{0,40}$/;

export const MAX_AGENT_RULE_FINDINGS = 5000;
export const MAX_SUBJECTS_READ = 100000;
