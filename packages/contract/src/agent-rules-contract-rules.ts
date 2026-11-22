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
 * What a rule reads. A closed list on the wire:
 *
 *   mcp-tool    an MCP tool's definition: its `description` and `inputSchema`
 *   skill       an agent skill's `SKILL.md`: its front matter's `description`
 *               and the body after it, `instructions`
 *   skill-file  a script bundled in a skill's directory: its `content`
 *
 * A2A cards are a later kind.
 */
export const AGENT_RULES_SUBJECT_KINDS = ['mcp-tool', 'skill', 'skill-file'] as const;
export type AgentRulesSubjectKind = (typeof AGENT_RULES_SUBJECT_KINDS)[number];

/** The subject kind in words, for the outputs. */
export const SUBJECT_KIND_TITLE: Readonly<Record<AgentRulesSubjectKind, string>> = Object.freeze({
    'mcp-tool': 'MCP tool definition',
    skill: 'Agent skill (SKILL.md)',
    'skill-file': 'Script bundled with a skill',
});

/**
 * The finding codes, by what they are about. An MCP tool's text:
 *
 *   MCP_TOOL_POISONING        a hidden second behaviour, different from the
 *                             tool's stated purpose
 *   MCP_PROMPT_INJECTION      an instruction to the model written into the text
 *   MCP_COMMAND_INJECTION     an executable payload — a shell command, a
 *                             reverse shell, a download-and-run — in the text
 *   MCP_DATA_EXFILTRATION     an instruction to send data to an external place
 *   MCP_CREDENTIAL_HARVESTING a reference to reading or taking credentials
 *
 * An agent skill's SKILL.md, and the scripts bundled with it:
 *
 *   SKILL_PROMPT_INJECTION      an instruction to the model to set its rules
 *                               aside, a role token, invisible characters, a
 *                               payload hidden in a comment, or concealment
 *                               from the user
 *   SKILL_COMMAND_INJECTION     an executable payload: a reverse shell, an
 *                               encoded command run, a destructive command, a
 *                               download from a paste service run
 *   SKILL_DATA_EXFILTRATION     data sent to a known collection service, a
 *                               secret file posted, a conversation forwarded
 *   SKILL_CREDENTIAL_HARVESTING a private key, a cloud credential file, a
 *                               keychain or the environment read wholesale
 *   SKILL_EXCESSIVE_PERMISSION  unrestricted shell in `allowed-tools`, approval
 *                               turned off, an agent's own configuration or
 *                               memory rewritten, a sensitive path made
 *                               writable
 *   SKILL_IMPERSONATION         a claim to be vouched for by a model vendor,
 *                               or a name that squats on a wallet
 */
export const AGENT_RULES_FINDING_CODES = [
    'MCP_TOOL_POISONING',
    'MCP_PROMPT_INJECTION',
    'MCP_COMMAND_INJECTION',
    'MCP_DATA_EXFILTRATION',
    'MCP_CREDENTIAL_HARVESTING',
    'SKILL_PROMPT_INJECTION',
    'SKILL_COMMAND_INJECTION',
    'SKILL_DATA_EXFILTRATION',
    'SKILL_CREDENTIAL_HARVESTING',
    'SKILL_EXCESSIVE_PERMISSION',
    'SKILL_IMPERSONATION',
] as const;
export type AgentRuleFindingCode = (typeof AGENT_RULES_FINDING_CODES)[number];

/** Which subject kinds a code may be raised on: an MCP code on a tool, a skill code on a skill or its script. */
export const CODE_SUBJECT_KINDS: Readonly<Record<AgentRuleFindingCode, readonly AgentRulesSubjectKind[]>> = Object.freeze({
    MCP_TOOL_POISONING: ['mcp-tool'],
    MCP_PROMPT_INJECTION: ['mcp-tool'],
    MCP_COMMAND_INJECTION: ['mcp-tool'],
    MCP_DATA_EXFILTRATION: ['mcp-tool'],
    MCP_CREDENTIAL_HARVESTING: ['mcp-tool'],
    SKILL_PROMPT_INJECTION: ['skill'],
    SKILL_COMMAND_INJECTION: ['skill', 'skill-file'],
    SKILL_DATA_EXFILTRATION: ['skill', 'skill-file'],
    SKILL_CREDENTIAL_HARVESTING: ['skill', 'skill-file'],
    SKILL_EXCESSIVE_PERMISSION: ['skill', 'skill-file'],
    SKILL_IMPERSONATION: ['skill'],
});

/** Severities, lowest first. There is no CRITICAL: no rule finding is ever one. */
export const AGENT_RULE_SEVERITIES = ['INFO', 'LOW', 'MEDIUM', 'HIGH'] as const;
export type AgentRuleSeverity = (typeof AGENT_RULE_SEVERITIES)[number];

const rank = (s: AgentRuleSeverity): number => AGENT_RULE_SEVERITIES.indexOf(s);

/**
 * The highest severity a code may carry. The
 * codes whose match is an unambiguous attack — an executable payload, a direct
 * instruction to the model — may reach HIGH, for a tool and for a skill alike;
 * the suggestive ones (text that reads as poisoning, exfiltration, credential
 * access, excess permission or impersonation) are at most MEDIUM. A person confirms every finding either way, and none is
 * CRITICAL. A rule declares its own ceiling, which the code's ceiling bounds.
 */
export const SEVERITY_CEILING: Readonly<Record<AgentRuleFindingCode, AgentRuleSeverity>> = Object.freeze({
    MCP_COMMAND_INJECTION: 'HIGH',
    MCP_PROMPT_INJECTION: 'HIGH',
    MCP_TOOL_POISONING: 'MEDIUM',
    MCP_DATA_EXFILTRATION: 'MEDIUM',
    MCP_CREDENTIAL_HARVESTING: 'MEDIUM',
    SKILL_PROMPT_INJECTION: 'HIGH',
    SKILL_COMMAND_INJECTION: 'HIGH',
    SKILL_DATA_EXFILTRATION: 'MEDIUM',
    SKILL_CREDENTIAL_HARVESTING: 'MEDIUM',
    SKILL_EXCESSIVE_PERMISSION: 'MEDIUM',
    SKILL_IMPERSONATION: 'MEDIUM',
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
 * `description` or `inputSchema`; for a skill, its directory under its code
 * root and `description` or `instructions`; for a bundled script, its path
 * under its code root and `content`. Never the text itself.
 */
export const AGENT_RULE_LOCATOR = /^(mcp-tool|skill|skill-file):\S{1,480}#[a-zA-Z][a-zA-Z0-9]{0,40}$/;

export const MAX_AGENT_RULE_FINDINGS = 5000;
export const MAX_SUBJECTS_READ = 100000;
/** The most origins — MCP servers and code roots — one report names. */
export const MAX_ORIGINS_READ = 1000;

/**
 * Where a subject was read from, as a report names it: the unit a finding is
 * closed against.
 *
 *   • an MCP server: `mcp:<configured URL>`, or `mcp:sha256-<32 hex>` when the
 *     URL is long, holds white space or has the shape of a secret;
 *   • a code root: `code:<root label>`, or `code:sha256-<32 hex>` on the same
 *     terms. The label is the operator's name for the root, never its path.
 *
 * The same in every report a scanner signs, so a consumer can tell that two
 * scans read the same origin.
 */
export const AGENT_RULE_ORIGIN_REF = /^(mcp|code):\S{1,400}$/;

/** Which subject kinds each origin family holds: an MCP server's tools, a code root's skills and their files. */
export const ORIGIN_FAMILY_OF_KIND: Readonly<Record<AgentRulesSubjectKind, 'mcp' | 'code'>> = Object.freeze({
    'mcp-tool': 'mcp',
    skill: 'code',
    'skill-file': 'code',
});

/** The family of an origin ref: its prefix. */
export function originFamily(ref: string): 'mcp' | 'code' {
    return ref.startsWith('code:') ? 'code' : 'mcp';
}
