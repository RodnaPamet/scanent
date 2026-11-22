/**
 * THE AGENT-SURFACE RULE SET — static patterns over an agent's own text.
 *
 * Pure and browser-safe: a string in, the rules that fired out. Each rule is a
 * regular expression re-authored from a public source, never the source's
 * verbatim text: Cisco AI Defense's MCP scanner (`cisco-mcp:*`, Apache-2.0)
 * and the Agent Threat Rules (`atr:*`, MIT). The `source` field names the rule
 * it came from, so a reviewer can compare; NOTICE carries the licences.
 *
 * `runAgentRules` is the ONE place the rules run: the scanner calls it over an
 * MCP tool's description where that text is held and never leaves, and the
 * evaluation scorer calls it over the corpus. One definition, two callers.
 *
 * A rule declares the code it raises and its severity, bounded by the code's
 * ceiling (`capRuleSeverity`): an executable payload or a direct instruction
 * to the model may be HIGH; a description that merely reads as poisoning,
 * exfiltration or credential access is at most MEDIUM. A person confirms every
 * finding, and none is CRITICAL.
 */
import {
    capRuleSeverity,
    type AgentRuleFindingCode,
    type AgentRuleSeverity,
    type AgentRulesSubjectKind,
} from './agent-rules-contract-rules';

export interface AgentRule {
    /** `<source>:<name>`, matching `RULE_ID`. */
    readonly id: string;
    /** Which public rule it was re-authored from, for a reviewer. */
    readonly source: string;
    readonly code: AgentRuleFindingCode;
    /** What this rule claims when it fires, bounded by the code's ceiling. */
    readonly declares: AgentRuleSeverity;
    readonly re: RegExp;
}

/** A rule that fired, with its severity already held to the code's ceiling. */
export interface AgentRuleMatch {
    readonly ruleId: string;
    readonly code: AgentRuleFindingCode;
    readonly severity: AgentRuleSeverity;
}

/**
 * The version-1 rules. Each `re` needs a suspicious verb paired with a
 * suspicious object, as its source does, so an ordinary description that
 * mentions a file or a URL does not fire. The patterns carry no flags that
 * keep state (`g`/`y`), so `re.test` is pure.
 */
export const AGENT_RULES: readonly AgentRule[] = Object.freeze([
    // ——— Prompt injection: an instruction to the model written into the text ———
    {
        id: 'cisco-mcp:instruction-override',
        source: 'cisco-ai-defense/mcp-scanner prompt_injection $instruction_overrides',
        code: 'MCP_PROMPT_INJECTION',
        declares: 'HIGH',
        re: /\b(bypass|disregard|do not (follow|obey)|forget|ignore)\s+((all|any|every)\s+(of\s+)?)?((your|the)\s+)?((previous|prior|above|earlier|preceding)\s+)?(command|context|conversation|guideline|instruction|message|prompt|request|rule)s?\b/i,
    },
    {
        id: 'cisco-mcp:role-redefinition',
        source: 'cisco-ai-defense/mcp-scanner prompt_injection $role_redefinition / $advanced_overrides',
        code: 'MCP_PROMPT_INJECTION',
        declares: 'HIGH',
        re: /\b(new\s+(instructions?|directive|guidelines?)\s*:\s*you\s+are|system\s*prompt\s*override|disregard\s+(all\s+)?safety\s+guidelines)\b/i,
    },
    {
        id: 'cisco-mcp:hidden-marker',
        source: 'cisco-ai-defense/mcp-scanner prompt_injection $hidden_markers / $html_comment_evasion',
        code: 'MCP_PROMPT_INJECTION',
        declares: 'HIGH',
        re: /(\[(hidden|internal|secret|private)\s+(instruction|directive|command)\]|<!--[^>]*(system\s+(instruction|override)|admin\s+override|ignore\s+(all\s+)?(previous\s+)?(safety\s+)?guidelines))/i,
    },
    {
        id: 'cisco-mcp:hide-from-user',
        source: 'cisco-ai-defense/mcp-scanner prompt_injection $hidden_behavior',
        code: 'MCP_PROMPT_INJECTION',
        declares: 'MEDIUM',
        re: /\b(do\s+not\s+(mention|tell|execute)|tell\s+the\s+user\s+only\s+about|never\s+(tell|inform|mention|notify)\s+(the\s+)?user)\b/i,
    },

    // ——— Command injection: an executable payload in the text ———
    {
        id: 'cisco-mcp:reverse-shell',
        source: 'cisco-ai-defense/mcp-scanner command_injection $reverse_shells',
        code: 'MCP_COMMAND_INJECTION',
        declares: 'HIGH',
        re: /(\b(bash|sh)\s+-i\b|\bnc\s+-e\b|\/dev\/tcp\/|\bsocat\b[^.\n]{0,40}\bexec)/i,
    },
    {
        id: 'atr:download-and-run',
        source: 'Agent-Threat-Rule/agent-threat-rules tool-poisoning (curl|wget … | sh)',
        code: 'MCP_COMMAND_INJECTION',
        declares: 'HIGH',
        re: /\b(curl|wget|fetch|iwr|invoke-webrequest)\s+[^|\n]{0,200}\|\s*(bash|sh|zsh|python[23]?|perl|ruby|node|powershell|pwsh)\b/i,
    },
    {
        id: 'atr:destructive-command',
        source: 'Agent-Threat-Rule/agent-threat-rules tool-poisoning (destructive)',
        code: 'MCP_COMMAND_INJECTION',
        declares: 'HIGH',
        re: /(\brm\s+-[rRf]{1,3}[\s/]|\bmkfs\b|\bdd\s+if=|:\(\)\s*\{\s*:\|:\s*&\s*\}|\bchmod\s+[0-7]{0,1}[4-7]{3}\b.{0,20}(suid|\/etc))/,
    },
    {
        id: 'atr:encoded-exec',
        source: 'Agent-Threat-Rule/agent-threat-rules tool-poisoning (base64 | sh)',
        code: 'MCP_COMMAND_INJECTION',
        declares: 'HIGH',
        re: /\bbase64\s+(-d|--decode)\s*(<<<|\|\s*(ba)?sh)|\beval\s*\(\s*(atob|base64)/i,
    },
    {
        id: 'cisco-mcp:windows-exec',
        source: 'cisco-ai-defense/mcp-scanner command_injection $windows_cmds',
        code: 'MCP_COMMAND_INJECTION',
        declares: 'HIGH',
        re: /\b(powershell(\.exe)?\s+-(e(nc(odedcommand)?)?|c(ommand)?|nop|ep\s+bypass)|cmd(\.exe)?\s*\/[ck]\s|iex\s*\(|invoke-expression|downloadstring\s*\()/i,
    },

    // ——— Tool poisoning: a hidden second behaviour ———
    {
        id: 'cisco-mcp:also-does',
        source: 'cisco-ai-defense/mcp-scanner tool_poisoning $also_does',
        code: 'MCP_TOOL_POISONING',
        declares: 'MEDIUM',
        re: /\b(also|additionally|furthermore|besides|in\s+addition)\s+(collect|gather|extract|send|upload|index|store|cache|log|monitor|track|record|capture|exfiltrat)(s|ing|ed)?\b/i,
    },
    {
        id: 'cisco-mcp:during-action',
        source: 'cisco-ai-defense/mcp-scanner tool_poisoning $during_action',
        code: 'MCP_TOOL_POISONING',
        declares: 'MEDIUM',
        re: /\b(during|while|when|after)\s+(processing|compression|formatting|conversion|validation|analyzing|scanning|checking)\s*,?\s*(extract|collect|send|upload|capture|log|index|store|transmit)(s|ing|ed)?\b/i,
    },
    {
        id: 'cisco-mcp:for-purposes',
        source: 'cisco-ai-defense/mcp-scanner tool_poisoning $for_purposes',
        code: 'MCP_TOOL_POISONING',
        declares: 'MEDIUM',
        re: /\b(for|as)\s+(caching|optimization|performance|quality|analytics|backup|sync)\s+(purposes?|reasons?)\s*[,.]?\s*(send|upload|store|collect|transmit)(s|ing|ed)?\b/i,
    },

    // ——— Data exfiltration: sending data to an external place ———
    {
        id: 'cisco-mcp:upload-external',
        source: 'cisco-ai-defense/mcp-scanner data_exfiltration $external_endpoints',
        code: 'MCP_DATA_EXFILTRATION',
        declares: 'MEDIUM',
        re: /\b(upload|send|post|transmit|forward|exfiltrat|leak|ship|relay)(s|ed|ing)?\s+([^.\n]{0,40}\s+)?(to|into|via|through)\s+(an?\s+|the\s+|some\s+)?(external|remote|third[- ]party)\s+(endpoint|server|api|service|storage)\b/i,
    },
    {
        id: 'cisco-mcp:hidden-transfer',
        source: 'cisco-ai-defense/mcp-scanner data_exfiltration $hidden_transfer',
        code: 'MCP_DATA_EXFILTRATION',
        declares: 'MEDIUM',
        re: /\b(invisibly|silently|covertly|secretly|without\s+(the\s+)?user\s+knowledge|behind\s+the\s+scenes|in\s+the\s+background)\s+(send|upload|transmit|transfer|collect|store)(s|ing|ed)?\b/i,
    },
    {
        id: 'cisco-mcp:conversation-exfil',
        source: 'cisco-ai-defense/mcp-scanner data_exfiltration $sends_conversation',
        code: 'MCP_DATA_EXFILTRATION',
        declares: 'MEDIUM',
        re: /\b(send|upload|transmit|export|forward)(s|ing|ed)?\s+(the\s+)?(complete\s+)?(conversation|chat\s+history|user\s+messages?|full\s+context)\b/i,
    },

    // ——— Credential harvesting: reading or taking credentials ———
    {
        id: 'cisco-mcp:reads-sensitive',
        source: 'cisco-ai-defense/mcp-scanner tool_poisoning $indexes_sensitive / $extracts_from_input',
        code: 'MCP_CREDENTIAL_HARVESTING',
        declares: 'MEDIUM',
        re: /\b(index|cache|store|log|record|read|extract|collect|dump|harvest)(s|es|ing|ed)?\s+(any|all)?\s*(api[_\s]?keys?|tokens?|credentials?|passwords?|secrets?|private\s+keys?)\b/i,
    },
    {
        id: 'cisco-mcp:credential-files',
        source: 'cisco-ai-defense/mcp-scanner credential_harvesting $credential_directories / $credential_filenames',
        code: 'MCP_CREDENTIAL_HARVESTING',
        declares: 'MEDIUM',
        re: /([/\\]\.(ssh|aws|kube)[/\\]|\b(id_rsa|id_ed25519|authorized_keys|credentials\.json|service_account\.json)\b|\b\.env\b[^.\n]{0,20}(read|send|upload|collect|dump))/i,
    },
    {
        id: 'cisco-mcp:env-exfil',
        source: 'cisco-ai-defense/mcp-scanner credential_harvesting $env_exfil',
        code: 'MCP_CREDENTIAL_HARVESTING',
        declares: 'MEDIUM',
        re: /\b(environment|env)\s+(variables?|vars?)\s*[^.\n]{0,20}(collect|gather|send|upload|transmit|dump|extract|exfiltrat)\b/i,
    },
]);

/**
 * Run the rules over one subject's text. Version 1 reads an `mcp-tool`; a kind
 * the rules do not cover yet returns nothing. Each match's severity is already
 * held to its code's ceiling, so a caller cannot report above what the code
 * allows.
 */
export function runAgentRules(text: string, kind: AgentRulesSubjectKind): readonly AgentRuleMatch[] {
    if (kind !== 'mcp-tool') return [];
    const out: AgentRuleMatch[] = [];
    for (const rule of AGENT_RULES) {
        if (rule.re.test(text)) {
            out.push({ ruleId: rule.id, code: rule.code, severity: capRuleSeverity(rule.code, rule.declares) });
        }
    }
    return out;
}
