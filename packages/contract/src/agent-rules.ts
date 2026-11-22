/**
 * THE AGENT-SURFACE RULE SET — static patterns over an agent's own text.
 *
 * Pure and browser-safe: a string in, the rules that fired out. Each rule is a
 * regular expression re-authored from a public source, never the source's
 * verbatim text: Cisco AI Defense's MCP scanner (`cisco-mcp:*`) and skill
 * scanner (`cisco-skill:*`), both Apache-2.0, and the Agent Threat Rules
 * (`atr:*`, MIT). The `source` field names the rule it came from, so a
 * reviewer can compare; NOTICE carries the licences.
 *
 * `runAgentRules` is the ONE place the rules run: the scanner calls it over an
 * MCP tool's definition and over a skill's SKILL.md and bundled scripts, where
 * that text is held and never leaves, and the evaluation scorer calls it over
 * the corpus. One definition, two callers. Each rule names the subject kinds
 * it reads; a rule never runs over a kind it does not name.
 *
 * A rule declares the code it raises and its severity, bounded by the code's
 * ceiling (`capRuleSeverity`): an executable payload or a direct instruction
 * to the model may be HIGH; a description that merely reads as poisoning,
 * exfiltration or credential access is at most MEDIUM. A person confirms every
 * finding, and none is CRITICAL.
 */
import {
    capRuleSeverity,
    CODE_SUBJECT_KINDS,
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
    /** The subject kinds it reads: within its code's (`CODE_SUBJECT_KINDS`). */
    readonly reads: readonly AgentRulesSubjectKind[];
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
 * The MCP tool rules. Each `re` needs a suspicious verb paired with a
 * suspicious object, as its source does, so an ordinary description that
 * mentions a file or a URL does not fire. The patterns carry no flags that
 * keep state (`g`/`y`), so `re.test` is pure.
 */
const MCP_RULES: readonly Omit<AgentRule, 'reads'>[] = [
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
];

/** The kinds a skill's text rule reads: SKILL.md only. */
const SKILL_MD: readonly AgentRulesSubjectKind[] = ['skill'];
/** The kinds a payload rule reads: SKILL.md and the scripts bundled with it. */
const SKILL_ANY: readonly AgentRulesSubjectKind[] = ['skill', 'skill-file'];

/**
 * The skill rules. A skill is instructions the model follows and scripts it
 * runs, so a rule reads SKILL.md (`SKILL_MD`) when it is about what the model
 * is told, and SKILL.md and the scripts (`SKILL_ANY`) when it is about a
 * payload, which may sit in either. Each pairs an action with an object, as
 * its source does, so a skill that writes about these attacks in general
 * words does not fire; one that quotes an attack verbatim does, and a person
 * judges it.
 */
const SKILL_RULES: readonly AgentRule[] = [
    // ——— Prompt injection: SKILL.md tells the model to set its rules aside ———
    {
        id: 'cisco-skill:ignore-instructions',
        source: 'cisco-ai-defense/skill-scanner PROMPT_INJECTION_IGNORE_INSTRUCTIONS; atr ATR-2026-00120 instruction override',
        code: 'SKILL_PROMPT_INJECTION',
        reads: SKILL_MD,
        declares: 'HIGH',
        re: /\b((ignore|disregard|forget|override)\s+(all\s+|any\s+)?((your|the)\s+)?(previous|prior|earlier|above|preceding|original)\s+(instructions?|rules|prompts?|guidelines|context)|you\s+(must|should|will|shall)\s+(now\s+)?(ignore|disregard|override)\s+(all\s+|any\s+)?((your|the)\s+)?(instructions?|rules|guidelines|safety\s+\w+|system\s+prompt))\b/i,
    },
    {
        id: 'cisco-skill:unrestricted-mode',
        source: 'cisco-ai-defense/skill-scanner PROMPT_INJECTION_UNRESTRICTED_MODE / PROMPT_INJECTION_BYPASS_POLICY; atr ATR-2026-00120 mode claim',
        code: 'SKILL_PROMPT_INJECTION',
        reads: SKILL_MD,
        declares: 'HIGH',
        re: /\b(you\s+are\s+(now\s+)?in\s+(unrestricted|debug|developer|admin|god|jailbreak|root)\s+mode|disable\s+(all\s+)?(your\s+)?(safety|security|content|ethical)\s+(filters?|checks?|guidelines|guardrails)|bypass\s+(the\s+)?(content|usage|safety)\s+polic(y|ies)|security\s+warnings?\s+are\s+test\s+artifacts?)\b/i,
    },
    {
        id: 'atr:2026-00120.role-token',
        source: 'Agent-Threat-Rule/agent-threat-rules ATR-2026-00120 (chat-template role tokens)',
        code: 'SKILL_PROMPT_INJECTION',
        reads: SKILL_MD,
        declares: 'HIGH',
        re: /(\[SYSTEM\]\s*:|<\|system\|>|<\|im_start\|>\s*system|<<SYS>>|\[INST\]\s*:)/,
    },
    {
        id: 'atr:2026-00120.hidden-comment',
        source: 'Agent-Threat-Rule/agent-threat-rules ATR-2026-00120 / ATR-2026-00128 (payload inside an HTML comment)',
        code: 'SKILL_PROMPT_INJECTION',
        reads: SKILL_MD,
        declares: 'HIGH',
        re: /<!--(?:(?!-->)[^]){0,400}?\b(ignore\s+(all\s+)?(previous|prior)|system\s+(instruction|override|prompt)|agent\s+(should|must)|send\s+(all|the|every)|curl\s|wget\s|eval\s*\()/i,
    },
    {
        id: 'atr:2026-00129.invisible-characters',
        source: 'Agent-Threat-Rule/agent-threat-rules ATR-2026-00120 zero-width cluster / ATR-2026-00129 Unicode tag smuggling',
        code: 'SKILL_PROMPT_INJECTION',
        reads: SKILL_MD,
        declares: 'HIGH',
        // Three or more zero-width characters together, or a run of Unicode tag
        // characters — matched from its first character, so the run that spells
        // a subdivision flag after U+1F3F4 (England, Scotland, Wales) is not one.
        re: /((?:\u200B|\u200C|\u200D|\u2060|\uFEFF){3,}|(?<![\u{1F3F4}\u{E0020}-\u{E007E}])[\u{E0020}-\u{E007E}]{3,})/u,
    },
    {
        id: 'cisco-skill:conceal-from-user',
        source: 'cisco-ai-defense/skill-scanner PROMPT_INJECTION_CONCEALMENT',
        code: 'SKILL_PROMPT_INJECTION',
        reads: SKILL_MD,
        declares: 'MEDIUM',
        re: /\b((do\s+not|don['’]t|never)\s+(tell|inform|notify|alert|warn)\s+(the\s+)?user|hide\s+(this|that|these)\s+(action|operation|step|command)s?\s+from|(do\s+not|don['’]t)\s+mention\s+(that\s+)?you\s+used\s+this\s+skill)\b/i,
    },
    {
        id: 'cisco-skill:hidden-trigger',
        source: 'cisco-ai-defense/skill-scanner capability_inflation_generic $hidden_triggers',
        code: 'SKILL_PROMPT_INJECTION',
        reads: SKILL_MD,
        declares: 'MEDIUM',
        re: /\b(secret\s+(command|keyword|trigger|passphrase)|hidden\s+(feature|mode|command|trigger)|backdoor\s+(access|entry|mode|command))\b/i,
    },

    // ——— Command injection: an executable payload in SKILL.md or a script ———
    {
        id: 'atr:2026-00121.reverse-shell',
        source: 'Agent-Threat-Rule/agent-threat-rules ATR-2026-00121 reverse shell; cisco-ai-defense/skill-scanner command_injection_generic $reverse_shell_*',
        code: 'SKILL_COMMAND_INJECTION',
        reads: SKILL_ANY,
        declares: 'HIGH',
        re: /(\b(bash|sh|zsh)\s+-i\s+>&\s*\/dev\/(tcp|udp)\/|\/dev\/tcp\/[\w.-]+\/\d{1,5}|\b(nc|ncat|netcat)\s+(-\w+\s+)*(-e|--exec|-c)\s+\S*\b(sh|bash|zsh|cmd(\.exe)?|powershell)\b|\bsocat\b[^\n]{0,80}\bexec:)/i,
    },
    {
        id: 'atr:2026-00121.encoded-exec',
        source: 'Agent-Threat-Rule/agent-threat-rules ATR-2026-00121 / ATR-2026-00223 (decode then run)',
        code: 'SKILL_COMMAND_INJECTION',
        reads: SKILL_ANY,
        declares: 'HIGH',
        re: /(\bbase64\s+(-d|-D|--decode)\b[^\n|]{0,80}\|\s*(sudo\s+)?(ba|z)?sh\b|\beval\s+["']?\$\(\s*echo\s+[^\n)]{0,400}\|\s*base64\s+(-d|-D|--decode)|\beval\s*\(\s*(atob|Buffer\.from|base64\.b64decode)\s*\(|\bexec\s*\(\s*(base64\.b64decode|codecs\.decode|zlib\.decompress)\s*\()/i,
    },
    {
        id: 'atr:2026-00121.download-from-paste',
        source: 'Agent-Threat-Rule/agent-threat-rules ATR-2026-00121 (download from a raw address or paste service, run)',
        code: 'SKILL_COMMAND_INJECTION',
        reads: SKILL_ANY,
        declares: 'HIGH',
        re: /\b(curl|wget|iwr|invoke-webrequest)\b[^\n|]{0,200}\b(https?:\/\/(\d{1,3}\.){3}\d{1,3}\b|pastebin\.com|glot\.io|rentry\.co|paste\.ee|hastebin\.com|transfer\.sh)[^\n|]{0,200}\|\s*(sudo\s+)?(bash|sh|zsh|python[23]?|perl|ruby|node|iex|powershell|pwsh)\b/i,
    },
    {
        id: 'atr:2026-00121.download-and-run',
        source: 'Agent-Threat-Rule/agent-threat-rules ATR-2026-00121 (curl|wget … | sh)',
        code: 'SKILL_COMMAND_INJECTION',
        reads: SKILL_ANY,
        declares: 'MEDIUM',
        re: /\b(curl|wget)\b[^\n|]{0,200}\|\s*(sudo\s+)?(bash|sh|zsh|python[23]?|perl|ruby|node)\b/i,
    },
    {
        id: 'cisco-skill:destructive-command',
        source: 'cisco-ai-defense/skill-scanner command_injection_generic $dangerous_rm',
        code: 'SKILL_COMMAND_INJECTION',
        reads: SKILL_ANY,
        declares: 'HIGH',
        re: /(\brm\s+-[rRf]{2,3}\s+(--no-preserve-root\s+)?(\/|~\/?|\$HOME\/?|\/(etc|root|home|usr|var|boot)\/?)\*?(?=\s|$|;|&|\||["'])|\bmkfs(\.\w+)?\s+\/dev\/|\bdd\s+if=\S+\s+of=\/dev\/(sd|nvme|hd|disk))/,
    },
    {
        id: 'cisco-skill:windows-exec',
        source: 'cisco-ai-defense/skill-scanner command_injection_generic (Windows)',
        code: 'SKILL_COMMAND_INJECTION',
        reads: SKILL_ANY,
        declares: 'HIGH',
        re: /\b(powershell(\.exe)?\s+(-\w+\s+)*-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}|iex\s*\(\s*(new-object\s+net\.webclient|\(new-object)|downloadstring\s*\(\s*['"]https?:)/i,
    },

    // ——— Data exfiltration ———
    {
        id: 'cisco-skill:known-exfil-destination',
        source: 'cisco-ai-defense/skill-scanner command_injection_generic $data_exfiltration_known_dest',
        code: 'SKILL_DATA_EXFILTRATION',
        reads: SKILL_ANY,
        declares: 'MEDIUM',
        re: /\b(curl|wget|iwr|invoke-webrequest|invoke-restmethod|requests\.(post|put|get)|urlopen|fetch|axios(\.(post|put))?)\b[^\n]{0,200}\b(webhook\.site|ngrok(-free)?\.(io|app|dev)|pastebin\.com|requestbin\.(com|net)|pipedream\.net|hookbin\.com|burpcollaborator\.net|interact\.sh|oast\.(fun|pro|live|site|online|me))\b/i,
    },
    {
        id: 'cisco-skill:post-secret-file',
        source: 'cisco-ai-defense/skill-scanner command_injection_generic $curl_post_sensitive_files',
        code: 'SKILL_DATA_EXFILTRATION',
        reads: SKILL_ANY,
        declares: 'MEDIUM',
        re: /\bcurl\b[^\n]{0,200}\s(-d|--data(-binary|-raw)?|-F|--form|-T|--upload-file)\s*['"]?[\w-]*=?@?['"]?(~\/|\$HOME\/|[/](root|home[/][\w.-]+)\/)?(\.ssh\/|\.aws\/|\.env\b|\.netrc|\.git-credentials|\/etc\/(passwd|shadow))/i,
    },
    {
        id: 'atr:2026-00222.secret-piped-out',
        source: 'Agent-Threat-Rule/agent-threat-rules ATR-2026-00121 / ATR-2026-00222 (credential file read, piped to the network)',
        code: 'SKILL_DATA_EXFILTRATION',
        reads: SKILL_ANY,
        declares: 'MEDIUM',
        re: /\b(cat|type|base64|tar\s+\S*c\S*)\s+[^\n|]{0,80}(\.ssh\/|\.aws\/credentials|\.env\b|\.netrc|\.git-credentials|\/etc\/shadow)[^\n|]{0,60}\|\s*(curl|wget|nc|ncat|netcat)\b/i,
    },
    {
        id: 'cisco-skill:conversation-exfil',
        source: 'cisco-ai-defense/skill-scanner data_exfiltration (conversation forwarded)',
        code: 'SKILL_DATA_EXFILTRATION',
        reads: SKILL_MD,
        declares: 'MEDIUM',
        re: /\b(send|upload|transmit|post|forward|export)(s|ing|ed)?\s+(the\s+|all\s+(of\s+)?(the\s+)?)?(complete\s+|full\s+|entire\s+)?(conversation|chat\s+history|user['’]?s?\s+messages?|session\s+(history|transcript)|full\s+context)\s+(to|into)\b/i,
    },

    // ——— Credential harvesting ———
    {
        id: 'cisco-skill:credential-files',
        source: 'cisco-ai-defense/skill-scanner credential access; atr ATR-2026-00214 / ATR-2026-00217',
        code: 'SKILL_CREDENTIAL_HARVESTING',
        reads: SKILL_ANY,
        declares: 'MEDIUM',
        re: /((~|\$HOME|%USERPROFILE%|[/](home[/][\w.-]+|root))[\\/](\.ssh[\\/]id_(rsa|ed25519|ecdsa|dsa)\b|\.aws[\\/]credentials\b|\.git-credentials\b|\.netrc\b)|\bLogin\s+Data\b|\bsecurity\s+(find|dump)-(generic|internet)-password\b|\bsecurity\s+dump-keychain\b)/i,
    },
    {
        id: 'cisco-skill:environment-dump',
        source: 'cisco-ai-defense/skill-scanner credential access (environment read wholesale)',
        code: 'SKILL_CREDENTIAL_HARVESTING',
        reads: SKILL_ANY,
        declares: 'MEDIUM',
        re: /(\bJSON\.stringify\(\s*process\.env\s*\)|\bdict\(\s*os\.environ\s*\)|\bjson\.dumps\(\s*(dict\()?\s*os\.environ|(?<![\w./-])(printenv|env)\s*(\||>\s*\S))/,
    },

    // ——— Excessive permission ———
    {
        id: 'atr:2026-00123.unrestricted-shell',
        source: 'Agent-Threat-Rule/agent-threat-rules ATR-2026-00123 (allowed-tools grants Bash(*))',
        code: 'SKILL_EXCESSIVE_PERMISSION',
        reads: SKILL_MD,
        declares: 'MEDIUM',
        re: /\ballowed[_-]tools\s*:[^\n]*\bBash\s*\(\s*\*\s*\)/i,
    },
    {
        id: 'atr:2026-00123.approval-off',
        source: 'Agent-Threat-Rule/agent-threat-rules ATR-2026-00123 (autoApprove, permission bypass)',
        code: 'SKILL_EXCESSIVE_PERMISSION',
        reads: SKILL_ANY,
        declares: 'MEDIUM',
        re: /(["']?autoApprove["']?\s*[:=]\s*(true|\[)|--dangerously-skip-permissions\b|["']?permission[_-]?mode["']?\s*[:=]\s*["']?bypassPermissions\b)/i,
    },
    {
        id: 'atr:2026-00200.agent-config-write',
        source: 'Agent-Threat-Rule/agent-threat-rules ATR-2026-00200 / ATR-2026-00123 (an agent\'s memory or settings rewritten)',
        code: 'SKILL_EXCESSIVE_PERMISSION',
        reads: SKILL_ANY,
        declares: 'MEDIUM',
        re: /\b(write|append|overwrite|modify|edit|add|insert|echo|tee|cat\s*>{1,2})\b[^\n]{0,80}(CLAUDE\.md|MEMORY\.md|SOUL\.md|AGENTS\.md|\.claude[\\/]settings(\.local)?\.json|\.cursorrules|\.mcp\.json)\b/i,
    },
    {
        id: 'cisco-skill:sensitive-permission-change',
        source: 'cisco-ai-defense/skill-scanner command_injection_generic $dangerous_chmod; atr ATR-2026-00064',
        code: 'SKILL_EXCESSIVE_PERMISSION',
        reads: SKILL_ANY,
        declares: 'MEDIUM',
        re: /(\bchmod\s+(-R\s+)?(777|666|[ugoa]*\+s)\s+[^\n]{0,40}(\.ssh|\.aws|\.env\b|\/etc\b|\/usr\/(local\/)?bin)|\b(chown|chmod)\s+[^\n]{0,30}\/etc\/(shadow|sudoers|passwd)\b|\becho\s+[^\n]{0,80}>>\s*\/etc\/sudoers\b)/i,
    },

    // ——— Impersonation ———
    {
        id: 'cisco-skill:vendor-endorsement',
        source: 'cisco-ai-defense/skill-scanner capability_inflation_generic $trusted_impersonation',
        code: 'SKILL_IMPERSONATION',
        reads: SKILL_MD,
        declares: 'MEDIUM',
        re: /\b(verified|certified|approved|endorsed|authori[sz]ed)\s+by\s+(anthropic|openai|google|microsoft|claude|github)\b/i,
    },
    {
        id: 'atr:2026-00124.wallet-name-squat',
        source: 'Agent-Threat-Rule/agent-threat-rules ATR-2026-00124 (name squatting on a wallet)',
        code: 'SKILL_IMPERSONATION',
        reads: SKILL_MD,
        declares: 'MEDIUM',
        re: /\bname\s*:\s*["']?(solana|bitcoin|ethereum|crypto|wallet|bybit|binance|metamask|phantom)[_-](drain|steal|recover|generat|sweep)[a-z]*/i,
    },
];

/** Every rule: the MCP tool rules, then the skill rules. */
export const AGENT_RULES: readonly AgentRule[] = Object.freeze([
    ...MCP_RULES.map((r): AgentRule => ({ ...r, reads: ['mcp-tool'] })),
    ...SKILL_RULES,
]);

/**
 * Run the rules over one subject's text: every rule that reads its kind. Each
 * match's severity is already held to its code's ceiling, so a caller cannot
 * report above what the code allows.
 */
export function runAgentRules(text: string, kind: AgentRulesSubjectKind): readonly AgentRuleMatch[] {
    const out: AgentRuleMatch[] = [];
    for (const rule of AGENT_RULES) {
        if (!rule.reads.includes(kind)) continue;
        if (rule.re.test(text)) {
            out.push({ ruleId: rule.id, code: rule.code, severity: capRuleSeverity(rule.code, rule.declares) });
        }
    }
    return out;
}

/** Whether every rule reads only kinds its code may be raised on: the rule set's own consistency, asserted by a test. */
export function ruleKindsWithinCodes(rules: readonly AgentRule[] = AGENT_RULES): boolean {
    return rules.every((r) => r.reads.length > 0 && r.reads.every((k) => CODE_SUBJECT_KINDS[r.code].includes(k)));
}
