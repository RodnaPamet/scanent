# Rule-based findings over the agent surface

> **Status: proposed, not built (2026-11-22).** The owner chose on 2026-11-22
> to take Cisco AI Defense's static detection rules (MCP, skills, A2A) before
> the vulnerability scanner's model step. This page is the design; its open
> questions are for the owner, and nothing is built until they are answered.

## What it is

A fourth kind of finding in the AGENT scanner — not a new scanner, not a new
report. The agent scanner already reads an MCP server's tool definitions, a
tenant's agent skills and A2A agent cards. Today it reads them for identity
(what tools an agent has, what a card claims). This adds a pass that reads the
SAME text for signs of attack written into it: a tool whose description hides a
second behaviour (tool poisoning), a skill carrying a prompt injection or an
exfiltration instruction, an agent card that spoofs another agent.

It is static and needs no model. Every check is a rule — a regular expression
or a YARA-style pattern — run over text the scanner already holds. It never
runs the tool, the skill or the agent it reads.

## Where the rules come from

Three public projects, all permissively licensed:

| Project | What is taken |
|---|---|
| [cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) (Apache-2.0) | Its YARA rules for a tool's text: tool poisoning, prompt and coercive injection, data exfiltration, credential harvesting, command and SQL injection written into a description. |
| [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) (Apache-2.0) | Its core YARA and signatures for a skill: prompt injection, context exfiltration, markdown exfiltration, autonomy abuse, capability inflation. It bundles the upstream Agent Threat Rules (MIT), kept as its own attribution. |
| [cisco-ai-defense/a2a-scanner](https://github.com/cisco-ai-defense/a2a-scanner) (Apache-2.0) | Its rules for an agent card: agent-card spoofing, impersonation, capability abuse, message injection, routing manipulation. |

Not taken: their live modes. mcp-scanner connects to a server and can launch a
stdio server's command; a2a-scanner sends requests to a live endpoint. scanent
does neither — it reads the text it already has and nothing else.

## How a finding is made

1. **The rules run in the scanner, over text that never leaves the site.** The
   MCP source reads a tool's description and schemas and, by design, does not
   report them (`sources/mcp.ts`: "the definition's text never leaves this
   site"). The rules run THERE, where the text is. Only the finding leaves.
2. **A finding is a code and a locator, never the text.** `TOOL_POISONING`,
   `SKILL_PROMPT_INJECTION`, `AGENT_CARD_SPOOFING`, … on the agent it is
   about, with the rule id that fired and where (the tool's name, the skill's
   path, the card's field). The report carries no excerpt, as the agent report
   carries none today.
3. **A match is a suggestion a person confirms.** A regular expression over a
   description is evidence, not proof: a legitimate tool can describe reading a
   file. So a rule finding is capped (open question 1) and never changes an
   agent's harness level.
4. **A rule that cannot read its input concludes nothing.** A description the
   source did not read in full raises no "clean" verdict, as everywhere else in
   scanent.

## What leaves the site

Nothing new. The agent report gains finding codes and rule ids. No description,
no skill text, no card text, no excerpt. The declared surface does not change:
no new request is made, because the text is already read.

## How it is evaluated

A fixed corpus ships with the rules, as the vulnerability scanner's does:
poisoned tools, injected skills and spoofed cards that must fire, and clean
ones that must not. Each rule set's record (fired, missed, false on clean)
ships with the release. The rules are vendored or re-authored at a pinned
commit (open question 2), through scanent's text scan, attributed in NOTICE.

## In the contract

The agent report (`inflect-agent-harness/4`) already carries `findings[]`. A
new finding code is a planner change, not a schema change, if the codes fit the
existing finding shape (open question 3). Inflect's ingest already reads the
agent report's findings.

## Order of work

1. The rule format and the planner, with the MCP tool-poisoning and
   injection rules first, and the evaluation corpus. No new input kind.
2. The skill rules (scanent already scans skill text; these are new codes).
3. The A2A card rules.
4. A release.

## Open questions for the owner

1. **The severity cap.** A rule match over a description is weaker evidence
   than the vulnerability scanner's refuted trace. Should a rule finding be
   capped at MEDIUM (a person confirms, never HIGH on a pattern alone), or may
   the strongest rules (an executable payload in a tool's output, a literal
   "ignore previous instructions") reach HIGH?
2. **Vendor the rules, or re-author them.** Vendor Cisco's YARA and the MIT
   ATR signatures as data, pinned and attributed, and add a YARA engine
   dependency — or re-express each rule as scanent's own TypeScript regex,
   citing the source rule id, with no new dependency. Re-authoring keeps the
   image dependency-free and the rules in one language; vendoring is faster and
   stays byte-for-byte auditable against the source.
3. **A new finding code, or a new report.** Put the rule findings in the agent
   report's existing `findings[]` (one more code, no schema change, Inflect
   ingests it today), or give them a contract of their own as the integrations
   and vulnerability reports have.

## Not in this page

The second, active flavour the owner asked for on 2026-11-22 — one that probes
a target and reports without damaging it — is a separate design. It breaks
scanent's "reads and never acts" promise on purpose, needs an authorisation
gate and a definition of "no damage", and is governed on its own page before
any code.
