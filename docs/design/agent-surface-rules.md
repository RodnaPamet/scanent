# Rule-based findings over the agent surface

> **Status: being built (2026-11-22). V1 to V4 are done.** V1: the contract
> `scanent-agent-rules/1` and its verifier, the re-authored MCP rule set
> (`packages/contract/src/agent-rules.ts`), the planner, the evaluation scorer
> and the corpus (`packages/scanner/evaluation/agent-rules/`). V2: the rules run
> in the `mcp` source, a scan signs `report.agent-rules.signed.json`, and the
> file output scores it into `results.json`, an "Agent surface" section of
> `summary.html` and `agent-rule-findings.csv`. V3: the report lists each
> origin it read, and the `inflect` output posts it with a key of its own. V4:
> the skill rules — the `code` source reads each `SKILL.md` under its roots and
> the scripts bundled with it (`packages/scanner/src/sources/code/skills.ts`).
> `report.pdf` carries the Agent surface section too. All of it ships in
> 0.17.0. Not yet: the A2A card rules.

## What it is

A fourth kind of finding in the AGENT scanner — not a new scanner. The agent
scanner reads an MCP server's tool definitions for identity (what tools an agent
has). This adds a pass that reads the SAME text for signs of attack written into
it — a tool whose description hides a second behaviour (tool poisoning) — and
reads two things the scanner did not read before: an agent skill's `SKILL.md`
and the scripts bundled with it, for a prompt injection, an executable payload
or an exfiltration instruction; and, later, an A2A agent card that spoofs
another agent.

This page said, until V4, that the scanner already read skills and agent cards.
It did not: no source read either one. The `mcp` source was the rules' only
input until the `code` source learned to read skills (V4), and agent cards still
need an input of their own.

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
ships with the release. Each rule is re-authored as scanent's own TypeScript
regular expression (decision 2), citing the source rule id, through scanent's
text scan, with Cisco's and the ATR set's attribution in NOTICE.

## In the contract

A report of its own (decision 3), `scanent-agent-rules/1`, beside the agent,
integrations and vulnerability reports: the same signature and envelope rules,
a verifier that reads no other contract, and a planner of its own. Each finding
is a code, the rule id that fired, the agent and the locator, and its severity.
Inflect gains a signed ingest and a tab for it, with a key scope of its own, as
the integrations report has.

## Order of work

1. The rule format and the planner, with the MCP tool-poisoning and
   injection rules first, and the evaluation corpus. No new input kind. (V1, V2)
2. Each origin in the report, and the post to Inflect. (V3)
3. The skill rules, read by the `code` source: a new input, and new codes. (V4)
4. The A2A card rules, which need an input that reads agent cards.
5. A release: 0.17.0 carries 1 to 3.

## Decisions (owner, 2026-11-22)

1. **Severity: HIGH for the strongest, MEDIUM for the rest.** An unambiguous
   rule — an executable payload in a tool's output, a literal "ignore previous
   instructions" — may raise a HIGH finding; every other rule is capped at
   MEDIUM. No rule finding is CRITICAL, and a person confirms each one. Each
   rule declares its own ceiling, and the planner holds it.
2. **Re-authored in TypeScript, not vendored.** Each rule is scanent's own
   regular expression, citing the Cisco or ATR rule id it came from, so the
   image gains no YARA engine and the rules live in one language. Cisco's
   Apache-2.0 notice and the ATR set's MIT notice go in NOTICE. A rule's test
   asserts it against the source's own example where the source gives one.
3. **Its own contract and ingest.** `scanent-agent-rules/1`, a report beside
   the other three, signed with the same key, with its own Inflect ingest, key
   scope and tab. The agent report is left unchanged.
4. **A finding closes only on positive evidence about where it was read.** The
   report lists every origin — an MCP server, a code root — read in full or in
   part, and a consumer closes a finding only when the same scanner read its
   origin in full and did not raise it again. One list, `origins[]`, for both
   families, named before 0.17.0 shipped so no consumer read the earlier
   `servers[]`.
5. **A skill is its `SKILL.md` and the scripts bundled with it.** The rules
   read the front matter and the instructions of every `SKILL.md` under a code
   root, and every script in its directory down to the next skill (by
   extension: shell, PowerShell, batch, Python, JavaScript and TypeScript, Ruby,
   Perl, PHP). The other files a skill bundles — reference Markdown, data — are
   not read. On by default; `skills: false` on a `code` source turns it off.
6. **Folded into 0.17.0.** The contract had not shipped, so the skill kinds,
   the codes and the rename went into `/1` rather than a `/2`.

## Not in this page

The second, active flavour the owner asked for on 2026-11-22 — one that probes
a target and reports without damaging it — is a separate design. It breaks
scanent's "reads and never acts" promise on purpose, needs an authorisation
gate and a definition of "no damage", and is governed on its own page before
any code.
