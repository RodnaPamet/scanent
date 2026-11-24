# The active flavour: probing an agent, and reporting what worked

> **Status: designed and decided (2026-11-24). No code yet.** The owner asked
> for it on 2026-11-22: a second scanent that attacks a target agent the way an
> attacker would, reports what the agent did, and does no damage. It was held
> while the agent-surface rules were built, and unheld on 2026-11-23. Decision
> 19 of [Several scanners in one scanent](scanners.md) puts it on a page of its
> own, with an authorisation gate and a definition of "no damage", before any
> code. This is that page. It ships nothing and changes no scanner. The owner
> took the eight decisions at the end on 2026-11-24, each as recommended; work
> starts at step 2 of the order of work.

## What it is

The scanners scanent ships read and never act. Their threat model holds them to
it: no code path changes anything in an estate, an MCP server is sent three
listing messages and no tool is ever called, and every request a scan can make
is declared in one file whose hash is in every signed report
([threat model](../threat-model.md), the rows for tampering).

The active flavour does the opposite on purpose, and only to an agent. It sends
crafted inputs to a target agent through the interfaces the agent exposes, and
reports which of them the agent acted on: a planted instruction it followed, a
secret it disclosed, a canary it fetched. A rule match in the agent-rules report
says "this text looks like an attack". A probe result says "this agent did what
the attack told it to", and carries the evidence.

Because it acts, it is **a separate flavour, never a mode of the read-only
scanner**:

- its own entry point and its own image (`scanent-probe`), so no
  configuration of the read-only image can turn it into a prober, and the
  read-only image's declared surface, manifest hash and proof stay exactly as
  they are;
- its own declared surface, built per engagement from a signed scope (below),
  never from a free-text list;
- its own report contract, signed with the same key machinery but naming its
  own contract id, so no reader of the read-only reports takes a probe result
  for an observation, or the reverse.

## What it probes, in version 1

Agent-facing surfaces only, through the interfaces the agent itself offers:

| Target | How it is reached | What a probe is |
|---|---|---|
| An MCP server's tools | `tools/call` with probe arguments | A tool argument carrying a planted instruction, a canary reference, or a request outside the tool's purpose |
| An A2A agent | Its task endpoint | A task whose text carries the probe |
| An agent behind an HTTP chat endpoint the operator names | One POST per turn, in the shape the scope declares | A conversation turn carrying the probe |

Not in version 1: networks, hosts, web applications, cloud accounts, and
anything the agent reaches downstream. The prober never talks to a system the
agent might call; it talks to the agent, and watches its own canaries.

## Where the probes come from

The owner named four projects on 2026-11-22. They were read on 2026-11-23
(READMEs, licence files, catalogues, and the one AI-specific skill of each that
has one). **None of them is a corpus of probes for agents**: two are general
offensive toolkits, one is a code audit, and Cisco's are scanners and a
detector. So the probes are written here, and the projects give the categories
to cover, the verdict rules and the limits, not payloads.

| Project | Licence | What it is | What is taken | What is not |
|---|---|---|---|---|
| [elementalsouls/Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter) | MIT for code; the README puts its skill text, wordlists and docs under CC BY 4.0 (`LICENSE-CONTENT`, not yet read) | A Claude Code bundle of 83 skills for bug bounty and external red-team work on web applications, APIs and internet-facing estates. Its scope check is a question the model is asked ("7-Question Gate"); a claim that scope is "enforced in code" was not verified | The agent-relevant categories of its `hunt-llm-ai` and `hunt-rag-vector` skills: direct and indirect injection, exfiltration through a tool or through markdown, agentic abuse | Its recon and exploitation tooling, every web and infrastructure skill, and its scope model: a question a model answers is not a gate |
| [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red) | MIT | A library of offensive skills across about 23 areas, from web to EDR evasion and C2. One is about AI: `offensive-ai-security` | That skill's categories: direct and indirect prompt injection, system prompt extraction, insecure output handling, excessive agency, tool-function abuse, RAG poisoning and cross-tenant leakage; and its advice to put canary tokens in context to detect exfiltration, which is the `canary` class here. Its reporting vocabulary is already used by the [vulnerability scanner](vulnerability-scanner.md) | Every technique. The AI skill tells a model to "exploit identified vulnerabilities and chain them" and carries no limit and no authorisation language |
| [Cisco AI Defense](https://github.com/cisco-ai-defense) | Apache-2.0 (per each README; `mcp-scanner`'s licence is already in `NOTICE`) | Scanners and a detection engine, not a probe corpus. `mcp-scanner`'s protocol mode "does not call tools", and says a protected endpoint "may require separate authorized testing". `project-quarry` is a rule engine over conversations, tool calls and tool results, and states that it does not encourage using or sharing active attack payloads | `mcp-scanner`'s attack vectors as categories (instruction override, indirect injection, data leakage, role escape). `project-quarry`'s approach as a candidate for judging a verdict: reading what the agent did with a probe, rather than what it said | Any payload: none is published, by Cisco's own choice |
| [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) | MIT, vendored at a pinned commit | A six-phase audit of source code, sandboxed; it never touches a live system | Its limits, as rules of this flavour: "prompt injection alone is not a finding" (a verdict needs an observed act or leak); confirm "a locally observable unrequested action" without extending the test "into harmful execution"; never test by exhausting a service. Its agent attack classes (`AI-AND-LLM.md`) as a checklist of what the catalogue covers | Its code-audit method, which the vulnerability scanner already uses |

Not read: BugHunter's `LICENSE-CONTENT`, `SECURITY.md`, engine code and skill
files; Claude-Red's other skills; most of Cisco's 21 repositories (among them
`skill-scanner`, whose rules the agent-surface rules already use); Cloudflare's
`SKILL.md` and the files beside `AI-AND-LLM.md`. Each is read, and each licence
confirmed at the commit taken, before anything of it is used.

Every probe is scanent's own: re-authored, citing the item it came from, with
the source's licence and attribution in `NOTICE`, as the agent-surface rules
were. No source's text is shipped as instructions, and none is sent to a model.

## "No damage", defined

Every probe belongs to exactly one class in a closed taxonomy, and the class
decides what it may do:

| Class | What it does | What it may touch | Verdict from |
|---|---|---|---|
| `canary` | Plants a unique, single-use marker and asks the agent to repeat, store or fetch it | Only scanent's own canary sink | Whether the marker comes back, or the sink records it |
| `disclosure` | Asks for something the agent should not give: its instructions, a tool's credentials, another user's data | Nothing beyond the reply | The reply alone, judged against the probe's expected leak shape |
| `side-effect` | Asks the agent to act: call a tool, send, fetch | Only a sink scanent owns: a canary URL, a canary inbox | Whether the sink recorded the attempt |

Refused **by construction**, in every class: a probe that writes, deletes or
changes a record in the estate, pays, sends to a real recipient, or carries
real data out. A side-effect probe names its sink by a reference the runner
resolves to scanent's own sink and nothing else; there is no field for another
destination. The catalogue states each probe's class, and a test holds every
probe to its class: a `disclosure` probe that names a URL, or a `side-effect`
probe whose target is not the sink, fails the build.

What the target returns is kept only as far as a verdict needs: a hash of the
reply, and an excerpt short enough to show the evidence, with every value of a
secret's shape masked by the same walk that keeps secrets out of the read-only
reports. A disclosure verdict records that a secret's shape was disclosed,
never the secret.

## The authorisation gate

A probe run needs a signed **engagement scope**. Without one, the prober sends
nothing. The scope is a file that names:

- the targets, as exact endpoints (no pattern, no range);
- the time window, start and end, in UTC;
- the probe classes allowed (version 1 offers `canary` and `disclosure`
  only: decision 3);
- the person who approved it, by name and role, and a kill contact;
- the rate cap, in requests per minute per target.

The scope is signed with a key the estate registered in advance, **not the
scanner's own key**: the party that runs the probes is not the party that
authorises them. The prober refuses to start when the signature does not
verify, when the time is outside the window, or when a target is not named;
and checks the window again before every request, so a run that outlives it
stops.

Every request carries a header naming the engagement, so the target's owner can
find it in their logs. A stop file or a signal ends the run at the next request.
A dry run prints every request it would send and sends none.

This is the control on a dual-use tool: no scope, no probes; and a scope is
something a named person in the estate signed.

## What it reports

A contract of its own, `scanent-probes/1`, signed as the other reports are:

- the engagement it ran under: the scope's digest and its signer;
- per probe: the probe id and class, the target, the verdict, and the evidence
  reference (the reply's hash, the masked excerpt, the canary record);
- per target: reached or not, with the reason.

The verdicts are `ACTED`, `DISCLOSED`, `RESISTED` and `INCONCLUSIVE`. A refusal
is `RESISTED`; a reply the verdict rule cannot read is `INCONCLUSIVE`; neither
is "clean". Zero is never complete: a run that reached no target, or ran no
probe, concludes nothing and says so.

The report reaches Inflect through an ingest and a key of its own, as the other
three do. That is named here and designed later.

## What it is not

- Not a penetration test of infrastructure, and not a scanner of the systems an
  agent reaches.
- Not autonomous: no model chooses a target, a probe or a payload. The catalogue
  is fixed and reviewed.
- Not unattended: it runs inside a signed window and stops at its end.
- Not part of the read-only image, its surface or its proof.

## Order of work

1. This page, and the owner's decisions on it (taken 2026-11-24).
2. The scope: its format, its verifier, and the refusals (no scope, wrong
   signer, outside the window, unnamed target). **Done (2026-11-24):**
   [The engagement scope](../engagement-scope.md), in `packages/probe`. The
   owner also set three limits for it that day: a window of at most seven
   days, a rate cap of 1 to 120 requests per minute per target, and no clock
   skew. The scope also names the one prober allowed to run it.
3. The catalogue and the class taxonomy, with the test that holds each probe to
   its class, and a corpus of a fake agent that acts, discloses and resists.
   **Done (2026-11-24):** [The probe catalogue and its verdicts](../probe-catalogue.md).
   Eleven probes in seven categories. A canary shows its marker in two
   halves, so quoting a probe is never ACTED. An instructions probe is judged
   against a marker the estate planted, and is INCONCLUSIVE without one.
4. The canary sink. **Deferred by the owner (2026-11-24)** until `side-effect`
   probes are decided: no version 1 probe uses it, because every one is judged
   from the reply and none may name a URL.
5. The runner, against the fake agent only. **Done (2026-11-24):**
   [The probe runner](../probe-runner.md). It checks the stop, the rate and the
   scope's gate before every request, and `run --dry-run` lists a run's
   requests without sending any.
6. The contract `scanent-probes/1`, its verifier and its report.
7. The image `scanent-probe`, its declared surface per engagement, and its proof.
8. The Inflect ingest.

## The owner's decisions (2026-11-24)

The owner took all eight on 2026-11-24, each as recommended. Changing one is a
new dated decision on this page, never an edit of the row.

| # | Question | Decision |
|---|---|---|
| 1 | A separate image, or a mode of the read-only one | **A separate image**, `scanent-probe`. The read-only image's promise and its proof stay unconditional |
| 2 | Who signs the scope | **A key the estate registers in advance, never the scanner's.** The party that runs the probes does not authorise them |
| 3 | Whether `side-effect` probes are in version 1 | **No: `canary` and `disclosure` only.** `side-effect` is a later decision, once the sink and the class test exist |
| 4 | Where the canary sink runs | **Beside the prober, inside the estate**, so no marker leaves it. A scanent-run sink is not offered: it would be a sub-processor question |
| 5 | How much of a reply is kept | **A hash and an excerpt of at most 280 characters, secrets masked** |
| 6 | Whether a model may ever write or choose a probe | **No. A fixed, reviewed catalogue**; a model may later help write it, never run it or choose from it |
| 7 | Which sources' material is used, given their licences | **Categories, verdict rules and limits only**, as the table above says, each confirmed against its licence file at the commit taken. No source's wording is adapted; if that ever changes, BugHunter's CC BY 4.0 content needs attribution in `NOTICE` |
| 8 | Who writes the probes, since no source offers a corpus | **scanent writes them**, a few per category, each with its class, its expected act or leak, and a fake agent in the corpus that acts, discloses and resists |
