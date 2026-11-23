# The active flavour: probing an agent, and reporting what worked

> **Status: being designed (2026-11-23). No code.** The owner asked for it on
> 2026-11-22: a second scanent that attacks a target agent the way an attacker
> would, reports what the agent did, and does no damage. It was held while the
> agent-surface rules were built, and unheld on 2026-11-23. Decision 19 of
> [Several scanners in one scanent](scanners.md) puts it on a page of its own,
> with an authorisation gate and a definition of "no damage", before any code.
> This is that page. It ships nothing and changes no scanner. The decisions it
> needs are at the end.

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

The owner named four projects on 2026-11-22. What this repository already
records of them, and what is still to be read:

| Project | Licence, as recorded here | Where it stands |
|---|---|---|
| elementalsouls' Claude-BugHunter | Not yet read | The starting point the owner named for this flavour. Its licence, its scope and whether it targets agents or general web applications are to be read before anything is taken |
| [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red) | MIT ([vulnerability scanner](vulnerability-scanner.md)) | Only its reporting vocabulary is used today. Its techniques tell a model to send payloads to live targets, evade detection and exfiltrate data; none of that is taken as it stands |
| Cisco AI Defense | Apache-2.0 for the three scanners the rules come from ([agent-surface rules](agent-surface-rules.md)) | Which of its repositories carry adversarial tests for agents, and under what licence, is to be read |
| [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) | MIT, vendored at a pinned commit | A method for auditing code, not a set of probes; its attack classes may name what to probe |

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
- the probe classes allowed (version 1 recommends `canary` and `disclosure`
  only);
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

1. This page, and the owner's decisions on it.
2. The scope: its format, its verifier, and the refusals (no scope, wrong
   signer, outside the window, unnamed target).
3. The catalogue and the class taxonomy, with the test that holds each probe to
   its class, and a corpus of a fake agent that acts, discloses and resists.
4. The canary sink.
5. The runner, against the fake agent only.
6. The contract `scanent-probes/1`, its verifier and its report.
7. The image `scanent-probe`, its declared surface per engagement, and its proof.
8. The Inflect ingest.

## Decisions for the owner

| # | Question | Recommendation |
|---|---|---|
| 1 | A separate image, or a mode of the read-only one | A separate image. The read-only image's promise and its proof stay unconditional |
| 2 | Who signs the scope | A key the estate registers in advance, never the scanner's |
| 3 | Whether `side-effect` probes are in version 1 | No: `canary` and `disclosure` only. Add `side-effect` once the sink and the class test exist |
| 4 | Where the canary sink runs | Beside the prober, inside the estate, so no marker leaves it. A scanent-run service is a sub-processor question |
| 5 | How much of a reply is kept | A hash and an excerpt of at most 280 characters, secrets masked |
| 6 | Whether a model may ever write or choose a probe | No. A fixed, reviewed catalogue; a model may later help write it, never run it |
| 7 | Which sources' material is used, given their licences | As the table above says; each to be confirmed against the licence file at the commit taken |
