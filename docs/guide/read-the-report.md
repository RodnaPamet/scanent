# Read the report

Each scan writes one folder with six files:

| File | What it is for |
|---|---|
| `summary.html` | The report to read. Open it in a browser. It is one file, loads nothing from the internet, and prints |
| `agents.csv` | One line for each agent, for a spreadsheet |
| `findings.csv` | One line for each finding, for a spreadsheet |
| `results.json` | Everything above, as data for another program |
| `report.signed.json` | The signed record of what the scanner read. The other files are worked out from it |
| `manifest.json` | The size and a checksum of each of the other five files, to check that a copy of the folder is whole |

This page explains `summary.html` from top to bottom, then the two
spreadsheets, then how to compare two scans.

## The one rule behind everything

**What nobody checked counts as not done.** The scanner gives an agent credit
for a control only when it saw evidence of it. A control that nobody looked
at, or that somebody claimed with nothing to show for it, counts the same as a
control that is missing.

This is deliberate. The other choice would give the best score to the agent
nobody can see into.

It has a consequence you must keep in mind: **a low level does not always mean
a badly controlled agent.** It can mean that this scan had no way to look. The
report tells the two apart, and this page shows where.

## The six levels

Every agent is placed on a ladder of six levels. An agent is at a level only
when every check on that level **and on every level below it** is met with
evidence.

<!-- guide:levels -->
| Level | Name | In plain words | An example |
|---|---|---|---|
| H0 | Shadow | It exists. Nothing more is established | A service account found in Google Cloud that is on nobody's list. The scan can say it exists and which keys it holds. Nobody has said who owns it |
| H1 | Registered | Your organisation knows it: it is on a list, has an owner, is described, and has a recent risk rating | Your inventory has a line for "Invoice triage". It names finance operations as the owner, says the agent needs a person's approval, handles confidential data and can write, and carries a risk rating dated two months ago |
| H2 | Bounded | What it can use is limited and known: its own credential, an explicit list of what it may touch | A GitHub Actions workflow that uses only the token GitHub gives each run, and states the permissions of every job explicitly, meets three of the five checks on this level |
| H3 | Guarded | What it does is checked before it takes effect | An agent whose changes are put to a person as proposals, whose tool descriptions are locked so they cannot change unnoticed, and whose outgoing connections are held to a list. The opposite: an agent whose code tells it to approve all of its own actions fails this level |
| H4 | Observed and stoppable | Going by the names of its checks: what it does is recorded, it has a spending limit, and stopping it has been practised | An agent with a record of every action, and a stop switch that was tried in a drill |
| H5 | Evidenced | Going by the names of its checks: the controls are backed by evidence and by somebody independent | An agent whose controls were audited by somebody outside the team that runs it |
<!-- /guide:levels -->

A level never stops an agent. It is a statement in a report.

### The checks on each level

The spreadsheet has one column for each check, named as in the first column
below. Where this guide can only go by a check's name, it says "by its name":
the full definition belongs to the people who maintain the ladder, and the
engagement team can get it for you.

<!-- guide:criteria -->
| Check | In plain words |
|---|---|
| `H1.registered` | It is on a list of known agents |
| `H1.owner` | It has a named owner |
| `H1.axes_declared` | Three things are written down: how independent it is, how sensitive its data is, and what it can reach |
| `H1.tier_scored_fresh` | It has a risk rating, and the rating is recent. For an inventory: dated within the 365 days before the scan |
| `H2.credential_bound` | It acts with a credential of its own. A token that acts as a person does not count; nor does a workflow that is handed a stored secret |
| `H2.grant_kind_declared` | It is known whether its credential acts for the agent itself or on behalf of a person |
| `H2.tools_allowlisted` | What it may use is an explicit list. "Everything", or a wildcard, is not a list |
| `H2.audience_tokens` | Its keys work only through short-lived tokens limited to named tools. Checked only through an Inflect tenant |
| `H2.policy_card` | By its name: a written policy exists for it. Checked only through an Inflect tenant |
| `H3.manifests_pinned` | The descriptions of its tools are locked ("pinned"), so a changed tool is noticed |
| `H3.payloads_guarded` | Something inspects a call before it runs |
| `H3.propose_not_commit` | It proposes changes for approval. It does not apply them by itself |
| `H3.prior_state_reads` | By its name: it reads how things stand before it changes them |
| `H3.skills_declared` | Its instructions and skills come from places that are declared, not from whatever files happen to be on the machine |
| `H3.delegation_narrows` | By its name: when it hands work to another agent, that agent gets less authority, not more |
| `H3.egress_enforced` | Its outgoing network connections are held to a list, and the limit is really enforced, not only written down |
| `H4.ledger_baseline` | By its name: a record of its actions exists |
| `H4.receipts` | By its name: each action leaves a receipt |
| `H4.kill_switch_drilled` | By its name: its stop switch has been tried in a drill |
| `H4.token_budget` | By its name: it has a spending limit |
| `H5.asi_coverage` | By its name: coverage against a set of agent security controls |
| `H5.evidence_emitted` | By its name: it produces evidence of its controls |
| `H5.skills_evaluated` | By its name: its skills have been evaluated |
| `H5.sample_audit` | By its name: a sample of its work is audited |
| `H5.independent_audit` | By its name: somebody independent audits it |
<!-- /guide:criteria -->

## What a scan on its own can show

This is the most important limit to understand. A scan "on its own" is one
with no Inflect tenant: the normal case in this guide.

Many checks can only be confirmed by a system that holds an organisation's
own register of agents. The scanner reads one such system, an Inflect tenant.
Without it, nothing the scanner reads can confirm those checks, so they count
as not done, for every agent.

<!-- guide:ceilings -->
| What the scan had | Highest level it can show for any agent |
|---|---|
| The systems only, and no inventory | H0 |
| The systems and your inventory | H1 |
| The systems and an Inflect tenant's register | H3 |
<!-- /guide:ceilings -->

Level by level:

| Level | Can a scan on its own show it? |
|---|---|
| H0 | Yes. It is where every agent starts |
| H1 | Yes, with your inventory. Everything it rests on is then "declared by the operator" |
| H2 | No. Two of its five checks can be confirmed only through an Inflect tenant. The scan can still show the other three one by one, from Microsoft Entra ID, Google Cloud, Okta and GitHub Actions |
| H3 | No. Every check on it can be confirmed only through an Inflect tenant. From agent code the scan can show three of them as **failed**, never as met: code can show that a control is missing, not that one works |
| H4 | No. Nothing in the scanner checks this level today, with or without a tenant |
| H5 | No. The same |

So in a scan on its own, **every agent is reported below its expected
level**. That is a limit of what was read. The report says so itself, in its
second section, in these words: "This run could not have shown any agent at
its bar". Do not read it as every agent having failed.

What a scan on its own does show well: which agents exist, which of them you
did not know about, which keys they hold and how old those are, which tools
they can call, and which individual checks were seen to fail.

## The page, from top to bottom

### The top of the page

The name you gave the scan, its id, and the time of the scan. Then one line:

- **"Complete. Every listed source was read in full."** A "source" is one
  kind of system that was read.
- **"Incomplete:"** followed by how many sources were not read in full.

Read this line first. Everything below depends on it.

### Completeness per source

A table with one line for each kind of system: whether it was read in full,
the reason if not, how many records were read, and how many agents were found
there.

When a system is "Incomplete", the reason is one of these:

| Reason | What happened | What to do |
|---|---|---|
| `AUTH_FAILED` | The credential was missing, refused or unusable | Check the credential and its role. Run the check step again |
| `UNREACHABLE` | The system did not answer, or answered with an error | Check the network path and the firewall |
| `RATE_LIMITED` | The system said the scanner was asking too fast | Scan again later |
| `TIME_BOX` | Reading took longer than the time allowed for one system | Scan again, or ask for the time limit to be raised |
| `BYTE_CAP` | A size limit was reached: there was more than one scan may hold | Split the scan into smaller ones. The engagement team can advise |
| `PAGINATION_TORN` | A list came back broken, or its next page could not be followed | Scan again. If it repeats, report it |
| `UNPARSEABLE` | A piece of agent code was read but part of it could not be worked out | Tell the engagement team. The agent is in the report, but what it holds may be incomplete, so it is given no level |

**An incomplete scan is never a clean result.** A system that was read only in
part may hold agents, tools and failed checks that the page does not show. So
on an incomplete scan the page never says that something is gone, closed or
resolved.

### What this scan could not evidence

This section states the highest level the scan could have shown for any
agent, as explained above. It then lists every check that nothing in this
scan could have confirmed, and why:

- "No reader in scanent reports this criterion": no scan can confirm it today.
- "A reader exists; this run did not configure it": a system that could
  confirm it was not part of this scan.

### Estate summary

Six numbers:

| Number | Meaning |
|---|---|
| Agents found | Everything the scan found |
| Judged | Agents that were given a level |
| Not judged | Agents that were given no level, because a system they depend on was not read in full |
| Below their bar | Judged agents below the level expected of them (see "The bar" below) |
| Shadow agents | Agents that are on no list |
| Orphan credentials | Keys and secrets that no agent uses |

Then a small chart of how many judged agents are on each level.

**If the scan found no agents at all**, this section says so in a highlighted
box: "This scan found no agents. That is a finding, not a clean result." An empty result
is what a scanner pointed at the wrong place looks like. It is never good
news by itself.

### Agents and criteria

The main table. One line for each agent, one column for each check.

The first columns:

| Column | Meaning |
|---|---|
| Agent | The scanner's id for the agent. If your inventory names it, the name is shown, marked "name declared by the operator" |
| Registration | "Not registered", "Declared by the operator" (it is in your inventory) or "In the Inflect register" |
| Reach | "Read only", "Write or external", or "Unknown" |
| Level | The level, or "Not judged" |
| Bar | The level expected of this agent, and "At bar" or "Below bar" |

Then one small cell for each check:

| Cell | In the spreadsheet | Meaning |
|---|---|---|
| E | `EVIDENCED` | Met. A system showed it |
| D | `DECLARED` | Met on what your inventory says. The scanner did not see it for itself |
| M | `MET_UNEVIDENCED` | Reported as met, with nothing to show for it. Counts as not met |
| N | `NOT_MET` | Not met. A system showed it failing |
| · | `UNANSWERED` | Nobody answered, although something in this scan could have. Counts as not met |
| – | `NOT_READABLE` | Nothing in this scan could have answered. Counts as not met |

The difference between N and the last two matters. N is a failure somebody
saw. The dot and the dash mean nobody looked.

**Reach** is what the agent can do. A tool that does not state that it only
reads is treated as able to change things. An agent is shown as "Read only"
only when all its tools say so **and** the scan read your MCP servers in
full; otherwise a tool that can write might simply be missing from the
picture, and the reach is "Unknown".

**The bar** is the level expected of an agent: H2 for an agent that only
reads, and H3 for one that can write, can reach outside, or whose reach is
unknown.

On a large scan this table shows the 500 agents that most need attention, and
says so. The spreadsheet always has all of them.

### Shadow agents

The agents that are on no list. With no inventory and no Inflect tenant,
every agent is one, so the section says that instead of repeating the table.

### Orphan credentials

Keys and secrets that the scan saw attached to no agent. A second list, "Seen
unbound, not concluded", holds those the scan could not be sure about, because
a system that might have named their user was not read in full.

### Findings

Every finding, most severe first. Click a title to open its explanation.
[findings.md](findings.md) explains each kind and what to do.

"No finding was raised" on an incomplete scan is followed by "The scan is
incomplete, so this is not a clean result."

### Inventory

Shown only when you gave an inventory. How many lines it has, how many
matched an agent the scan found, and which did not. A line that matched
nothing is "declared, not found by this scan". That is not a statement that
the agent is gone: the scan may not read the place where it lives.

### Provenance

The technical record: which version of the scanner ran, the fingerprint of
the signing key, and a checksum of the signed report. Keep this section with
any copy of the report you pass on. It lets somebody else check that the
files belong together.

## Words the results use

| Word | Meaning |
|---|---|
| Incomplete | A system was not read in full. Things may be missing. Nothing is concluded from their absence |
| Not judged | The agent was found, but it has no level, because a system that could have said something about it was not read in full. In the spreadsheet its level is empty. It is never shown as H0 |
| Declared by the operator | It comes from your inventory. The scanner did not observe it. It counts for level H1 only, it is labelled in every file, and it is never put in the signed report |
| Not checked | Used by the check step (`doctor`), for a check it did not make. It always gives the cause: "not applicable" (there was nothing to check), "blocked" (an earlier check failed, so this one could not be made) or "not observable" (nothing the scanner reads can answer it, and the line says what to confirm by hand). It is never counted as passed |
| Not concluded | Something is no longer reported, and the scan cannot say that it is gone |
| Shadow agent | An agent that is on no list |
| Orphan credential | A key or secret that no agent uses |
| Pinned | A tool's description has been locked to a known version, so a later change is noticed |

When an agent is not judged, the page gives a code and a sentence for each
reason:

| Code starts with | Meaning |
|---|---|
| `SOURCE_INCOMPLETE` | A system the agent was found in was not read in full |
| `VERDICT_SOURCE_INCOMPLETE` | A system that reports on agents found elsewhere was not read in full |
| `OTHER_SOURCE_INCOMPLETE` | Not a reason, a note: another system was not read in full, and it does not affect this agent |

## The two spreadsheets

Both open in any spreadsheet program. A cell that a spreadsheet might run as
a formula is written with a leading single quote, so it is shown and never
run.

### agents.csv

One line for each agent. The first columns:

| Column | Meaning |
|---|---|
| `discoveredId` | The scanner's id for the agent. Copy it exactly when you write an inventory |
| `declaredName`, `declaredOwner`, `declaredPurpose` | What your inventory says. Empty if the agent is not in it |
| `observedOwnerKind`, `observedOwnerRef` | The owner a system reported: a user or a group, and its id |
| `discoveredVia` | The kind of system the agent was found in |
| `registration` | `NONE`, `DECLARED_INVENTORY` or `OBSERVED_REGISTER` |
| `judged` | `yes` or `no` |
| `level` | The level. Empty when not judged |
| `observedLevel` | The level if everything from your inventory is set aside |
| `notJudgedReasons` | Why not, when not judged |
| `reach` | `READ_ONLY`, `WRITE_OR_EXTERNAL` or `UNKNOWN` |
| `bar` | The level expected of it |
| `shortfall` | `yes` when the agent is below its bar |
| `blockingNextRung` | The checks that stand between the agent and the next level |
| `credentials`, `tools`, `writeCapableTools`, `unpinnedWriteTools` | Counts: its keys, its tools, the tools that can change things, and those of them that are not pinned |

Then one column for each check, holding one of the six words in the table of
cells above.

Useful first sorts: by `registration` to see what you did not know about; by
`unpinnedWriteTools` to see the agents that can change the most with the
least review; by `observedOwnerRef` to find agents with no owner.

### findings.csv

One line for each finding:

| Column | Meaning |
|---|---|
| `code` | The kind of finding. [findings.md](findings.md) explains each |
| `severity` | `LOW`, `MEDIUM`, `HIGH` or `CRITICAL` |
| `type` | `NONCONFORMITY` (something is not as it should be) or `OBSERVATION` (something to look at) |
| `sourceRef` | A stable reference for the finding. The same finding has the same reference in the next scan |
| `discoveredId` | The agent it is about. Empty for a finding about the scan itself or about a credential |
| `title`, `description` | What was found, in words |

## Comparing two runs

One scan is a snapshot. Two scans show what changed. The command is in
[run-it.md](run-it.md#running-it-again-and-comparing). It prints a short text
report.

It starts with one of three sentences:

| It says | Meaning |
|---|---|
| "No difference, and every comparison could be made." | Nothing changed |
| "The two runs differ." | Something changed, listed below |
| "No difference was found, but not every comparison could be made." | Do not read this as "nothing changed". Something could not be compared, and the end of the report says what |

What to look at, in this order:

1. **Completeness.** Did a system that was read in full before come back
   incomplete? If so, treat the rest with care.
2. **Agents.** "new" is an agent that was not there before. "gone" is used
   only when every system the agent was found in was read in full this time.
   Otherwise the word is "not seen", with the reason, and nothing is
   concluded.
3. **Levels.** "level up" or "level down". Levels are compared only for
   agents that both scans judged.
4. **Findings.** "opened" is new. "closed" is used only when the newer scan
   has the evidence to close it. Otherwise the line reads "no longer reported,
   not concluded".
5. **Orphan credentials.** The same three words.
6. **Warnings.** For example, that the two scans used different inventories.
   Then what you declared shows up as a change, although nothing in your
   systems moved.

The rule is the same as for one scan: **something missing counts as gone only
when the place it would be in was read in full.**

The comparison refuses to run, and says why, when the newer scan is not later
than the older one, when the two scans come from different scanners, or when
they were scored on different versions of the ladder.

A scan on its own does not remember earlier scans. So a drop in an agent's
level is something you see here, in the comparison, and not as a finding in
the report of one scan.

## Where the detail is

- [../scanner.md](../scanner.md#local-results): every file and every rule
  behind this page.
- [../contract.md](../contract.md#the-ladder): the ladder and the signed
  report, for a technical reader.
