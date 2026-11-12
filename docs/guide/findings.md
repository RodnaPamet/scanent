# The findings, and what to do about each

A finding is one thing the scan saw that somebody should look at. There are
seven kinds. This page says, for each: what it means, why it matters, what to
do, and who usually owns the fix.

Three things are true of every finding:

- **A finding never blocks anything.** No agent is stopped or changed because
  of one.
- **A finding is closed only on evidence.** A later scan closes a finding
  when it can see that the cause is gone. Something that is merely missing
  from a later scan closes nothing.
- **"Who usually owns it" is our suggestion**, not something the scanner
  knows. Your organisation decides.

## At a glance

<!-- guide:findings -->
| Code | Severity | Can a scan on its own raise it? |
|---|---|---|
| `SHADOW_AGENT` | HIGH | Yes |
| `UNPINNED_WRITE_TOOL` | HIGH | Yes |
| `HARNESS_SHORTFALL` | HIGH, or MEDIUM for an agent that only reads | Yes |
| `EMPTY_SCAN` | HIGH | Yes |
| `INCOMPLETE_SOURCE` | MEDIUM | Yes |
| `ORPHAN_CREDENTIAL` | MEDIUM | Yes |
| `LEVEL_DROP` | MEDIUM | No. Only a system that remembers earlier scans can |
<!-- /guide:findings -->

"A scan on its own" is a scan with no Inflect tenant. The severity is fixed
for each kind. The scanner does not weigh how important a particular agent is
to you: that judgement is yours.

## `SHADOW_AGENT`

**What it means.** The scan found an agent that is on no list. With an
inventory: the agent is not in your inventory. With no inventory and no
Inflect tenant: no agent can be on a list, so every agent the scan found gets
this finding.

**Why it matters.** An agent on no list has no owner on record. Nobody has
said what it is for, nobody reviews what it can reach, and nobody will notice
when it is no longer needed.

**What to do.**

1. Find out what it is. The finding names the agent and the kind of system it
   was found in. The system's own administration shows who created it.
2. If it is wanted: give it an owner and add it to your inventory.
   [run-it.md](run-it.md#then-tell-it-which-agents-you-already-know) shows
   how.
3. If nobody claims it: disable it in the system it lives in, wait, and then
   remove it. The scanner does not do this for you.

**When it closes.** When a later scan that read everything in full finds the
agent in your inventory.

**Who usually owns it.** The team that looks after the system the agent was
found in (identity, cloud platform, or the development team for agent code),
together with whoever keeps your list of agents.

## `UNPINNED_WRITE_TOOL`

**What it means.** The agent can call a tool that can change something, and
nobody has locked that tool's description to a reviewed version. A tool counts
as able to change something unless it states that it only reads. The finding
names up to ten such tools.

**Why it matters.** An agent decides what a tool does from its description.
If the description can change without anybody noticing, the tool can start
doing something else under the same name, and the agent will go along with
it.

**What to do.**

- **For a tool offered by an MCP server** (a server that offers tools to AI
  agents): have somebody who understands the tools review the server's list.
  Then "pin" it: the scanner works out a fingerprint of the list, and that
  fingerprint is written into the scanner's settings. From then on a changed
  list shows up as unpinned again. Whoever runs the scanner makes this
  change; [../scanner.md](../scanner.md#mcp) has the detail. Separately, ask
  the server's owner to mark the tools that only read as read-only.
- **For a tool written directly in agent code, or seen only in LangSmith's
  records:** the scanner always reports these as unpinned and able to change
  something. Neither place holds a locked description or a read-only mark
  that it can read. Use the finding as a list of agents whose tools deserve a
  review. A later scan will not close it while the agent has such a tool.

**When it closes.** When a later scan read every place the agent's tools could
be in, in full, and saw no such tool.

**Who usually owns it.** The team that runs the MCP server, or the
development team that wrote the agent.

## `HARNESS_SHORTFALL`

**What it means.** The agent is below the level expected of it. The expected
level, called the bar, is H2 for an agent that only reads and H3 for an agent
that can change things, can reach outside your organisation, or whose reach
is not known. The finding names the checks that stand between the agent and
the next level.

**Read this before you act on it.** A scan on its own cannot show any agent
above H1. So in such a scan **every agent that was given a level gets this
finding**. That is a limit of what the scan could read, not a failure of each
agent. [read-the-report.md](read-the-report.md#what-a-scan-on-its-own-can-show)
explains why.

**Why it matters.** Taken together, these findings are a fair statement: for
these agents, nobody has shown that the expected controls are in place.

**What to do.** Do not work through them one by one. Use them to set
priorities:

1. In `agents.csv`, look at the columns for the individual checks. Start with
   the cells that say `NOT_MET`: a system saw that control fail. Those are
   real, whatever else the scan could not see. (One exception: on
   `H1.axes_declared` and `H1.tier_scored_fresh`, `NOT_MET` can mean only
   that your inventory leaves out the descriptions or the risk rating for
   that agent, or that the rating is not dated within the 365 days before
   the scan. The fix for those is to complete the inventory.)

   The page and the spreadsheet say only that a check failed. To see what
   was looked at, ask whoever ran the scan: the data file `results.json`
   holds, for each answer, a reference to where it was seen, such as a file
   and a place in it. Then take the check's plain-word meaning from
   [read-the-report.md](read-the-report.md#the-checks-on-each-level) to the
   agent's owner, and ask for that control to be put in place.
2. Next, the agents that can change things and that nobody owns.
3. The cells that say `NOT_READABLE` or `UNANSWERED` mean that nobody looked.
   Decide with the engagement team whether to look by other means. For
   example, ask the agent's owner to show you the written policy, or the
   approval step, by hand.

If the level rests partly on your inventory, the finding says so, and gives
the level that the systems alone support.

**When it closes.** When a later scan shows the agent at its bar.

The finding's own text also mentions "a time-limited acceptance by the
agent's owner". An acceptance is recorded in an Inflect tenant. A scan on its
own has no way to record one, so here the finding stays open until the agent
is at its bar.

**Who usually owns it.** The owner of the agent, for the agent. Whoever is
responsible for how AI agents are governed, for the picture as a whole.

## `EMPTY_SCAN`

**What it means.** The scan found no agent at all.

**Why it matters.** It is rarely good news. An empty result is what a scanner
pointed at the wrong place looks like: the wrong directory, the wrong
project, the wrong repositories, a folder with no agent code in it. The
report shows it as a finding and never as a clean result.

**What to do.**

1. Check what the scan was told to read: the directory id, the projects, the
   repositories, the folders.
2. Check the first section of the report. If a system is "Incomplete", fix
   that first.
3. Run the check step again ([run-it.md](run-it.md#5-check)).
4. If you are sure the place is right and it really holds no agents, record
   that conclusion yourselves. The scanner will not draw it for you.

**When it closes.** When a later scan finds at least one agent.

**Who usually owns it.** Whoever runs the scan.

## `INCOMPLETE_SOURCE`

**What it means.** One kind of system could not be read in full. There is one
such finding for each. It gives the reason.

**Why it matters.** Agents and tools in that system may be missing from the
report. Agents that depend on it are given no level. And nothing is treated
as gone or fixed on the strength of this scan.

**What to do.** Look up the reason in
[read-the-report.md](read-the-report.md#completeness-per-source), fix the
cause, and scan again. Likely causes are a credential that expired or lacks
its role, a firewall that does not allow the connection, and a system too
large to read in the time allowed.

**When it closes.** When a later scan reads that system in full.

**Who usually owns it.** Whoever runs the scan, with the administrator of the
system that could not be read.

## `ORPHAN_CREDENTIAL`

**What it means.** A key or secret exists, and no agent the scan found uses
it. Today the scanner can see this in two places: in Microsoft Entra ID, a
password or certificate on an application that has no account to sign in as;
and in GitHub, a stored secret that no workflow refers to.

The scanner raises this only when it is sure of its ground: the system
holding the credential was read in full, and so was every system in the scan
that could have named the agent it belongs to. When it is not sure, the
credential is listed in the report under "Seen unbound, not concluded", and
there is no finding.

**Why it matters.** A credential that nothing uses is one that nobody
rotates and nobody will miss. If it leaks, it still works.

**What to do.**

1. Ask the owners of the application or repository whether anything still
   needs it. The scan sees only the systems it was given: a credential can be
   in use from somewhere the scan did not read.
2. If nothing needs it, remove it.
3. If something does, note what, so that the next review does not have to ask
   again.

**When it closes.** When a later scan by the same scanner reads the same
system in full and no longer sees the credential unused.

**Who usually owns it.** The owner of the application or repository that
holds the credential.

## `LEVEL_DROP`

**What it means.** An agent's level is lower than it was at the previous scan.

**You will not see this in a scan on its own.** One scan does not remember
earlier scans, so it cannot raise this finding. It is raised by a system that
keeps the history of scans, such as an Inflect tenant. Without one, you find
the same thing by comparing two runs: the comparison says "level down" and
shows the old and the new level.
[read-the-report.md](read-the-report.md#comparing-two-runs) explains the
comparison.

**Why it matters.** A control that was shown to be in place is no longer
shown to be. Either something changed in the agent, or something changed in
what the scan could read.

**What to do.**

1. Check completeness first. If a system was read less fully than before, the
   drop may be about the scan and not about the agent.
2. Check whether the inventory changed. A risk rating older than 365 days no
   longer counts as recent, and that alone takes an agent from H1 to H0.
3. Otherwise, the finding names the checks that now stand in the way. Ask the
   agent's owner what changed.

**When it closes.** It does not. It records that something happened at that
scan. Deal with it, and note what you did.

**Who usually owns it.** The owner of the agent.

## Where the detail is

- [../contract.md](../contract.md#findings): the exact rule for each kind,
  for a technical reader.
- [read-the-report.md](read-the-report.md): how the findings appear in the
  report and the spreadsheet.
