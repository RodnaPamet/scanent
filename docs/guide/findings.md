# The findings, and what to do about each

A finding is one thing the scan saw that somebody should look at. There are
nine kinds. This page says, for each: what it means, why it matters, what to
do, and who usually owns the fix. The integrations scanner, which reads what
your directory has granted to applications, raises five more of its own: they
are at the end of this page, under "Integration findings".

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
| `UNREGISTERED_IDENTITY` | MEDIUM | Yes |
| `UNPINNED_WRITE_TOOL` | HIGH | Yes |
| `HARNESS_SHORTFALL` | HIGH, or MEDIUM for an agent that only reads | Yes |
| `EMPTY_SCAN` | HIGH | Yes |
| `INCOMPLETE_SOURCE` | MEDIUM | Yes |
| `ORPHAN_CREDENTIAL` | MEDIUM | Yes |
| `SPENDING_AGENT_UNDECLARED` | HIGH | Yes, for every listed agent whose code can pay. A scan on its own cannot see a spending limit, so it cannot tell which have one |
| `LEVEL_DROP` | MEDIUM | No. Only a system that remembers earlier scans can |
<!-- /guide:findings -->

"A scan on its own" is a scan with no Inflect tenant. The severity is fixed
for each kind. The scanner does not weigh how important a particular agent is
to you: that judgement is yours.

## `SHADOW_AGENT`

**What it means.** The scan found an agent that is on no list, and something
it read suggests the agent runs an AI model. The signs it goes by are these:
it was found in agent code, in a tracing system or on a tool server, or it
lists a tool or a model. With an inventory: the agent is not in your
inventory. With no inventory and no Inflect tenant: nothing can be on a list,
so everything the scan found gets this finding or the next one,
`UNREGISTERED_IDENTITY`.

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
agent in your inventory. It also closes when a later scan that read
everything in full shows no sign of a model for it: it is then an
unregistered identity (below), and that finding takes this one's place. A
scan that did not read everything closes nothing, because the sign may be in
the part it did not read.

**Who usually owns it.** The team that looks after the system the agent was
found in (identity, cloud platform, or the development team for agent code),
together with whoever keeps your list of agents.

## `UNREGISTERED_IDENTITY`

**What it means.** The scan found an automated account that is on no list,
and nothing it read suggests the account runs an AI model. A build workflow
that holds a key looks like this. So does a service account, or an
application registered in a directory. The scanner reports it as an
unregistered automated identity, not as an agent.

**The scan cannot show that it runs no model.** It only saw no sign of one.
The signs it looks for are listed under `SHADOW_AGENT` above. The name of a
key is not one of them: a secret called after an AI provider is a guess about
what uses it.

**Why it matters.** An automated account with a key and no owner on record is
a risk whether or not a model is behind it. And if it is an agent after all,
nobody has said so.

**What to do.**

1. Find out what it is. The system's own administration shows who created
   it.
2. If it is an agent: add it to your inventory. It is then treated as an
   agent, given a level, and held to the bar.
3. If it is ordinary automation: make sure it has an owner on record in the
   place your organisation keeps such things. Adding it to the scanner's
   inventory would make the scanner treat it as an agent, so do not.
4. If nobody claims it: disable it in the system it lives in, wait, and then
   remove it. The scanner does not do this for you.

**What it is not held to.** It is given a level, which you can see in the
table and the spreadsheet, and it is not held to the bar. So it has no
`HARNESS_SHORTFALL` finding.

**When it closes.** When a later scan that read everything in full finds it
in your inventory. It also closes when a later scan sees a sign of a model:
the account is then a shadow agent, and a `SHADOW_AGENT` finding takes this
one's place. A sign counts on any scan, also one that did not read everything.

**Who usually owns it.** The team that looks after the system the account
was found in: identity, the cloud platform, or the team that owns the build
pipeline.

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
finding**, except an unregistered automated identity, which is held to no
bar. That is a limit of what the scan could read, not a failure of each
agent. [read-the-report.md](read-the-report.md#what-a-scan-on-its-own-can-show)
explains why.

**Why it matters.** Taken together, these findings are a fair statement: for
these agents, nobody has shown that the expected controls are in place.

**What to do.** Do not work through them one by one. Use them to set
priorities:

1. In `agents.csv`, look at the columns for the individual checks. Start with
   the cells that say `NOT_MET`: a system saw that control fail. Those are
   real, whatever else the scan could not see. A cell that says
   `NOT_MET_DECLARED` is a different thing. It appears only on
   `H1.axes_declared` and `H1.tier_scored_fresh`, and means that your
   inventory leaves out the descriptions or the risk rating for that agent,
   or that the rating is not dated within the 365 days before the scan. No
   system saw anything fail. The fix for those is to complete the inventory.

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

**When it closes.** When a later scan shows the agent at its bar. Also when a
later scan that read everything in full shows it to be an unregistered
identity, which is held to no bar.

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

## `SPENDING_AGENT_UNDECLARED`

**What it means.** An agent on your list (in your inventory, or in an Inflect
register) has code that calls a payment client: a library that lets a
program pay for something on its own. Today the scanner knows the payer side
of the x402 payment protocol: the packages `x402-fetch`, `x402-axios`,
`@x402/fetch` and `@x402/axios` for JavaScript and TypeScript, and `x402` for
Python. The finding names each place in the code, as a file and a line. It
never names an amount, a wallet or a key: the scanner does not read them.

**A scan on its own cannot see a spending limit.** Where the agent has one,
it is kept in an Inflect register, which the scanner does not read, and an
inventory has no place for one. So a scan on its own raises this finding for
every listed agent whose code can pay, and the finding says that it saw no
limit, not that there is none. An Inflect tenant closes it when the agent has
a limit that a second person has reviewed.

**Why it matters.** An agent that can pay can spend money nobody approved.
Somebody should have said how much it may spend, where, and until when, and
somebody else should have checked that.

**What to do.**

1. Ask the agent's owner whether the agent is meant to pay at all.
2. If it is: write down the limit (how much per payment and per period,
   which sellers, until when) and have a second person review it. In an
   Inflect tenant that is the agent's spending authority.
3. If it is not: remove the payment client from the agent's code.

**When it closes.** A later scan that no longer sees the payment client does
not close it. The scanner reads one file at a time and cannot follow code
that wraps the payment client somewhere else, so not seeing it is no proof
that the agent cannot pay. Close it yourself once you have dealt with it. In
an Inflect tenant it closes when a reviewed spending limit is on record, and
a later scan opens it again only if it sees the payment client again.

An agent found in code that is on no list gets `SHADOW_AGENT` and not this
finding: put it on the list first. The scan's results still show, for every
agent, whether its code calls a payment client.

**Who usually owns it.** The owner of the agent, with whoever approves
spending in your organisation.

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

## Integration findings

These come from the **integrations scanner**, only when it is set up
([what-it-reads.md](what-it-reads.md#microsoft-entra-id-for-integrations)).
They are about the applications your directory has granted access to, not
about agents, and they are listed in a section of their own in the results
page and in `integration-findings.csv`.

Two rules decide when they can be raised:

- **Something seen counts; something missing counts only after a full read.**
  A grant the scan saw is reported even if the read stopped early. "This
  application holds no high-privilege grant", "no grant at all" and "has not
  signed in" are concluded only when that part was read in full. Otherwise
  the results list the question as **not concluded**, with the reason, and
  never as clean.
- **A permission the scanner does not know is not called high, and not
  called low.** Which Microsoft Graph permissions are high-privilege is a
  written list of about 130 names. Any permission not on it, and every
  permission on another company's API, is listed in the results as "not known"
  for a person to judge.

<!-- guide:integration-findings -->
| Code | Severity | Can a scan on its own raise it? |
|---|---|---|
| `INTEGRATION_HIGH_PRIVILEGE_GRANT` | HIGH | Yes |
| `INTEGRATION_UNVERIFIED_PUBLISHER` | HIGH | Yes |
| `INTEGRATION_NO_OWNER` | MEDIUM | Yes |
| `INTEGRATION_UNUSED` | LOW | Yes, only when sign-in activity is read |
| `INTEGRATION_EMPTY_INVENTORY` | HIGH | Yes |
<!-- /guide:integration-findings -->

## `INTEGRATION_HIGH_PRIVILEGE_GRANT`

**What it means.** An application holds a permission that reaches your
directory (its groups, applications, roles or policies), your mail, your files
or SharePoint sites, your chats and Teams channel messages, or your calendars,
or that can change something. Reading people's profiles (`User.Read.All`) or
the directory's sign-in and audit logs (`AuditLog.Read.All`) does not count:
those are profiles and logs, not content. That line was decided on 13
November 2026 and is written into the scanner's list. The finding lists the
permissions, and says
whether each was granted on behalf of people ("delegated") or to the
application itself.

**Why it matters.** A permission like this is used without anybody signing in
each time. Whoever controls the application can read or change what the
permission names, for as long as the grant stands.

**What to do.**

1. Ask the application's owner, or the team that uses it, whether it still
   needs each permission listed.
2. Remove the permissions it does not need: in the Entra admin centre,
   Enterprise applications, the application, Permissions.
3. Keep the ones it needs, and record why. The scanner will keep reporting
   them: holding such a grant is the finding, not a mistake.

**When it closes.** When a later scan reads the application's grants in full
and none of them is high-privilege.

**Who usually owns it.** The owner of the application, with whoever approves
access to the directory.

## `INTEGRATION_UNVERIFIED_PUBLISHER`

**What it means.** An application from outside your organisation holds a
high-privilege grant, and your directory records no verified publisher for
it. A verified publisher is a company Microsoft has checked; without one,
nobody has shown who is behind the application.

**Why it matters.** Granting broad access to an application from an unknown
publisher is a common way in for attackers: a convincing name and a consent
screen are all it takes.

**What to do.**

1. Find out who publishes it and why it was granted access.
2. If nobody can vouch for it, remove its access, or disable the application
   in Enterprise applications.
3. If it is wanted, record who approved it and why.

If the scan could not tell whether the publisher is verified, it does not
raise this finding. It lists the question as not concluded.

**When it closes.** When a later scan sees a verified publisher, or no
high-privilege grant, for the application.

**Who usually owns it.** Whoever approves third-party applications for your
organisation.

## `INTEGRATION_NO_OWNER`

**What it means.** An application holds access granted in your directory,
and the directory records nobody as its owner.

**Why it matters.** With no owner, nobody is on record to say whether the
application still needs its access, or to answer for it when something goes
wrong.

**What to do.** Assign an owner in the Entra admin centre (the application's
Owners page). For an application your organisation registered, the owners of
its registration count too.

**When it closes.** When a later scan sees an owner for the application.

**Who usually owns it.** Whoever approves access to the directory.

## `INTEGRATION_UNUSED`

**What it means.** An application has not signed in for longer than the
window you set (90 days unless your configuration says otherwise), or has
never signed in that the directory recorded.

**You will see this only if sign-in activity is read.** That needs the extra
permission `AuditLog.Read.All` and a licence that records sign-ins. Without
them, the results say that "unused" was not concluded, and why. Not seeing
this finding then says nothing about use.

**Why it matters.** An application nobody uses still holds whatever it was
granted. It is access with no purpose, kept open.

**What to do.** Ask its owner whether it is still needed. If not, remove its
permissions or delete it from Enterprise applications.

**When it closes.** When a later scan, reading sign-in activity in full,
sees a sign-in within the window.

**Who usually owns it.** The owner of the application.

## `INTEGRATION_EMPTY_INVENTORY`

**What it means.** The integrations scan read your directory in full and
found no application at all, other than Microsoft's own.

**Why it matters.** It is almost never true. A directory in use holds
applications. An empty answer is what a read of the wrong directory, or one
made with permissions that see only part of it, looks like. The report shows
it as a finding and never as a clean result.

**What to do.** Check the directory id in the configuration, and that the
application the scanner reads with holds both permissions and admin consent.
Run the check step again ([run-it.md](run-it.md#5-check)).

**When it closes.** When a later scan finds at least one application.

**Who usually owns it.** Whoever runs the scan.

## Where the detail is

- [../contract.md](../contract.md#findings): the exact rule for each kind,
  for a technical reader.
- [../contract.md](../contract.md#the-integrations-contract): the same for the
  integration findings.
- [read-the-report.md](read-the-report.md): how the findings appear in the
  report and the spreadsheet.
