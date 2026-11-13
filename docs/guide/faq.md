# Questions a security team asks

Short answers, each with the page that has the detail. "The scanner" is
scanent. "A system" is one of the things it reads: Microsoft Entra ID, Okta,
Azure Key Vault, Google Cloud, GitHub, LangSmith, an MCP server, or folders
of agent code.

## Does it write or change anything in our systems?

No. In the systems it reads, the scanner can only ask to read. The part of
the program that talks to a system has one operation, "get", and no way to
send a change.

Three things are not plain reads, and none of them changes anything:

- **Signing in.** For Microsoft and Google, the scanner first exchanges its
  credential for a short-lived token. That is how those systems work.
- **Asking an MCP server for its list of tools.** The scanner sends the three
  messages that open a session and ask for the list. It never calls a tool.
- **Sending the report to an Inflect tenant.** Only if you set that up. It is
  off otherwise.

Two things do change, and both are yours:

- Your administrators **create the read-only access**. That is a change you
  make, in your own systems, and can undo.
- The scanner's sign-ins and reads will normally show up in each system's own
  sign-in and audit records, like those of any other reader.

On your own computer, the scanner writes its results into one folder you
choose, and nowhere else.

Detail: [../network-and-permissions.md](../network-and-permissions.md) lists
every request it can make, and for each system the requests it can never
make.

## Can it read our passwords, keys or tokens?

It never asks a system for the value of one. It reads names and dates.

Three cases where a secret, or part of one, can pass through the scanner's
memory, without being kept, written or reported:

- **Agent code and GitHub workflow files.** The scanner reads these files in
  full. If somebody wrote a key directly into a file, the scanner reads past
  it. For agent code, the report then names the file and the line, never the
  key.
- **Microsoft Entra ID.** For each application password, Microsoft sends a
  hint (the first few characters of the password) and the label somebody
  gave it, together with the id and dates the scanner asks for. The scanner
  drops the hint and the label and keeps only the id and the dates.
- **LangSmith deployments**, only if somebody turns that option on. It is off
  unless you set it. See [what-it-reads.md](what-it-reads.md#langsmith).

As a last line of defence, the scanner checks its own results before it
writes them. If anything in them looks like a secret, it writes nothing and
says where the problem is.

The scanner does hold the **read-only credentials you give it**, while it
runs. See "What should we protect?" below.

Detail: [../data-protection.md](../data-protection.md#what-it-never-requests-or-keeps).

## Where does the data go?

Into one folder, on the computer where the scanner runs. You choose the
folder. That is all, unless you decide otherwise.

If the engagement team runs the scan for you, the folder is on their computer
or on one you lend them. Agree beforehand where it is, who may open it, and
when it is deleted.

Detail: [../data-protection.md](../data-protection.md#what-it-writes-and-where).

## What leaves our network?

- **Requests to the systems you chose**, each carrying the read-only
  credential for that system. If a system is a cloud service, such as
  Microsoft Entra ID, Okta, GitHub, Google Cloud or LangSmith, the request
  goes to that service. These are services your organisation already uses.
- **Name lookups (DNS)** for those systems' addresses.
- **Nothing else.** The scanner sends no usage data to its authors, does not
  check for updates, and does not send your results anywhere. A scan of agent
  code alone can run with the network switched off.

The one exception is the report sent to an Inflect tenant, and only if you
set that up.

You can print the complete list of addresses for your setup, for your
firewall team, before anything is scanned. The command is in
[what-it-reads.md](what-it-reads.md#what-the-scanner-connects-to).

Detail: [../network-and-permissions.md](../network-and-permissions.md).

## What is stored, and for how long?

In the settings folder:

- the settings file, which holds names and addresses but no secret;
- the file with the read-only credentials you filled in;
- the signing key.

In the results folder, for each scan: the report page, two spreadsheets, a
data file, the signed report and a list of checksums.

The scanner also prints a short log as it runs. It holds counts and the
addresses of systems. It does not hold agents' ids or owners.

**Nothing is deleted automatically** unless you ask for it. A setting,
`retainRuns`, keeps that many scans and removes older ones. Without it,
keeping and deleting is up to you. The files are created so that only the
user who ran the scan, and that user's group, can read them.

Detail: [../data-protection.md](../data-protection.md#retention) and
[../operations.md](../operations.md#the-files-of-a-run).

## What personal data is in the report?

The scanner is about accounts that are not people. Personal data comes in
through one door: an agent has an owner, and an owner is a person.

- From **Microsoft Entra ID** and **Okta's API tokens**, an owner is kept as
  that system's internal id for the user. No name and no e-mail address.
- From **an Okta application** and **Azure Key Vault**, an owner is whatever
  your organisation wrote in the owner field or tag. If that is a name or an
  e-mail address, it is in the report. If it is a team or an id, it is not.
- From **your inventory**, the owner is what you wrote. A team name keeps
  people out of it.
- **Names you chose.** The names of secrets, workflow files, repositories,
  tools and code files appear as they are. If one contains a person's name,
  so does the report.

The scanner does not read profiles, e-mail, files, chats, or what an agent
was asked and what it answered.

Treat the results as personal data wherever an owner appears. The technical
page has a filled-in template for a data protection impact assessment.

Detail: [../data-protection.md](../data-protection.md).

## Can we run it offline?

- **Agent code only:** yes, entirely. It reads folders and makes no network
  connection.
- **Any other system:** the scanner must reach that system, and only that
  system.
- **A site with no internet access:** the scanner can be carried in as a
  package and loaded without a download: the air-gapped bundle attached to
  each release, which is signed and checks itself before it loads.

Detail: [../deployment.md](../deployment.md#a-site-with-no-internet).

## How do we verify the image?

"The image" is the packaged scanner that Docker runs.

**Since 0.13.2** (the first release), the release process gives each
image a signature, a list of every component inside it, and a signed
statement of which source code it was built from. You check them with a free
tool called `cosign`. The commands are written down, and they were run
against 0.13.2 from outside the build system, including on a machine with no
network.

Detail: [../verify-a-release.md](../verify-a-release.md).

## How do we know it only does what it says?

- Every request the scanner can make is written down in one list inside the
  program. A fingerprint of that list is in every report. A scanner that
  could do more would have a different fingerprint.
- Automated tests run each reader against a stand-in for the system it reads,
  and fail if the reader makes a request that is not on the list.
- You can read the source code.

What has **not** been done: no outside firm has tested it, nobody outside the
project has reviewed the code, and it has not yet been run at a client. It
has been run once against a real organisation's systems: its maker's own.

Detail: [../threat-model.md](../threat-model.md#what-has-not-been-done).

## What should we protect?

Three things on the computer that runs the scanner:

- **The file with the read-only credentials.** Anybody who has it can read
  what the scanner can read.
- **The signing key.** Anybody who has it can sign a report that looks like
  one of yours.
- **The results.** They are a map of your agents and their keys, by name.

Run the scanner on a computer you trust, keep both folders private, and
remove the access when the work is done.

Detail: [../threat-model.md](../threat-model.md).

## Does it need administrator rights?

**On the computer that runs it:** no. It runs as an ordinary user, with every
special permission removed.

**In your systems:** it needs read-only roles only. Creating those roles
takes an administrator on your side, once.
[what-it-reads.md](what-it-reads.md) lists each one, and what must not be
granted.

The check step warns you when it can tell that a credential is able to change
things. It can tell for Microsoft Entra ID, for an older kind of GitHub
token, and for code folders. For the other systems it says "not observable"
and tells you what to confirm in that system's own administration.

## How much load does it put on our systems?

It reads each list once, page by page. It does not retry a request that
failed. If a system tells it to slow down, it stops reading that system and
reports it as incomplete, with the reason `RATE_LIMITED`. The whole scan is
given ten minutes unless the set-up changes it. Systems are read side by
side, and one that is not finished by then is marked incomplete, with the
reason `TIME_BOX`. Each system also has a size limit, and reaching it is
reported the same way.

The one real organisation scanned so far, the maker's own (four systems, 40
agents), took 14 seconds. A larger one has not been measured.

Detail: [../scanner.md](../scanner.md#limits-and-scale).

## How do we remove access afterwards?

The scanner leaves nothing behind in your systems, because it wrote nothing
there. Removing access means deleting what your administrators created:

| System | Remove |
|---|---|
| Microsoft Entra ID | The application you registered for the scanner. Its secret and its permission go with it |
| Azure Key Vault | The role assignment on each vault |
| Okta | The API token, and the user you made for the scanner |
| GitHub | The access token |
| Google Cloud | The service account you made for the scanner. Its key goes with it |
| LangSmith | The API key |
| MCP servers | The token, on each server |
| Agent code in folders | Nothing. The scanner only had the folders while it ran |
| An Inflect tenant | The API key |

Then, on the computer that ran the scanner:

- delete the settings folder. It holds the credentials file and the signing
  key;
- keep or delete the results folder, as your own rules say;
- remove the image:

```bash
docker image rm "$IMAGE"
```

A checklist for the whole clean-up, to tick and keep as a record, is in the
engagement kit:
[../engagement/data-handling.md](../engagement/data-handling.md#how-to-delete-everything-afterwards).

To confirm that access is gone, look in each system's own administration.
Running the check step again with the old credentials file would also show
each access being refused, but only do that before you delete the file.

## Is it open source?

No. It is licensed under the Business Source License 1.1, and the licensor is
Inflect Ltd. You can read the source code. Use in production is subject to
the licence's terms.

Detail: [../../LICENSE](../../LICENSE).
