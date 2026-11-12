# Data protection

What personal data scanent reads, what it writes and where, what it never
reads, and who decides. Then a data protection impact assessment (DPIA)
template with the facts of the scanner filled in and the facts of your estate
left for you.

This page describes the scanner as shipped. It is not legal advice, and it
does not decide whether a DPIA is required in your case: that is the
controller's assessment.

- [In short](#in-short)
- [Personal data the scanner reads](#personal-data-the-scanner-reads)
- [What it never requests or keeps](#what-it-never-requests-or-keeps)
- [What it writes, and where](#what-it-writes-and-where)
- [Transfers](#transfers)
- [Retention](#retention)
- [Roles](#roles)
- [DPIA template](#dpia-template)

## In short

scanent inventories **non-human identities**: service principals, service
accounts, API tokens, CI workflows, agents in code, MCP servers. People are
not its subject. Personal data enters in one way: an identity or an agent has
an **owner**, and the owner is a person. The scanner keeps an owner as the
identifier the source gave, never a profile.

It runs inside your estate and by default sends nothing anywhere: results are
files in a directory you choose.

## Personal data the scanner reads

| Source | Field read | What it is | Kept as |
|---|---|---|---|
| Microsoft Entra ID (`entra-sp`) | The owners of an app registration or service principal | The directory object id of the first owner that is a user | `owner.id`: an object id (a GUID). No name, no e-mail address |
| Okta (`okta-app`) | One property of a service app's profile (`owner` by default) | Whatever your estate wrote there to name the accountable person: an id, a login, or an e-mail address | `owner.id`: the value as written (no spaces, at most 256 characters) |
| Okta (`okta-app`) | An API token's `userId` | The Okta user id of the administrator who created the token | `owner.id`: an Okta user id |
| Azure Key Vault (`vault`) | One tag of a secret or certificate (`owner` by default) | Whatever your estate wrote there to name the accountable person | `owner.id`: the value as written |
| The tenant's register (`inflect-register`) | A registered agent's owner | The tenant's own user id for the owner | `owner.id`: a user id |
| The operator's inventory (a file you write) | `name`, `owner`, `purpose` per agent | What you declared. `owner` may be a person's name, a team, or an address | In `results.json`, `agents.csv` and `summary.html`, labelled as declared. Never in the signed report |
| GitHub Actions (`cicd`), Google Cloud (`gcp-sa`), LangSmith (`runtime`), MCP servers (`mcp`), code (`code`) | None | These sources yield no owner. A Google service account's e-mail address is read to tell the scanner's own account apart and is not reported | Nothing |

A user's object id or user id is a pseudonymous identifier: on its own it
names nobody, and with access to your directory it names one person. Treat
the outputs as personal data wherever an owner is present.

Whether a person's name or address is in the outputs is decided by what your
estate writes in the Okta profile property and the Key Vault tag, and by what
you write in the inventory. Writing an id or a team there keeps names out.

**Indirectly.** A service principal, a token or an agent may itself be named
after a person (`jane-test-token`). Whether such a name reaches the outputs
depends on the source:

- **Reported by the provider's id, so a display name is not carried:** Entra
  service principals and applications (object ids), Okta apps and API tokens
  (Okta ids), Google service accounts and their keys (numeric ids, with the
  project id), LangSmith deployments and projects (ids).
- **Reported as your estate wrote them, so a person's name in one is
  carried:**
  - Azure Key Vault: the name of each secret and certificate (in the
    credential's reference), and the value of the tag that names the
    principal a credential belongs to, which becomes that principal's id.
  - GitHub Actions: the repository's owner and name, each workflow file's
    name, and each secret's name. A secret's value is never read.
  - MCP servers: each server's URL as you configured it and each tool's
    name. A server's label is not reported; it is written to the log.
  - Code: a file's path, the variable an agent is assigned to, tool names,
    model names, and the host of a model or MCP endpoint written in code.

If people's names appear in secret names, workflow file names, repository
names, tool names or paths in your estate, they are in the report and in the
results files. The log holds labels and host names, not agent ids.


## What it never requests or keeps

Two different things, kept apart here. `docs/network-and-permissions.md` lists
every request the scanner makes.

**Never requested.** The scanner makes no request that returns any of these:

- A credential's value from a vault or an identity provider: a Key Vault
  secret's value, an Okta client secret, a GitHub secret's value, private key
  material. (One listing does return secret values, and is off by default:
  see LangSmith deployments, below.)
- User profiles: names, e-mail addresses, phone numbers, group memberships,
  sign-in logs, of anyone.
- Mail, files, chats, calendars.
- What an agent was asked or answered: prompts, completions, run inputs and
  outputs, traces' contents, tool call arguments and results.
- A call of any tool on an MCP server. Only its list of tools is asked for.

**Received or read, and dropped.** These reach the scanner's memory because
the answer or the file that holds what it needs also holds them. None is
written, logged or reported, and a report or an output file that held a
secret's shape would be refused whole:

- **The contents of source files.** The code source reads every source file
  under a root in full, up to 1 MiB each: comments, strings, and any secret or
  personal data written in them. It keeps the agent definitions it recognises.
  A key written in code is reported as the place it is written (file and
  line), never its value; a URL written in code is reported as its host.
- **LangSmith project descriptions and metadata.** The projects listing
  carries each project's description, free-form metadata and run tags. The
  scanner keeps a project's id and the tool names in its run statistics.
- **LangSmith deployment secrets, only with `readDeployments: true`.** The
  deployments listing carries each deployment's secrets, names and values.
  With the option on, the scanner receives them and keeps a deployment's id
  and tracing project. The option is off unless you set it; leave it off
  unless you need deployments in the report.
- **Okta app objects.** The apps listing is asked for whole, with no field
  selection. The scanner keeps an app's id, its type and the one profile
  property you name as the owner. Whether the listing carries an app's
  client secret for a Read-only Administrator has not been confirmed against
  a live Okta organisation; if it does, it is dropped with the page.
- **An MCP server's tool descriptions and instructions.** They arrive with the
  list of tools. Names and hashes are kept.
- **A Google service account's e-mail address**, read to tell the scanner's
  own account apart.
- **Entra password hints and display names.** Microsoft Graph returns each
  password credential's `hint` (the first characters of the secret) and
  free-text `displayName`s with the members the scanner selects. The scanner
  keeps each credential's id and dates.
- **The contents of GitHub workflow files.** Each workflow file on the
  default branch is read whole, as text, for its permissions and the secret
  names it refers to. Anything else written in it is dropped.

Special categories of data (health, beliefs, and so on) and data about
criminal convictions are not read.

## What it writes, and where

| Output | Where | Personal data in it |
|---|---|---|
| The signed report (`report.signed.json`, or stdout, or posted to a tenant) | Your output directory; a tenant only if you configure one | Owner ids, as above. No declared inventory fields |
| `results.json`, `agents.csv`, `summary.html` | Your output directory | Owner ids, and the inventory's declared `name`, `owner` and `purpose` |
| `findings.csv` | Your output directory | Agent ids and credential references. A finding names an agent or a credential by its id; for the sources listed under "Indirectly" above, that id holds names your estate chose (a secret's name, a workflow file, a path), and a person's name written there is carried |
| The log (stderr) | Wherever your platform sends a container's stderr | None by design: kinds, counts, scan ids, host names. No owner, no agent id (`docs/operations.md`) |
| A support bundle | Where you write it, if you run the command | None by default: every name and id is replaced by a token. With `--include-identifiers`: agent ids, the estate's name, the tenant's host and slug, configured hosts, labels, paths, and the text of each doctor check |

Files are written `0640` in directories `0750`, owned by the user the scanner
runs as. Nothing is written outside the output directory.

## Transfers

- **By default, none.** A configuration with no `inflect` block and no
  `inflect` output sends the results nowhere. Every example configuration is
  like this.
- **To the providers you already use.** The scanner calls the APIs of the
  sources you configure, with your credentials, to read. It sends them no data
  about your estate beyond the requests themselves.
- **To a tenant, only if you configure it.** With the `inflect` output, the
  signed report is posted to the origin you name. It then contains owner ids.
  Whether that is a transfer to a processor, and where that processor is, is a
  matter between you and whoever operates the tenant.
- **No telemetry.** The scanner reports nothing to its authors and checks for
  no update.

## Retention

The scanner keeps what you tell it to. With `retainRuns` set on the file
output, it keeps that many runs and removes older ones at the end of each
scan. Without it, nothing is ever removed, and retention is yours to apply to
the directory. A removed run is deleted from the file system; the scanner does
not overwrite the blocks.

Choose `retainRuns` from how long you need to compare runs (`scanent diff`
compares any two), not from a default. Logs follow your platform's retention.

## Roles

| Role | Who | For what |
|---|---|---|
| Controller | You: the organisation whose estate is scanned | You decide that the scan happens, which sources are read, where results go and how long they are kept |
| Processor | Whoever runs the scanner on your behalf, if that is not you (a service provider or an auditor) | Runs it on your instructions. Needs a data processing agreement with you that covers the outputs |
| Processor or separate controller | The operator of a tenant you post to, if you configure one | For the reports it receives. Set by your agreement with them |
| Not a party | The authors of scanent | They receive nothing from a scanner you run |

## DPIA template

Copy this section and fill in the right-hand column. The middle column is what
is true of the scanner; change it only where your deployment differs.

### 1. Description of the processing

| Question | True of the scanner | Your deployment |
|---|---|---|
| What is done? | A scheduled, read-only inventory of non-human identities and AI agents, with a per-agent control level and findings | |
| Why? (purpose) | To know which agents and service identities exist, who owns each, and whether the controls expected of them are in place | *(your stated purpose)* |
| Which sources? | Those you configure, of: Entra ID, Okta, Azure Key Vault, GitHub Actions, Google Cloud IAM, LangSmith, MCP servers, code repositories, a tenant's register | |
| How often? | `schedule.everyHours` in the configuration | |
| Who runs it, where? | A container in your estate | *(team, cluster or host)* |
| Who has access to the outputs? | Whoever can read the output directory | *(roles)* |

### 2. Lawful basis and necessity

| Question | Notes | Your deployment |
|---|---|---|
| Lawful basis | For an organisation's own security governance this is commonly legitimate interests, or a legal obligation where a regulation requires an inventory of this kind. The choice is yours | |
| Is the personal data necessary? | An owner is needed to make an identity accountable. Only an identifier is kept, not a profile | |
| Could less be processed? | Yes: write ids or team names, not personal names, in the Okta owner property, the Key Vault owner tag and the inventory; leave out sources you do not need | |

### 3. Data categories and data subjects

| Category | Present? | Source | Your deployment |
|---|---|---|---|
| Directory object ids of owners | If `entra-sp` is configured | Entra ID | |
| Okta user ids of token creators | If `okta-app` is configured | Okta | |
| Owner values from an Okta profile property or a Key Vault tag | If your estate sets them | Okta, Key Vault | *(what do you write there?)* |
| Declared owner, name and purpose of agents | If you supply an inventory | Your inventory file | *(what do you write there?)* |
| Names, e-mail addresses, contact details | Not read, unless you write them in the three places above | | |
| Special categories; criminal convictions | Not read | | |
| Credential values, message content, prompts and outputs | Not read | | |

Data subjects: employees and contractors who own applications, tokens,
secrets or agents.

### 4. Recipients and transfers

| Recipient | When | Your deployment |
|---|---|---|
| Readers of the output directory | Always | |
| A tenant's operator | Only with the `inflect` output | *(who, where, under which agreement)* |
| A support contact | Only if you send a support bundle; names are replaced by default | |
| Transfers outside your jurisdiction | None by the scanner itself | |

### 5. Retention

| Item | True of the scanner | Your deployment |
|---|---|---|
| Runs on disk | Kept until `retainRuns` removes them, or for ever without it | *(value, and why)* |
| Logs | Your platform's retention | |
| Reports at a tenant | The tenant's retention | |

### 6. Security measures

| Measure | Where it is described |
|---|---|
| Read-only by construction; every request declared and hashed into each report | `docs/network-and-permissions.md` |
| Least-privilege grants per source | `docs/access.md` |
| No credential value read, logged or written; outputs refused on a secret's shape | `docs/threat-model.md`, boundaries 2 and 6 |
| Non-root container, read-only root file system, no capability, no shell | `docs/deployment.md` |
| Egress limited to named hosts | `docs/deployment.md`, `docs/threat-model.md`, boundary 5 |
| Output files private to the scanner's user | `docs/operations.md` |
| Signed releases, SBOM, provenance | `docs/verify-a-release.md` |
| Signed reports | `docs/contract.md` |

Your own measures: *(access control on the output directory, encryption at
rest, who holds the credentials and the signing key, how they are rotated)*.

### 7. Risks to data subjects

| Risk | Likelihood and severity before measures | Measures | Residual |
|---|---|---|---|
| The outputs are read by someone who should not, and show which person owns which privileged identity | | Directory permissions; `retainRuns`; ids in place of names | |
| An owner is held responsible for a finding that is wrong (a source was incomplete, a provider's answer was wrong) | | An incomplete source states no level and closes nothing; findings name the evidence | |
| The outputs are used to monitor individuals' work | | Purpose limitation in your policy; the scanner reads no activity of people | |
| A report posted to a tenant is disclosed there | | Only if configured; agreement with the tenant's operator | |
| *(yours)* | | | |

The scanner's own residual risks are in `docs/threat-model.md`, "Residual
risks".

### 8. Consultation and sign-off

| Item | Your deployment |
|---|---|
| Data protection officer consulted, date, advice | |
| Employee representatives consulted, where required | |
| Is prior consultation with the supervisory authority needed? | |
| Decision, by whom, date | |
| Review date | |
