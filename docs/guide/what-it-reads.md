# What the scanner reads, and the access to grant

The scanner can read twelve kinds of system. You choose which ones. For each
one you choose, your organisation creates **one read-only access**: a role, a
token or a key that can look and cannot change.

This page says, for each system, what the scanner looks at, what it never
asks for, which access to grant, and how much work granting it is.

Three things hold for every system:

- **It reads and does not write.** It has no way to create, change or delete
  anything in the system it reads.
- **It never asks for a secret value.** It reads that a key or password
  exists, what it is called, when it was made and when it expires. It never
  asks for the key or password itself.
- **It tells you when it could not read everything.** A system that was read
  only in part is shown as "Incomplete", with the reason. It is never shown as
  complete, and never left out.

## The access to grant, at a glance

"Code in the report" is the short name the results use for that kind of
system. "Where the credential goes" is the name of the setting that holds the
token or key you create; the value itself goes in a file you keep, never into
the scanner's configuration. "Steps" counts the steps in that product's own
administration screens, as listed further down this page.

<!-- guide:access -->
| System | Code in the report | Read-only access to grant | Where the credential goes | Steps |
|---|---|---|---|---|
| Microsoft Entra ID | `entra-sp` | The Microsoft Graph application permission `Application.Read.All`, with admin consent | `ENTRA_CLIENT_SECRET` | 4 |
| Azure Key Vault | `vault` | The role Key Vault Reader on each vault you list. For a vault that uses access policies: List on secrets and List on certificates, and nothing else | `AZURE_CLIENT_SECRET` | 1 |
| Okta | `okta-app` | An API token made by a user who holds the Read-only Administrator role and no other | `OKTA_API_TOKEN` | 2 |
| GitHub Actions | `cicd` | A fine-grained personal access token (or a GitHub App installation) limited to the repositories you list, with Contents: Read-only and Secrets: Read-only | `GITHUB_READ_TOKEN` | 3 |
| Google Cloud | `gcp-sa` | The role Service Account Viewer on each project you list, held by a service account made for the scanner, and one JSON key for that account | `GCP_SCANNER_KEY_FILE` | 3 |
| LangSmith | `runtime` | A service key with the workspace Viewer role | `LANGSMITH_API_KEY` | 1 |
| MCP servers | `mcp` | For each server, a token that can list the server's tools and do nothing else. None if the server needs none | `MCP_<LABEL>_TOKEN` | 1 |
| Agent code in folders | `code` | Permission to read the folders. Nothing else | none | 1 |
| An Inflect tenant (optional) | `inflect-register` | An API key for the scanner with the scope `admin:harness_ingest`, plus `mcp:read` if the tenant's list of agents is read | `INFLECT_INGEST_KEY` | 1 |
| Microsoft Entra ID, for integrations | `entra-integrations` | The Microsoft Graph application permissions `Application.Read.All` and `Directory.Read.All`, with admin consent; `AuditLog.Read.All` as well only to read when each application last signed in | `ENTRA_INTEGRATIONS_CLIENT_SECRET` | 5 |
| Okta, for integrations | `okta-integrations` | An API token made by a user who holds the Read-only Administrator role and no other. It may be the token of the Okta row above | `OKTA_API_TOKEN` | 2 |
| GitHub, for integrations | `github-integrations` | A fine-grained personal access token made by an owner of the organisation, for the organisation, with the organisation permissions Administration: Read-only and Webhooks: Read-only | `GITHUB_INTEGRATIONS_TOKEN` | 4 |
<!-- /guide:access -->

An MCP server is a server that offers tools to AI agents. The Inflect row
applies only if your organisation uses an Inflect tenant. A scan needs none:
see [read-the-report.md](read-the-report.md#what-a-scan-on-its-own-can-show).

### How long does granting access take?

The steps themselves are few: between one and four screens for each system.
We have not timed them in a real organisation, so this guide gives no minutes.
In practice the waiting is in your own approval process:

- **Microsoft Entra ID** needs an administrator who is allowed to give "admin
  consent".
- **Okta** needs an administrator who can assign the Read-only Administrator
  role to a new user.
- **Google Cloud** and **Azure Key Vault** need somebody who can grant a role
  on each project or vault.
- **GitHub** needs somebody who can create a token for the repositories, and,
  if your GitHub organisation requires it, an owner who approves the token.

Ask for these early. The scan itself takes little time once the access exists.

A ready-to-send request for each administrator, with the same access and the
same "do not grant" list, is in the engagement kit:
[../engagement/access-request-templates.md](../engagement/access-request-templates.md).

## System by system

Each section says what is looked at, what is never asked for, and what must
not be granted. The lists of what must not be granted matter: the scanner has
no use for more, and should not be handed more.

### Microsoft Entra ID

**Looks at.** The applications registered in your directory and their service
principals (the accounts those applications sign in as), and managed
identities (accounts that Azure creates for its own services). For each: its id, whether it is enabled, the ids and dates of its
passwords and certificates, and the id of its owner.

**Never asks for.** The list of people in your directory: an owner is kept as
an id only, with no name and no e-mail address. Nothing that creates a
password or changes an application.

**How to grant it.**

1. Entra admin centre: App registrations, New registration.
2. API permissions: Add a permission, Microsoft Graph, Application
   permissions, `Application.Read.All`.
3. Grant admin consent.
4. Certificates and secrets: New client secret.

**Do not grant.** Any permission with "ReadWrite" in its name. Any
`Directory.` permission, unless the same application also reads for the
integrations scanner (below), which needs `Directory.Read.All`. Any delegated
permission (one that acts on behalf of a signed-in person). Any directory
role.

### Azure Key Vault

**Looks at.** The names, tags and dates of the secrets and certificates in
each vault you list, and whether each is enabled.

**Never asks for.** The value of any secret. Keys are not read at all.

**Before you start.** Key Vault access is given to an application registered
in Microsoft Entra ID. If you also scan Entra ID, use the application you
registered there. If you do not, register one first (Entra admin centre: App
registrations, New registration; then Certificates and secrets, New client
secret). It needs no API permission for Key Vault. Its client secret is the
value that goes in `AZURE_CLIENT_SECRET`.

**How to grant it.**

1. In each vault: Access control (IAM), Add role assignment, Key Vault Reader,
   given to the application you registered for the scanner.

**Do not grant.** Key Vault Secrets User. Key Vault Administrator. "Get" on
secrets. Each of these can read or change secret values.

### Okta

**Looks at.** Service apps (applications that sign in as themselves, with no
person). API tokens: the id, which user each belongs to, and its dates.

**Never asks for.** An application's secret by itself: Okta has a separate
request for that, and the scanner never makes it. The list of your users.
Okta does not return the value of an API token, and the scanner does not ask.

**One thing not yet confirmed.** The scanner asks Okta for its list of
applications whole, and keeps only each application's id, its type and the
owner field. Whether Okta puts an application's client secret into that list
for a Read-only Administrator has not been confirmed against a live Okta
organisation. If it does, the secret reaches the scanner's memory and is
dropped there: it is not kept, written or reported.

**How to grant it.**

1. Okta admin console: Security, Administrators. Give the Read-only
   Administrator role to a user made for the scanner.
2. Signed in as that user: Security, API, Tokens, Create token.

**Do not grant.** Super Administrator. Org Administrator. App Administrator.
API Access Management Administrator.

**A limit you should know.** According to Okta's documentation, a Read-only
Administrator can see only its own API tokens. So with this access the scan
sees every service app, but of API tokens only those of the scanner's own
user. Other people's API tokens are not seen, and the report does not say they
are absent. Seeing all of them would need a role that can also write, so this
guide does not ask for it: look at Security, API, Tokens by hand instead. This
limit comes from Okta's documentation and has not been confirmed against a
live Okta organisation.

### GitHub Actions

**Looks at.** In each repository you list: the workflow files on the default
branch, and the **names** of the repository's Actions secrets.

**Never asks for.** The value of a secret: GitHub does not return one, and no
secret is asked for by name. Any file outside the workflows folder. Workflow
runs and their logs.

**How to grant it.**

1. GitHub: Settings, Developer settings, Personal access tokens, Fine-grained
   tokens, Generate new token.
2. Repository access: Only select repositories.
3. Repository permissions: Contents: Read-only, and Secrets: Read-only.
   GitHub adds Metadata: Read-only by itself.

**Do not grant.** Any "Read and write" permission. Actions. Administration.
Workflows. A classic token with the `repo` scope.

### Google Cloud

**Looks at.** The service accounts in each project you list, and the id and
dates of each account's keys.

**Never asks for.** Key material: Google does not return it, and the scanner
cannot create a key. Access policies are not read. The scanner cannot act as
any account.

**How to grant it.**

1. Google Cloud console: IAM and admin, Service accounts, Create service
   account.
2. IAM: Grant access on each project, role Service Account Viewer.
3. On the new service account: Keys, Add key, JSON.

**Do not grant.** Service Account Admin. Service Account Key Admin. Service
Account User. Service Account Token Creator. Editor. Owner.

The key you download in step 3 is a file. It is given to the scanner as a
file, which is why the setting is called `GCP_SCANNER_KEY_FILE`.

### LangSmith

LangSmith is a product that records what AI agents do.

**Looks at.** The list of tracing projects (a project is where LangSmith
keeps the records of one agent or application), with **counts** of how often each
tool was called in a recent period. Optionally, the list of deployments.

**Never asks for.** Any single run, with what the agent was asked and what it
answered. Datasets.

**How to grant it.**

1. LangSmith: Settings, API keys, Create API key, Service key, role Viewer.

**Do not grant.** The Editor or Admin role. An administrator's personal
access token.

**A choice to leave off.** Listing deployments is off unless somebody turns it
on. LangSmith's list of deployments also carries the deployments' secrets.
The scanner throws them away and keeps only an id, but they do reach it. Leave
the option off unless you need deployments in the report.

### MCP servers

**Looks at.** For each server you list: the names of the tools it offers, and
whether each tool says it only reads. The scanner keeps a fingerprint of each
tool's description (a short code worked out from the text; if the text
changes, so does the code), not the description.

**Never asks for.** It never calls a tool. It asks only for the list.

**How to grant it.**

1. In the server's own administration, create a token that can list tools and
   nothing else. Some servers need no token.

**Do not grant.** Anything that lets the token call a tool.

### Agent code in folders

**Looks at.** Python, JavaScript and TypeScript files in the folders you list.
It recognises agents built with LangChain, LangGraph and the Claude Agent SDK.
It also recognises an agent written directly against Anthropic, OpenAI or
Azure OpenAI, Google Gemini or AWS Bedrock: a call to the AI model that hands
it tools. A call that hands the model no tools is not an agent, and is not
reported. For each agent it reports its tools, the AI model service it calls,
and the **names** of the keys it uses.

When part of an agent is set up somewhere the scanner cannot follow, such as
a tool list that another file builds, the agent is still reported, and the
report names the file and the line it could not follow. The same is done for
a call to an AI model whose settings it cannot see at all: it cannot tell
whether that call is an agent, so it names the place for a person to look at.

**Never does.** It never runs the code. It never follows a shortcut (a
symbolic link) to another place. It makes no network request for this kind of
system. If a key is
written directly in a file, the report gives the file and the line, never the
key.

**How to grant it.**

1. Give the scanner the folders as read-only. [run-it.md](run-it.md) shows
   how.

**Do not grant.** Permission to write to the folders.

### An Inflect tenant (optional)

Only if your organisation uses Inflect. The scanner can then read the
tenant's own list of registered agents, and can send the signed report to the
tenant. Both are off unless you set them up.

**How to grant it.**

1. On the tenant's API keys page, create a key for the scanner with the scope
   (a named permission that a key carries)
   `admin:harness_ingest`, and `mcp:read` if the list of agents is to be read.

**Do not grant.** Any other scope.

### Microsoft Entra ID, for integrations

This is the second scanner in the same program: the **integrations scanner**.
It asks a different question of the same directory. The agent scanner above
asks which non-human accounts exist; this one asks what the directory has
**granted to applications**, and whether anybody owns those grants. It runs
beside the agent scanner, or on its own when you configure no agent source;
then the results say that the agent scanner did not run, and nothing in them
is about agents. Its results are a report of their own,
`report.integrations.signed.json`, and a section of the results page.

**Looks at.** Each application that has an account in your directory (yours
and other companies'), except Microsoft's own: whether a verified publisher is
recorded for it, who owns it (by id), the permissions it was granted on behalf
of people and in its own right, and the ids and dates of its passwords and
certificates. If you choose, also the day each application last signed in.

**Never asks for.** Who consented to a grant: a grant made for named people is
counted, and nobody is named. The list of people in your directory, or their
own sign-ins. Nothing that grants, removes or changes a permission.

**How to grant it.**

1. Entra admin centre: App registrations, New registration (or use the
   application you registered for the agent scanner).
2. API permissions: Add a permission, Microsoft Graph, Application
   permissions, `Application.Read.All` and `Directory.Read.All`.
3. To see when each application last signed in, also `AuditLog.Read.All`.
   That record needs a Microsoft Entra ID P1 or P2 licence; without it, the
   scan says so and does not call any application unused.
4. Grant admin consent.
5. Certificates and secrets: New client secret.

**Do not grant.** Any permission with "ReadWrite" in its name. Any delegated
permission. Any directory role. `AuditLog.Read.All` unless you want the
sign-in dates.

### Okta, for integrations

The integrations scanner, asking the same question of an Okta organisation:
what it has granted to applications.

**Looks at.** Every application in your Okta organisation: its id, its name,
whether it is active and how people sign in to it. Okta's own apps, which
every organisation has (the Okta Admin Console, the Okta End-User Dashboard
and the Okta Browser Plugin), are left out, as Microsoft's own are for Entra;
the results say how many were left out. For each, the Okta
permissions (Okta calls them scopes, such as `okta.users.read`) that it has
been granted.

**Never asks for.** Who granted a permission. An application's secret. The
list of your users. Okta's System Log.

**What Okta cannot tell it.** Okta records no owner of an application, does
not mark an application as one whose publisher it has checked, and keeps when
an application was last used only in its System Log, which the scanner does
not read. So for Okta the scan does not conclude whether an application has no
owner, has a publisher nobody checked, or is unused, and the results say so
for each Okta application rather than calling it clean.

**How to grant it.**

1. Okta admin console: Security, Administrators. Give the Read-only
   Administrator role to a user made for the scanner (or use the one made for
   the Okta row above).
2. Signed in as that user: Security, API, Tokens, Create token.

**Do not grant.** Super Administrator. Org Administrator. App Administrator.
API Access Management Administrator.

### GitHub, for integrations

The integrations scanner, asking it of a GitHub organisation: which apps are
installed on it and what each may do, and where it sends its events.

**Looks at.** The GitHub Apps installed on the organisation: each app's name,
the permissions it holds and whether each can only read or can also change,
whether it reaches every repository or only some, and whether it is
suspended. The organisation's webhooks (addresses GitHub sends events to): for
each, **the name of the server only**, the events, whether it is active and
the day it was made.

**Never asks for.** A webhook's full address or its secret: an address can
carry a password in it, so the scanner keeps the server's name and nothing
else. Any repository's content. The organisation's audit log.

**What GitHub cannot tell it.** GitHub's list of installations names nobody
as an installation's owner, says nothing about whether the app's publisher was
checked, and does not say when the app was last used. So for GitHub, as for
Okta, the scan does not conclude those three, and says so. No finding is
raised about a webhook in this version: they are listed for you to look at.

**How to grant it.**

1. Signed in as an owner of the organisation: Settings, Developer settings,
   Personal access tokens, Fine-grained tokens, Generate new token.
2. Resource owner: the organisation. Repository access: public repositories
   (read-only); no repository is needed.
3. Organization permissions: Administration: Read-only, and Webhooks:
   Read-only.
4. If your organisation requires approval of such tokens, approve it in the
   organisation's settings.

**Do not grant.** Any "Read and write" permission. Any repository permission.
Any other organisation permission. A classic token: GitHub lets a classic
token list webhooks only with a scope that can also change them.

## What the scanner connects to

Every connection is encrypted (https, port 443). The scanner connects only to
the systems you chose, and looks up their addresses by name (DNS):

| System | Connects to |
|---|---|
| Microsoft Entra ID | `login.microsoftonline.com` and `graph.microsoft.com` |
| Azure Key Vault | `login.microsoftonline.com` and each vault's own address |
| Okta | Your Okta organisation's address |
| GitHub Actions | `api.github.com` |
| Microsoft Entra ID, for integrations | `login.microsoftonline.com` and `graph.microsoft.com` |
| Okta, for integrations | Your Okta organisation's address |
| GitHub, for integrations | `api.github.com` |
| Google Cloud | `oauth2.googleapis.com` and `iam.googleapis.com` |
| LangSmith | `api.smith.langchain.com` or `eu.api.smith.langchain.com`, or your own LangSmith server |
| MCP servers | Each server's address |
| Agent code in folders | Nothing |
| An Inflect tenant | The tenant's address |

One command prints the exact list for your own setup, so the people who look
after your firewall can be given it. It makes no connection itself. If you
scan only agent code in folders, it prints nothing: there is no address to
open.

```bash
scanent --network none -v "$PWD/scanent:/etc/scanent:ro" "$IMAGE" hosts --config /etc/scanent/config.json
```

([run-it.md](run-it.md) explains the first part of that line.)

## Where the detail is

- [../access.md](../access.md): the same access, one table per system, in the
  exact words `scanent init` prints.
- [../network-and-permissions.md](../network-and-permissions.md): every
  request the scanner can make, and for each system the requests it can never
  make.
- [../data-protection.md](../data-protection.md): the personal data that can
  appear in the results.
