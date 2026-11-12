# Access request templates

One ready-to-send request for each system the scanner can read. Copy the one
you need, fill in the parts in *[square brackets]*, and send it to the
system's administrator.

Every request asks for **read-only** access: access that can look and cannot
change anything. The role or permission named in each request is the exact one
the scanner needs. The technical reference is [Access the scanner needs](../access.md),
which is produced from the scanner's own set-up code.

Three rules hold for every request:

1. **Ask for the named access and nothing more.** Each template lists access
   that must not be granted. If an administrator offers a broader role
   "because it is easier", say no.
2. **The credential stays with the client.** A credential is the password,
   token or key file that the access produces. It is put into a file on the
   machine where the scanner runs, or into the client's secret store. It is
   never typed into the scanner, and it should not be sent by e-mail or chat.
3. **Remove the access when the engagement ends.** Each template says how.

A read-only credential can still read. Treat it as confidential.

---

## Microsoft Entra ID

> **Subject: Read-only access request for an agent inventory scan (Microsoft Entra ID)**
>
> We are running a read-only inventory of AI agents and the non-human accounts
> they use. For Microsoft Entra ID, please create the following.
>
> **What we need**
>
> - A new app registration, used only for this scan.
> - On it, the Microsoft Graph **application permission `Application.Read.All`**,
>   with admin consent granted.
> - One client secret for that app registration.
>
> **Steps** (Entra admin centre)
>
> 1. App registrations, New registration.
> 2. API permissions, Add a permission, Microsoft Graph, Application
>    permissions, `Application.Read.All`.
> 3. Grant admin consent.
> 4. Certificates and secrets, New client secret.
>
> **What this lets the scanner read**
>
> - App registrations and service principals.
> - For each: the identifiers and dates of its credentials, and who owns it.
>
> **What we are not asking for. Please do not grant these.**
>
> - Any permission whose name contains `ReadWrite`.
> - Any `Directory.*` permission.
> - Any delegated permission.
> - Any directory role.
>
> **What to give us:** the directory (tenant) id and the application (client)
> id. These are identifiers, not secrets. Please place the client secret
> itself with *[name of the person who holds credentials on the client side]*,
> not in a reply to this message.
>
> **When the scan ends** (planned for *[date]*): delete the client secret, then
> delete the app registration.

---

## Azure Key Vault

> **Subject: Read-only access request for an agent inventory scan (Azure Key Vault)**
>
> We are running a read-only inventory of AI agents and the credentials they
> use. For Azure Key Vault we read the **names, tags and dates** of secrets and
> certificates. We never read a secret's value.
>
> **What we need**
>
> - The built-in role **Key Vault Reader** on each of these vaults:
>   *[list of vaults]*, assigned to the scan's app registration.
> - For a vault that uses access policies instead of roles: the permissions
>   **List on secrets** and **List on certificates**, and nothing else.
> - One client secret for that app registration.
>
> **If no app registration exists for the scan yet** (it exists already if
> Microsoft Entra ID is also being scanned): create one first. Entra admin
> centre: App registrations, New registration; then Certificates and secrets,
> New client secret. It needs no API permission for Key Vault.
>
> **Steps:** on each vault, Access control (IAM), Add role assignment, Key
> Vault Reader, to the app registration's service principal.
>
> **What this lets the scanner read:** the names, tags and dates of secrets and
> certificates.
>
> **What we are not asking for. Please do not grant these.** Each of them
> reads or changes secret values.
>
> - Key Vault Secrets User.
> - Key Vault Administrator.
> - The "Get" permission on secrets.
>
> **What to give us:** the address of each vault, the directory (tenant) id and
> the application (client) id. Please place the client secret with *[name]*.
>
> **When the scan ends** (planned for *[date]*): remove the role assignment
> from each vault and delete the client secret.

---

## Okta

> **Subject: Read-only access request for an agent inventory scan (Okta)**
>
> We are running a read-only inventory of AI agents and the non-human accounts
> they use. For Okta, please create the following.
>
> **What we need**
>
> - A dedicated Okta user, used only for this scan, holding the
>   **Read-only Administrator** role and no other administrator role.
> - One API token created while signed in as that user.
>
> **Steps** (Okta admin console)
>
> 1. Security, Administrators: assign Read-only Administrator to the dedicated
>    user.
> 2. Signed in as that user: Security, API, Tokens, Create token.
>
> **What this lets the scanner read**
>
> - Service apps.
> - Information about API tokens (not the tokens themselves), as far as the
>   role shows it. See the limit below.
>
> **A limit you should know about.** According to Okta's documentation, a
> Read-only Administrator can see only the API tokens of its own user. So the
> scan will see every service app, but it may not see API tokens that belong
> to other users. The report does not say that those tokens are absent. We
> have not confirmed this behaviour against a live Okta organisation. To cover
> the gap, please also send us an export or a screenshot of Security, API,
> Tokens, or review that list with us.
>
> **What we are not asking for. Please do not grant these.** Each of them can
> make changes.
>
> - Super Administrator.
> - Org Administrator.
> - App Administrator.
> - API Access Management Administrator.
>
> **What to give us:** the address of the Okta organisation (for example
> `https://example.okta.com`). Please place the API token with *[name]*.
>
> **When the scan ends** (planned for *[date]*): revoke the API token, then
> deactivate the dedicated user.

---

## GitHub Actions

> **Subject: Read-only access request for an agent inventory scan (GitHub)**
>
> We are running a read-only inventory of AI agents. For GitHub we read the
> automation workflow files and the **names** of the secrets they use. We
> never read a secret's value.
>
> **What we need**
>
> - A **fine-grained personal access token** (or a GitHub App installation)
>   limited to these repositories: *[list of repositories]*.
> - Repository permissions: **Contents: Read-only** and **Secrets: Read-only**.
>   GitHub adds Metadata: Read-only by itself.
>
> **Steps** (GitHub)
>
> 1. Settings, Developer settings, Personal access tokens, Fine-grained tokens,
>    Generate new token.
> 2. Repository access: Only select repositories.
> 3. Repository permissions: Contents: Read-only, Secrets: Read-only.
>
> **What this lets the scanner read**
>
> - Workflow files on each repository's default branch.
> - The names of Actions secrets. Never a value.
>
> **What we are not asking for. Please do not grant these.**
>
> - Any "Read and write" permission.
> - The Actions, Administration or Workflows permissions.
> - A classic token with the `repo` scope.
>
> **What to give us:** the list of repositories as `owner/name`. Please place
> the token with *[name]*.
>
> **When the scan ends** (planned for *[date]*): delete the token, or remove
> the GitHub App installation.

---

## Google Cloud

> **Subject: Read-only access request for an agent inventory scan (Google Cloud)**
>
> We are running a read-only inventory of AI agents and the non-human accounts
> they use. For Google Cloud we read service accounts and information about
> the keys they hold. We never read key material.
>
> **What we need**
>
> - A dedicated service account, used only for this scan.
> - The role **Service Account Viewer** (`roles/iam.serviceAccountViewer`) for
>   that account on each of these projects: *[list of projects]*.
> - One JSON key for that account.
>
> **Steps** (Google Cloud console)
>
> 1. IAM and admin, Service accounts, Create service account.
> 2. IAM: Grant access on each project, role Service Account Viewer.
> 3. The service account: Keys, Add key, JSON.
>
> **What this lets the scanner read**
>
> - Service accounts.
> - Information about the keys users created for them: identifiers and dates.
>
> **What we are not asking for. Please do not grant these.**
>
> - `roles/iam.serviceAccountAdmin`
> - `roles/iam.serviceAccountKeyAdmin`
> - `roles/iam.serviceAccountUser`
> - `roles/iam.serviceAccountTokenCreator`
> - Editor
> - Owner
>
> **What to give us:** the list of project ids. Please place the JSON key file
> with *[name]*. It is given to the scanner as a file.
>
> **When the scan ends** (planned for *[date]*): delete the key, then delete
> the service account.

---

## LangSmith

> **Subject: Read-only access request for an agent inventory scan (LangSmith)**
>
> We are running a read-only inventory of AI agents. For LangSmith we read the
> list of tracing projects and summary figures about which tools they call. We
> do not read what any agent was asked or what it answered.
>
> **What we need**
>
> - A **service key** holding the workspace **Viewer** role.
>
> **Steps** (LangSmith): Settings, API keys, Create API key, Service key, role
> Viewer.
>
> **What this lets the scanner read**
>
> - Tracing projects and their summary tool statistics.
> - Deployments, only if we switch that option on. It is off unless agreed
>   with you: LangSmith's list of deployments includes each deployment's
>   secrets, which the scanner receives and discards. We recommend leaving it
>   off.
>
> **What we are not asking for. Please do not grant these.**
>
> - The Editor or Admin role.
> - A personal access token of an administrator.
>
> **What to give us:** whether you use LangSmith's US or EU service, or the
> address of your own installation. Please place the service key with
> *[name]*.
>
> **When the scan ends** (planned for *[date]*): delete the service key.

---

## MCP servers

MCP (Model Context Protocol) servers offer tools to agents. The scanner asks
each server for its list of tools and calls none of them.

> **Subject: Read-only access request for an agent inventory scan (MCP servers)**
>
> We are running a read-only inventory of AI agents. For each MCP server
> below we ask the server for its list of tools. We never call a tool.
>
> Servers: *[list of server addresses]*
>
> **What we need, per server**
>
> - A token that can list the server's tools and nothing else.
> - If the server needs no token to list tools, we need nothing.
>
> **Where it is created:** in the server's own administration.
>
> **What this lets the scanner read:** each tool's name, and whether the
> server marks it as a tool that only reads. Each tool's definition is kept
> only as a fingerprint (a hash), not as text.
>
> **What we are not asking for. Please do not grant this.**
>
> - Any permission that lets the token call a tool.
>
> **What to give us:** the address of each server. Please place each token
> with *[name]*.
>
> **When the scan ends** (planned for *[date]*): revoke each token.

---

## Source code

> **Subject: Read-only access request for an agent inventory scan (source code)**
>
> We are running a read-only inventory of AI agents. For source code, the
> scanner reads Python, JavaScript and TypeScript files in the folders below
> and looks for agent definitions. It reads the files as text. It never runs
> them.
>
> Folders: *[list of folders or repositories]*
>
> **What we need**
>
> - A copy or checkout of each folder on the machine where the scanner runs.
> - Read access to those folders for the user the scanner runs as.
>
> **What we are not asking for. Please do not grant this.**
>
> - Write access. Please make the folders available read-only.
>
> No credential is involved.
>
> **When the scan ends** (planned for *[date]*): remove the copies.

---

## An Inflect tenant (optional)

Only if the client has an Inflect tenant and has agreed that results are sent
to it, or that its register of agents is read.

> **Subject: API key request for an agent inventory scan (Inflect tenant)**
>
> **What we need**
>
> - An API key bound to the scanner's own agent entry, with the scope
>   `admin:harness_ingest`.
> - Also the scope `mcp:read`, only if the scan is to read the tenant's
>   register of agents.
>
> **Where it is created:** the tenant's API keys page.
>
> **What this allows:** sending the signed scan report to the tenant and, with
> `mcp:read`, reading the tenant's register of agents through one tool.
>
> **What we are not asking for. Please do not grant this.**
>
> - Any other scope.
>
> **When the scan ends** (planned for *[date]*): revoke the API key. If the
> scanner's public signing key was registered with the tenant, remove it.

---

## After the access is created

Before the first scan, the scanner's own check confirms that each credential
works and each system can be reached. It reads only. Where a system lets it
see that a credential has more than read access, it warns. For most systems
it cannot see that, and it says so. The administrator should confirm the
grant by eye against the request above.
