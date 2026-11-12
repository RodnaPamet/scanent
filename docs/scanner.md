# The scanner

`@scanent/scanner` runs inside an estate, reads that estate's sources
**read-only**, builds an `inflect-agent-harness/3` report, signs it with an
Ed25519 key, and either prints it (`scan --dry-run`) or posts it unchanged to
an Inflect tenant's ingest. The report's schema, the ladder its verdicts are
scored on and the signature rule are `@scanent/contract`
(`packages/contract/src/harness-contract.ts` is the specification of record).
The ingest accepts `/2` and `/3`; `/3` adds the `gcp-sa` source kind. `/1` is
retired.

This document was carried over from the scanner's README in the repository it
was extracted from (see [EXTRACTION.md](EXTRACTION.md)) and rewritten to this
repository's paths. "The owner" in it is Inflect Ltd., the scanner's owner and
licensor; "the register" and "the ingest" are an Inflect tenant's agent
register and its report endpoint; a "DPIA condition" is a condition of
Inflect's data-protection impact assessment of the scanner.

## Sources

One interface (`packages/scanner/src/source.ts`), one adapter per product. A source that cannot
be read is reported `INCOMPLETE` with the contract's reason, never left out.

| Kind | Product | What it reads | Requests |
|---|---|---|---|
| `entra-sp` | Entra | Service principals of applications registered in the directory, and managed identities, with the credentials on each principal and its application registration, by reference, and their owners. Microsoft's own applications and disabled principals never; third-party applications only when the estate opts in | `POST` the client-credentials token exchange to `login.microsoftonline.com` for the Graph audience, then `GET /v1.0/applications`, `GET /v1.0/servicePrincipals` on `graph.microsoft.com` |
| `mcp` | MCP servers | Each configured server's tools, by name, with a hash of each definition, the server's `readOnlyHint`, and whether the estate's pin matches the live listing. Reported against the agents the configuration lists for the server, and in place of a `code` agent's `<key>:*` placeholder for the same URL | `POST` to each configured endpoint: `initialize`, `notifications/initialized`, `tools/list`. Never `tools/call` |
| `inflect-register` | The scanner's own tenant | Each live registered agent: its owner, its own API keys by reference, and the verdicts the register can evidence; and each principal a person confirmed as an agent, linked to it. The only source that links to the register | `POST` to the ingest host's `/api/mcp`: `initialize`, `notifications/initialized`, and one `tools/call` of `get_harness_register` |
| `okta-app` | Okta | Service apps (OAuth clients with `application_type: service`) and API tokens, with their owners: an app's `profile.owner`, a token's `userId`. Every token is reported except the scanner's own, identified by id from `/api-tokens/current` | `GET /api/v1/apps`, `GET /api/v1/api-tokens/current`, `GET /api/v1/api-tokens` |
| `vault` | Azure Key Vault | Secrets and certificates tagged with the principal they belong to (`inflect-principal`), with an `owner` tag | `POST` the client-credentials token exchange to `login.microsoftonline.com`, then `GET /secrets`, `GET /certificates` |
| `runtime` | LangSmith | Tracing projects that called a tool in a bounded window, and deployments when the estate opts in, with each one's tools and their call counts. Aggregates only: no run is ever fetched | `GET /api/v1/sessions`; with `readDeployments`, `GET /v2/deployments` (`/api-host/v2/deployments` self-hosted) |
| `cicd` | GitHub Actions | Each workflow file on each configured repository's default branch that holds a secret, whose run token may write, or that reaches secrets dynamically; its secrets and run token by reference. The repository's Actions secrets by name, and each one no workflow references, as unbound | `GET /repos/{owner}/{repo}`, `GET /repos/{owner}/{repo}/contents/.github/workflows`, `GET …/contents/.github/workflows/{file}`, `GET /repos/{owner}/{repo}/actions/secrets` on `api.github.com` |
| `gcp-sa` | Google Cloud IAM | Each enabled service account in each configured project, by its numeric id, with its enabled user-managed keys by reference. Never its e-mail address, display name or description; never the scanner's own account | `POST` the JWT-bearer token exchange to `oauth2.googleapis.com`, then `GET /v1/projects/{project}/serviceAccounts` and `GET /v1/projects/{project}/serviceAccounts/{account}/keys?keyTypes=USER_MANAGED` on `iam.googleapis.com` |
| `code` | LangChain and LangGraph, the Claude Agent SDK | Agent definitions in the Python, JavaScript and TypeScript files under the configured roots: each agent's tools, the model endpoints it calls and the credentials those reference, by reference; for an Agent SDK agent, the options that fail a ladder criterion | None. Local reads only (`lstat`, `readdir`, `readFile`) |

### Entra

Which service principals are agents is the owner's decision of 2026-10-19:
an `Application` principal whose application is registered in this
directory (`appOwnerOrganizationId` is the configured `directoryId`), and every
`ManagedIdentity`. A third-party application's principal is reported only with
`"includeThirdPartyApplications": true`, and Microsoft's first-party
applications never are. A disabled principal is counted in `rows` and reported
as nothing.

Each is `entra:sp:<objectId>`. Its credentials are the password and certificate
credentials on its application registration and on the principal itself,
referenced as `entra://<directoryId>/applications/<appId>/password/<keyId>` (or
`…/certificate/…`, or `…/servicePrincipals/<id>/…`), with their age and expiry.
A certificate whose `usage` is `Sign`, such as a SAML signing certificate, is not
a credential the principal signs in with, and is left out. Its owner is the
first user, by object id, among the registration's owners, else the principal's.
`H2.credential_bound` is reported met when it holds a credential of its own or is
a managed identity. The grant kind is not reported: whether a credential acts
for a person depends on the permissions granted to it, which the source does not
read, so every credential's `grant` is `unknown`.

A credential on an application registration that has no service principal in
the directory signs in as nothing there. It is reported in `/2`'s
`unboundCredentials[]`, and only after both listings were read in full.

Graph returns each password credential's `hint`, the first characters of the
secret, and free-text display names, with the members the source asks for.
Neither is read; both are dropped with the page, and the tests hold a marker in
each out of the report and the log.

### MCP

Each configured server is asked what it serves and nothing else: `initialize`,
the one-way `notifications/initialized` the protocol requires, then
`tools/list`, paged by cursor (DPIA condition 1, as amended by owner decision 5).
The wire the source holds has two functions, `open` and `listTools`,
and no method parameter, so it cannot spell `tools/call`. A JSON body and a
Server-Sent Events stream are both read, under the byte cap, and a stream is
cancelled as soon as the answer arrives.

A tool is reported with:
- its name, by digest when it is not an identifier;
- the server's configured URL;
- `readOnlyHint` as the server's annotations declare it, else `null`, which the
  contract counts as a write;
- `manifestHash`, SHA-256 over the canonical JSON of the definition as served.
  The definition's text never leaves the source; the hash stands for it.
- `pinned`, true only when the server's `pinnedManifestHash` equals the hash of
  its whole listing read live: SHA-256 over each tool's name and hash, in name
  order. The scanner logs each server's listing hash (`mcp server read`), which
  is the value to pin.

Neither answer names a caller, so a server's tools reach an agent two ways (owner
decision 2):
- the agents the configuration lists for the server, by `discoveredId`;
- a `<key>:*` placeholder another source reported at the same URL, which the
  `code` source does for a tool set its agent fetches at run time. The report
  builder replaces it with the server's tools and adds `mcp` to the agent's
  `discoveredVia`, but only for a server read in full. A partial read replaces
  nothing, and the placeholder stays, counting as a write.

A server may take a read token (owner decision 6): `readTokenEnv`, sent as a
bearer token with the three messages above and nothing else. For Inflect's own
`/api/mcp` it is an API key holding `mcp:read` and no other MCP scope. A
configured token missing from the environment leaves that server unread
(`AUTH_FAILED`), and the other servers are still read.

Each server is a host the customer names, so it is checked as the self-hosted
LangSmith is: at configuration, and again before every request, with an optional
`egressPrivateCidrAllowlist` per server. The source is complete only when every
server was read to the end of its listing.

### The register

The scanner's own tenant's register, read through the one MCP tool the scanner
may call (DPIA condition 2, as amended by owner decision 7):
`get_harness_register`, on the ingest host's `/api/mcp`. The scanner first
exchanges the ingest key at the same host's `/api/mcp/token` for a short-lived
token naming that one tool, and `/api/mcp` sees only that token, so the
key can be created with "Agent tool calls only through a short-lived,
tool-scoped token" set. The key needs `mcp:read` beside `admin:harness_ingest`,
and the scanner agent must be granted the tool (owner decision 3). The source takes no configuration field:
`{ "kind": "inflect-register" }`.

Per live registered agent (not deleted, not `RETIRED`, not a legacy placeholder),
it reports (owner decision 4):
- each principal a person confirmed as the agent, as that principal's own id
  (`entra:sp:<objectId>`), linked to the agent, so the Entra source's
  observation of it merges with this one. An agent with no confirmed principal
  is `inflect:agent:<id>`.
- its owner, an Inflect user id;
- its own live API keys, as
  `inflect://<host>/t/<slug>/api-keys/<id>`, bound to the agent and `app-only`;
- `H1.registered`, `H1.owner`, `H1.axes_declared`, `H1.tier_scored_fresh` (a
  scored tier whose newest assessment is not stale), `H2.tools_allowlisted`
  (deny-by-default grants) and `H2.policy_card`. `H2.credential_bound` and
  `H2.grant_kind_declared` are reported only when the agent has a key of its
  own, so the register's silence never outvotes another source that sees the
  credential;
- what Inflect's gate enforces on it: `H2.audience_tokens` when it holds
  a key that reaches `/api/mcp` (met only when every such key requires the
  exchange), `H3.manifests_pinned`, and — only when the whole read-only bound
  holds (the ceiling refuses propose and orchestrate, no propose or external
  grant, no profile, no run mounted a skill) — `H3.propose_not_commit`,
  `H3.prior_state_reads`, `H3.skills_declared` and `H3.delegation_narrows`.
  Short of the bound those four are unanswered, never "no";
- on the scanner's OWN agent only: `H3.payloads_guarded` (the scanner refuses to
  sign a report with a secret-shaped member, and the ingest refuses one again)
  and, when the configuration names an egress proxy, `H3.egress_enforced` from
  this scan's own proof (The egress proxy, below).

It is the only source whose `registeredAgentId` reaches the report. A register
larger than one read returns is read as far as it goes and reported `BYTE_CAP`.

Azure Key Vault is the only vault adapter and LangSmith the only runtime
adapter. The `vault` and `runtime` kinds and the `product` field keep the
interface generic for the next one.

### LangSmith

Two kinds of agent, each identified by LangSmith's own id:

| Agent | Id | Reported when |
|---|---|---|
| A tracing project | `langsmith:project:<id>` | it recorded at least one tool call in the window, and no listed deployment writes to it |
| A deployment (LangSmith Deployment) | `langsmith:deployment:<id>` | the estate opted in with `"readDeployments": true`; then always, since a deployment is an agent server by existence |

A project that only called a model is counted in `rows` and reported as nothing,
and an evaluation experiment is not listed. A deployment's tools are those its
tracing project recorded.

**Deployments are opt-in** (owner decision, 2026-10-19). LangSmith's
deployments listing carries each deployment's `secrets`, name and value, so by
default the scanner never requests it and reads projects only. An estate that
wants its deployments listed sets `"readDeployments": true`, and the scanner
then receives that listing, keeps each deployment's id and tracing project, and
drops the rest with the page.

**Tool usage is an aggregate.** The projects listing is asked for its stats over
the window (`windowDays`, 7 by default, at most 30), filtered to tool runs: the
count of tool calls, and the run facets that split it by tool name. Each tool is
reported with `server` set to the project its calls were traced in
(`langsmith://<host>/projects/<id>`), `manifestHash: null`, `pinned: false` and
`readOnlyHint: null`, because LangSmith records no definition, pin or hint. The
contract counts an undeclared hint as a write, so the ingest raises
`UNPINNED_WRITE_TOOL` for every agent that called a tool. The call counts are not
in the report: `inflect-agent-harness/2` has a member for them (`calls`, with
`windowDays`), which the source does not fill yet, and until then the log line
reports their total (`toolCalls`). A tool name that is not a plain identifier, such as a run name set
at call time, is reported as a digest (`tool-sha256:<16 hex>`).

**Completeness is proven.** The facets must account for every call the count
records, or the read is `PAGINATION_TORN`: a facet list cut short is never
reported as the whole. So is a page cut short, absent stats, and a project listed
twice across offsets. A rejected or expired key is `AUTH_FAILED`, a host that
cannot be reached `UNREACHABLE`, and a refusal from LangSmith's rate limiter
`RATE_LIMITED`. A window with no tool call and no deployment reports no agent,
and the ingest raises `EMPTY_SCAN` for a scan that found none.

**What is never kept.** Both listings return more than the source reads: a
deployment's `secrets` and source configuration, a project's description and
metadata, and facets over run tags and metadata. Only ids, a deployment's
tracing project, and a project's tool-call count and tool-name facets are read.

The endpoint paths are one table, `LANGSMITH_READ_PATHS` in
`packages/scanner/src/sources/langsmith.ts`. The paths and query parameters are in LangSmith's
published OpenAPI documents. The members of one run facet (`key`, `value`, `n`)
are not documented there, and a facet that does not read as a count stops the
read rather than being skipped. Before the first estate scans a real workspace,
one dry run confirms the outcome.

### GitHub Actions

Decision 10 puts CI/CD in the pilot. A workflow runs unattended, holds
credentials, and those credentials reach production, so it is an agent-shaped
principal. The source reads what each configured repository declares about its
workflows, with a fine-grained token holding **Contents: read** and **Secrets:
read** and nothing else. Secrets: read lists names; GitHub has no read of a
secret's value.

| Agent | Id | Reported when |
|---|---|---|
| A workflow file | `github:workflow:<owner>/<repo>/<file>` | it references a repository, organisation or environment secret; or any job's token may write (a `write` scope, `write-all`, or no `permissions:` at all, which takes a repository default the source does not read); or it reaches secrets dynamically |

A workflow that only reads and holds no secret is counted in `rows` and
reported as nothing.

**What a workflow holds,** by reference and never by value:

- its run token, `github-token://github.com/<owner>/<repo>/.github/workflows/<file>`:
  bound, app-only, minted for each job and expiring with it;
- an OIDC token, `github-oidc://…`, when a job may mint one (`id-token: write`
  or `write-all`): the identity a workflow federates into a cloud with;
- each secret it references, `github-secret://github.com/<owner>/<repo>/<NAME>`,
  aged from the listing's `updated_at`. A repository secret is readable by every
  workflow in the repository, so it is reported as not bound to this one. A
  secret the repository's listing does not hold (an organisation's or an
  environment's) is reported with its age unknown.

**What counts as a reference** is an expression only: the inside of a
`${{ … }}` span, or a whole `if:` value. A script that mentions `secrets.FOO` in
its text holds nothing. Names compare upper-case, as GitHub's do.

**Dynamic access** is a computed index (`secrets[matrix.key]`), the whole
context (`toJSON(secrets)`), or `secrets: inherit` on a call to a workflow in
another repository. Such a workflow is a principal whatever else it holds, its
`H2.credential_bound` is evidenced false, and no secret of that repository is
reported unbound. `secrets: inherit` on a call to a workflow in the same
repository hides nothing, because the callee's own file is read.

**Verdicts** come from the file:

- `H2.credential_bound` is false when the workflow holds a secret or reaches
  secrets dynamically. When its only credentials are the run's own, it is true,
  and so is `H2.grant_kind_declared`.
- `H2.tools_allowlisted` is true when every job's token scope is an explicit
  `permissions:` map, and false otherwise, naming the first job that is not.
  `read-all` and `write-all` are not allowlists.

**Unbound secrets.** A repository secret that no workflow file references is
reported in `unboundCredentials[]`, and the ingest raises `ORPHAN_CREDENTIAL`.
This happens only when every workflow file was read and parsed and none reaches
secrets dynamically: "referenced by no file I read" is evidence only when there
is no file the source could not read.

**Completeness.**

- A repository the token cannot see answers 404 at `GET /repos/{owner}/{repo}`,
  and the read is `UNREACHABLE`, never zero workflows. A 404 on the
  workflow directory, asked only after the repository answered, is zero
  workflows.
- A directory listing at GitHub's 1,000-entry cap, or a file GitHub serves
  without content (over 1 MB) or over 512 KiB decoded, is `BYTE_CAP`.
- A secrets listing whose `total_count` changes between pages, or does not match
  the secrets read, is `PAGINATION_TORN`.
- A file that is not one YAML document with a `jobs` mapping, or that declares
  a `permissions:` value other than `read-all`, `write-all` or a map of `read`,
  `write` and `none`, is `UNPARSEABLE`. The other files are still reported, and
  that repository reports no unbound secret.

The YAML is parsed by `js-yaml` under its safe core schema: no type construction,
at most 1,000 aliases, and 100 levels of nesting.

**Not read:** organisation and environment secret listings, CODEOWNERS (a
workflow's owner is reported `null`, which the ingest reads as unowned), and
GitHub Enterprise Server.

### Google Cloud service accounts

`/3`'s `gcp-sa` kind (owner decision 2026-10-19). A service account acts
as itself: a workload attached to it, or anyone holding one of its keys, calls
Google's APIs with its authority and no person in the loop. Every enabled
account in each configured project is reported:

| Agent | Id | Reported when |
|---|---|---|
| A service account | `gcp:sa:<uniqueId>` | it is enabled and is not the account the scanner authenticates as. The project's default accounts (Compute Engine's, App Engine's) are in the listing and are reported; Google-managed service agents are not in it |

**Its credentials are its user-managed keys,** each
`gcp-sa-key://<project>/<uniqueId>/<keyId>`:
- bound to the account, app-only;
- aged from `validAfterTime`;
- expiring when `validBeforeTime` is not Google's `9999` "never".

A disabled key authenticates nothing and is not reported. An account with no
user-managed key reports none, because its tokens are minted by Google for the
workload it is attached to and never leave Google. Google returns key metadata
only: there is no read of a private key after it was created.

**The scanner's own account** is identified by the `client_email` of the key it
signs with, the account Google authenticated it as, and is not reported. This is
the Okta source's rule for its own token.

**What is never kept.** The listing returns each account's e-mail address,
display name and description, any of which can name a person. A principal is
its numeric id, so none of them reaches the report, and a test holds a marker in
each out of the result.

**Authentication** is the OAuth 2.0 JWT-bearer grant (RFC 7523):
- The source signs a ten-minute RS256 assertion with the key, and exchanges it
  at `oauth2.googleapis.com/token`.
- That endpoint is a constant. The key file's own `token_uri` is never used: a
  key file is the one input that names a host, and it is not trusted to.
- The scope is `cloud-platform`, because the IAM API takes no read-only scope.
  What keeps the read read-only is the account's role,
  `roles/iam.serviceAccountViewer` (lists accounts and key metadata, changes
  neither), and the GET-only wire.

**Completeness.**
- A key file that does not parse, or cannot sign, is `AUTH_FAILED` before any
  request.
- A refused assertion or a project the account cannot read is `AUTH_FAILED`.
- An account with no usable id, an account listed twice, a key with no usable
  id, or a key listing that claims to be paged is `PAGINATION_TORN`.
- An empty project (Google omits the empty collection) is read in full with zero
  rows.

**Not read:** role bindings (`getIamPolicy` is a POST, and the wire has no verb
for it), an owner (an account carries none, so each is reported unowned), and
any project the configuration does not list.

### The `code` source

`packages/scanner/src/sources/langchain.ts` reads the roots it is given and recognises:

- LangChain's agent factories (`create_tool_calling_agent`, `create_react_agent`,
  `initialize_agent`, `createToolCallingAgent`, …) and the `AgentExecutor` that
  wraps one, reported once;
- LangGraph's prebuilt `create_react_agent` / `createReactAgent`, and a
  compiled `StateGraph` that has a `ToolNode` or binds tools to a model;
- their tools — `@tool` functions, `Tool(...)`, `tool()`,
  `DynamicStructuredTool`, prebuilt tool and toolkit classes, and an MCP
  client's servers (`MultiServerMCPClient`), each as `<server>:*`;
- their chat models (`ChatOpenAI`, `ChatAnthropic`, `init_chat_model`, a
  `provider:model` string, …) with the endpoint each calls;
- the credentials those take, as `env://NAME` or, for a value written into the
  code, `code://<label>/<path>#L<line>` — never the value;
- Claude Agent SDK agents: `query` from `@anthropic-ai/claude-agent-sdk`,
  and `query` or `ClaudeSDKClient` from `claude_agent_sdk`, with their options,
  plus a Python `ClaudeAgentOptions` that no such call in its file consumes.
  Each agent's tools are the built-ins `tools` turns on (every built-in when it
  is left out), less `disallowedTools`, plus each `mcpServers` entry as
  `<server>:*` and each `mcp__<server>__<tool>` that `allowedTools` approves on
  a server the options configure. Its model is Anthropic's endpoint, or
  `ANTHROPIC_BASE_URL` from its `env`, and its key is the `env` entry that
  names one or else `ANTHROPIC_API_KEY`.

Every name is resolved through the file's own imports: only what is imported
from a `langchain`, `langgraph` or Claude Agent SDK module counts, and a file
that names none of those modules is not parsed at all.

An Agent SDK agent's options also become verdicts, as the owner mapped them
(2026-10-29; `AGENT_SDK_OPTION_CRITERIA` in
`packages/contract/src/harness-findings.ts`). Each is NOT MET with the option's
`code://` locator as evidence:
- `bypassPermissions` fails `H3.propose_not_commit`;
- host settings loaded fail `H3.skills_declared` and `H2.tools_allowlisted`;
- an `allowedTools` wildcard fails `H2.tools_allowlisted`;
- a callable `Bash` or `WebFetch` fails `H2.tools_allowlisted`;
- no hook, with `settingSources: []`, fails `H3.payloads_guarded`.

Nothing is ever MET from code, and an option the reader could not resolve
concludes nothing. Python is read by a bounded
tokenizer and expression reader (`packages/scanner/src/sources/code/python.ts`); JavaScript and
TypeScript by TypeScript's syntax-only parser (`packages/scanner/src/sources/code/javascript.ts`).
Neither imports, evaluates or spawns anything, and the side-effect test in
`packages/scanner/tests/langchain-code-source.test.ts` proves it. A lint
rule in `eslint.config.mjs` refuses `child_process`, `vm`, `worker_threads`,
`module`, `cluster`, `inspector`, `require()`, `import()`, `eval` and
`Function` in those files. A file that does not parse, or a definition built from something the
reader cannot see — a tool list returned by a function, a model passed in as a
parameter, `**kwargs` — makes the source `INCOMPLETE` `UNPARSEABLE`, and the
agent is still reported with what resolved.

Each agent's model endpoints go into `/2`'s optional `models[]`: the https URL,
the `env://` reference it is read from, or, when neither is knowable, the
`code://` locator of the model's construction. The ingest verifies them and
keeps them on the agent's scan item, and the harness matrix lists them.

**Unbound credentials.** `/2`'s `unboundCredentials[]` lists credential
references a source saw bound to no principal, from which the ingest derives
`ORPHAN_CREDENTIAL`. A source returns them on its read
(`SourceRead.unboundCredentials`), and the report builder drops any reference a
principal in the merged population holds. Entra returns the credentials of an
application registration with no service principal in the directory. Okta and
Key Vault report every credential against the principal it belongs to, so
neither returns one. Nor does the `code` source: a reference in code that no
agent uses is not evidence that a credential exists.

### The labelling conventions

These are the documented defaults (owner decision, 2026-10-19). Each can be
overridden for one estate in its configuration:

| What | Default | Override |
|---|---|---|
| An Okta service app's owner | the app's `profile.owner` | `ownerProfileKey` on the `okta-app` source |
| The principal a Key Vault secret or certificate belongs to | the tag `inflect-principal`, holding the principal's id (`okta:app:<id>`, `entra:sp:<objectId>`, …) | `principalTag` on the `vault` source |
| A Key Vault credential's owner | the tag `owner` | `ownerTag` on the `vault` source |

What the sources never do:

- **Write.** A source holds a `ReadOnlyHttp`, whose only verb is a GET. The token
  exchange is the one POST, to the identity provider, behind its own interface.
- **Read a secret's value.** Neither `GET /api/v1/apps/{id}/credentials/secrets`
  (Okta returns client secrets there) nor `GET {vault}/secrets/{name}` is
  called. Credentials are reported by reference (`okta://…`, `azure-kv://…`).
  One listing the scanner can call carries values it never reads: LangSmith's
  deployments listing documents each deployment's `secrets`, name and value. It
  is requested only when the estate opts in (`readDeployments`); the source then
  reads a deployment's id and tracing project and nothing else, and the tests
  hold a marker in that member out of the report and the log.
- **Read a run.** No LangSmith run, trace or run content is fetched: not
  `GET /api/v1/runs/{id}`, not `POST /api/v1/runs/query`. Tool usage comes from
  the projects listing's aggregates.
- **Link to the register.** Only the `inflect-register` source's
  `registeredAgentId` reaches the report; the builder drops the member from any
  other source, because a label in the estate being scanned is something its
  administrator can write.
- **Leave their origin.** Every request is https, on the configured host, with
  redirects refused; a next-page link anywhere else ends the read as
  `PAGINATION_TORN`. Each source has a time box and a byte budget.
- **Run what they read.** The `code` source parses text. It follows no symbolic
  link, caps each file at 1 MiB and the whole read at 20,000 files and 128 MiB,
  and stops at the scan's deadline, reporting each as its reason.

`packages/scanner/src/scanner-surface.ts` declares every request the scanner can make, and its
hash is the report's `scan.scanner.manifestHash`. The tests hold every request
the HTTP fakes see to that declaration.

## What it may import

Itself; Node's built-ins; `zod`; `typescript`, whose syntax-only parser the
`code` source reads JavaScript and TypeScript with; `js-yaml`, which the `cicd`
source reads workflow files with; and `@scanent/contract`: the wire contract
(`harness-contract`, `harness-findings`, `harness-ladder`, `canonical-json`)
and the pure CIDR parser (`cidr`), so a private-range allowlist parses exactly
as the ingest's side does. Nothing else, and
`packages/scanner/tests/package-closure.test.ts` holds each package's declared
dependencies to what its source imports. Sharing the contract is deliberate.
The scanner checks its report against the ingest's own schema and secret-shape
scan **before** it signs, and signs the message the ingest verifies, through
one function rather than a copy.

## Configuration

One JSON file per estate. Strict: an unknown key is an error. No credential is
ever in the file; each is named by the environment variable that holds it, and a
secret-shaped string anywhere in the file is refused by path.

```json
{
  "estate": "acme-prod",
  "scanner": { "agentId": "<the scanner's register id>", "signingKeyEnv": "SCANNER_SIGNING_KEY" },
  "inflect": { "baseUrl": "https://inflect.example.com", "tenantSlug": "acme", "apiKeyEnv": "INFLECT_INGEST_KEY" },
  "schedule": { "everyHours": 24 },
  "sources": [
    {
      "kind": "entra-sp", "directoryId": "<Entra directory id, a GUID>",
      "clientId": "<app id>", "clientSecretEnv": "ENTRA_CLIENT_SECRET"
    },
    { "kind": "okta-app", "orgUrl": "https://acme.okta.com", "apiTokenEnv": "OKTA_API_TOKEN" },
    {
      "kind": "vault", "product": "azure-key-vault",
      "vaultUrls": ["https://acme-agents.vault.azure.net"],
      "directoryTenantId": "<Entra tenant id>", "clientId": "<app id>",
      "clientSecretEnv": "AZURE_CLIENT_SECRET"
    },
    {
      "kind": "runtime", "product": "langsmith",
      "endpoint": { "cloud": "eu" },
      "apiKeyEnv": "LANGSMITH_API_KEY",
      "workspaceId": "<workspace id>", "windowDays": 7
    },
    {
      "kind": "cicd", "product": "github-actions",
      "repositories": ["acme/payments-api", "acme/infra"],
      "tokenEnv": "GITHUB_READ_TOKEN"
    },
    {
      "kind": "gcp-sa", "product": "gcp-iam",
      "projects": ["acme-prod", "acme-data"],
      "keyEnv": "GCP_SCANNER_KEY"
    },
    {
      "kind": "code", "product": "langchain",
      "roots": [{ "label": "support-bot", "path": "/estate/repos/support-bot" }]
    },
    { "kind": "inflect-register" },
    {
      "kind": "mcp",
      "servers": [
        {
          "label": "crm", "url": "https://mcp.acme.example/crm/mcp",
          "agents": ["entra:sp:<objectId>"],
          "pinnedManifestHash": "sha256:<the listing hash from the log>",
          "readTokenEnv": "MCP_CRM_TOKEN"
        }
      ]
    }
  ]
}
```

A self-hosted LangSmith names its own host instead:
`"endpoint": { "selfHosted": "https://langsmith.acme.example" }`, with
`"egressPrivateCidrAllowlist": ["10.20.0.0/16"]` beside it when that host is on
the estate's own network (below). Add `"readDeployments": true` to list
deployments as well; leave it out for a LangSmith that runs no deployment
control plane.

- `SCANNER_SIGNING_KEY`: the Ed25519 private key, PKCS#8 PEM. Register its
  public half in the tenant (`public-key` prints it).
- `INFLECT_INGEST_KEY`: an API key bound to the scanner agent, with the
  `admin:harness_ingest` scope, and `mcp:read` when the estate reads the register
  (`inflect-register`), and no other. The scanner agent must then be granted the
  tool `get_harness_register`.
- `ENTRA_CLIENT_SECRET`: an Entra application holding the Microsoft Graph
  application permission `Application.Read.All`, which lists registrations and
  service principals and cannot change them. Add
  `"includeThirdPartyApplications": true` to report third-party applications
  consented into the directory as well.
- `OKTA_API_TOKEN`: an SSWS token for a read-only administrator.
- `MCP_CRM_TOKEN` (any name, per server, optional): a READ token for that MCP
  server. For Inflect's own `/api/mcp`, an API key holding `mcp:read` and no
  other MCP scope. It is sent with `initialize`, the initialized notification
  and `tools/list`, and nothing else.
- `AZURE_CLIENT_SECRET`: an Entra application holding `Key Vault Reader` on each
  vault, which reads metadata and cannot read a secret's contents.
- `LANGSMITH_API_KEY`: a LangSmith service key holding the workspace Viewer
  role, where the workspace can assign one; otherwise the key carries its
  issuer's rights and the GET-only wire is what keeps the read read-only.
  `workspaceId` is sent as `X-Tenant-Id`; leave it out for a key scoped to one
  workspace.
- `GITHUB_READ_TOKEN`: a fine-grained personal access token, or a GitHub App
  installation token, limited to the listed repositories and holding the
  repository permissions **Contents: read** and **Secrets: read**, and no other.
- `GCP_SCANNER_KEY`: the JSON key file of a service account holding
  `roles/iam.serviceAccountViewer` on the listed projects, and no other role.

Entra is read from `graph.microsoft.com`, Okta orgs must be on `*.okta.com` or `*.oktapreview.com`, vaults on
`*.vault.azure.net`, LangSmith on `api.smith.langchain.com` (`"cloud": "us"`) or
`eu.api.smith.langchain.com` (`"cloud": "eu"`), GitHub on `api.github.com`,
Google Cloud on `iam.googleapis.com` with its token from `oauth2.googleapis.com`,
and the ingest on https.
A `code` root is an absolute path with no `..` segment, reported only by its
label; it takes no credential.

A self-hosted LangSmith is the one host the configuration lets a person type, so
it is checked the way the Inflect application checks any customer-named host
(`packages/scanner/src/customer-host.ts`): it must be a bare
https origin, not a literal private, loopback or link-local address, not
`localhost` or a metadata name, and not a `.local` or `.internal` name. Before
every request the scanner resolves the host again and refuses to send the key
if any address it resolves to is private, so a name repointed after the file was
written stops the read as `UNREACHABLE`.

**A self-hosted LangSmith on the estate's own network** names the private ranges
its host may resolve into, in `egressPrivateCidrAllowlist` on the `selfHosted`
endpoint. This mirrors the Inflect application's self-hosted egress allowlist, and keeps
its three properties:

- It is the estate's own file. No tenant column, form or route reaches it.
- Metadata, loopback and link-local stay refused inside it: `127.0.0.0/8`,
  `0.0.0.0/8`, `169.254.0.0/16`, `::1`, `::` and `fe80::/10` are checked before
  the allowlist, so even `0.0.0.0/0` cannot reach `169.254.169.254`. The blocked
  names stay refused too.
- It widens which addresses are acceptable and removes no other check. The host
  is still resolved before every request with every address tested, so a name
  that resolves outside the listed ranges sends nothing.

With an allowlist, an internal name such as `langsmith.corp.internal` is
accepted, because the question becomes the address rather than the name. Each
entry must be a CIDR, or the configuration is refused.

### Outputs

Where one run's results go. Optional:

```json
"outputs": [
  { "kind": "file", "dir": "/out", "retainRuns": 90 },
  { "kind": "stdout" },
  { "kind": "inflect" }
]
```

| Kind | Fields | Effect |
|---|---|---|
| `file` | `dir`, an absolute path; `retainRuns`, optional, 1 to 10,000 | Writes the run's files under `dir` (see "Local results") |
| `stdout` | none | Writes the signed report and a newline to stdout |
| `inflect` | none | Posts the signed report to the `inflect` block's tenant |

One to three entries, each kind at most once. Without `outputs`, a
configuration that has an `inflect` block posts to it, which is what every
configuration written before outputs existed means.

The `inflect` block is optional. It is required, and the configuration is
refused without it, when the `inflect` output is configured, when the
`inflect-register` source is configured, or when `egress` is set. The ingest
key is needed, before the scan starts, only when the `inflect` output is in
effect for the run.

Two flags adjust the outputs for one call:

- `--out <dir>` (an absolute path; `--out=<dir>` is the same) sets the file
  output's directory, adding a file output if the configuration has none.
- `--dry-run` removes the `inflect` output and adds `stdout`: post nothing,
  print the report. With `--out` it writes the files as well.

An argument `scan`, `schedule` or `public-key` does not know is refused with
exit code 2 before the configuration is read, so a mistyped flag never runs a
scan that delivers somewhere other than where it was told. `--help` or `-h`
after any of the three prints the commands.

A call left with no output is refused before anything is read: exit code 2
and `nowhere to deliver: configure outputs, or pass --out or --dry-run`.

Delivery order is file, stdout, inflect, so what stays in the estate is
written before anything leaves it. Each output is attempted whatever happened
to the others, a failure is one `output failed` log line naming the output,
and `scan` exits 0 only when every output was delivered.

### The inventory

Optional. An estate with no register has nothing that says an agent is known or
who owns it, so every agent the scanner finds would read as a shadow agent. The
inventory is the operator's own list:

```json
"inventory": { "path": "/etc/scanent/inventory.json" }
```

The path is absolute, and the file is a `.json` or a `.csv` (told apart by the
extension), at most 5 MiB and 5,000 rows. JSON:

```json
{
  "inventory": "scanent-inventory/1",
  "agents": [
    {
      "discoveredId": "entra:sp:00000000-0000-0000-0000-000000000000",
      "name": "Invoice triage",
      "owner": "finance-operations",
      "purpose": "Sorts incoming invoices into queues",
      "axes": { "autonomy": "human-approves", "dataClass": "confidential", "reach": "write" },
      "riskTier": "MEDIUM",
      "riskAssessedOn": "2026-09-30"
    }
  ]
}
```

CSV is RFC 4180, UTF-8, with a header row holding
`discoveredId,name,owner,purpose` and any of
`autonomy,dataClass,reach,riskTier,riskAssessedOn`. An empty optional cell is an
absent value.

| Field | Required | Rule |
|---|---|---|
| `discoveredId` | yes | The id the scan reports, 1 to 256 characters, once in the file |
| `name`, `owner` | yes | 1 to 256 characters, no control character |
| `purpose` | yes | 1 to 512 characters, no control character |
| `axes` | no | All three or none. `autonomy`: `human-approves`, `human-reviews`, `autonomous`. `dataClass`: `public`, `internal`, `confidential`, `restricted`. `reach`: `read-only`, `write`, `external` |
| `riskTier` | no | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, with `riskAssessedOn` or not at all |
| `riskAssessedOn` | no | `YYYY-MM-DD` |

What holds it:

- **It matches by exact `discoveredId` and nothing else.** No case folding, no
  trimming, no prefix, no name. A row that matches no agent in the scan is
  listed as declared and not found; it is not a finding.
- **Everything it supplies is declared by the operator, never observed.** Local
  results label it so, and keep a level that rests on a declaration apart from
  the level the sources observed alone.
- **It evidences the four H1 criteria and nothing above H1.** A matched row
  declares the agent registered and owned; its axes when all three are given;
  and its risk tier as fresh when the assessment is dated on or before the scan
  and at most 365 days before it. A declared "met" never outvotes a source that
  observed NOT MET.
- **It never enters the signed report** and is never posted.
- **A file that is missing, too large, malformed or refused is an error, never
  an empty inventory.** Scoring against half an inventory would report known
  agents as shadow agents. A refusal names the row and the field, never the
  value, and a secret-shaped value anywhere in the file is refused by path.

The inventory is read once per run, before any source, whenever the
configuration names one. A file that is missing or refused stops the run:
scoring against half an inventory would report known agents as shadow agents.
It is used by the file output's local results (below) and by nothing else.

## Running

From a checkout, after `npm ci && npm run build`:

```bash
node packages/scanner/dist/cli.js public-key --config estate.json
node packages/scanner/dist/cli.js scan --config estate.json --dry-run
node packages/scanner/dist/cli.js scan --config estate.json
node packages/scanner/dist/cli.js scan --config estate.json --out /var/lib/scanent
node packages/scanner/dist/cli.js schedule --config estate.json [--out /var/lib/scanent]
node packages/scanner/dist/cli.js diff <old> <new>
node packages/scanner/dist/cli.js init [--dir <dir>] [--answers <file>]
node packages/scanner/dist/cli.js keygen --out <file>
node packages/scanner/dist/cli.js doctor --config estate.json [--json]
node packages/scanner/dist/cli.js hosts --config estate.json
node packages/scanner/dist/cli.js help
```

`init`, `keygen`, `doctor` and `hosts` are described under
[Setting up an estate](#setting-up-an-estate) below.

`scan --strict` changes the exit code and nothing else: a run that was
delivered exits 3 when a source was `INCOMPLETE` or the scan found no agent,
so a scheduler can tell a full run from a partial one. Without it a delivered
run exits 0, complete or not, as it always has; the report and the local
results say what was incomplete either way. `schedule` does not take the flag,
because a schedule does not exit.

`@scanent/scanner` declares that file as two commands, `scanent` and its alias
`aes`; wherever the package is installed they are the same program.

`schedule` scans at once and then every `schedule.everyHours`, anchored to each
run's start. A failed run is logged and the schedule continues. The tenant
declares the same cadence on the estate, and shows the estate as stale once its
last complete scan is older than one and a half cadences.

The log is one JSON line per event on stderr, with kinds and counts only. A
string with a secret's shape is replaced before it is written.

On `SIGTERM` or `SIGINT` the scanner stops at once. A scan cut short posts
nothing, and a run that was being written is left under a temporary name that
no reader takes for a run; the next run after a day removes it.

## Setting up an estate

Three commands take an estate from nothing to a first scan, and none of them
needs a second tool: `init` writes the files, `doctor` checks them, `scan`
runs.

### `init`

```
scanent init [--dir <dir>] [--answers <file>] [--force] [--no-keygen] [--print-access]
```

`init` writes three files under `<dir>` (default `./scanent`, created with
mode 0700):

| File | Mode | What it holds |
|---|---|---|
| `config.json` | 0600 | The configuration for the sources you chose. It parses under the strict schema, by construction |
| `scanent.env` | 0600 | One line per credential the configuration names: the NAME and nothing after the `=`. The one value it ever holds is the path of the signing key `init` created |
| `signing-key.pem` | 0600 | An Ed25519 signing key, unless `--no-keygen` |

It then prints the public half of the key, the read-only access each chosen
source needs ([access.md](access.md) is the same tables), and the next steps.
It makes no network request and reads no credential.

**It never asks for a secret value.** No question is about one; where a source
has a credential, the wizard names the variable it goes in and moves on. Every
answer is checked for a secret's shape before anything else looks at it: a hit
is refused, is not stored, written or repeated back, and the question is asked
again. Three refusals of one question end the wizard with nothing written. A
terminal has already shown what was typed, which is why the refusal says to
rotate the credential if it was real.

Two ways to answer:

- **At a terminal.** `init` asks for the estate's name, then whether you have
  each kind of source and that source's facts (a directory id, an org URL, a
  repository), then the output directory, the schedule, an optional inventory
  and whether to post to an Inflect tenant (default: no).
- **From a file**, `--answers <file>`, for automation. Without it, and when
  stdin is not a terminal, `init` exits 2 and says so.

The answers file is strict JSON, schema `scanent-init-answers/1`:

```json
{
  "answers": "scanent-init-answers/1",
  "estate": "acme-prod",
  "everyHours": 24,
  "outputDir": "/out",
  "retainRuns": 90,
  "inventoryPath": "/etc/scanent/inventory.json",
  "sources": [
    { "kind": "entra-sp", "directoryId": "<guid>", "clientId": "<guid>" },
    { "kind": "okta-app", "orgUrl": "https://acme.okta.com" },
    { "kind": "cicd", "repositories": ["acme/payments-api"] },
    { "kind": "code", "roots": [{ "label": "support-bot", "path": "/estate/support-bot" }] },
    { "kind": "mcp", "servers": [{ "label": "crm", "url": "https://mcp.acme.example/crm/mcp", "readToken": true }] }
  ],
  "inflect": null
}
```

A source is the configuration's source without `product` (each kind has one)
and without its variable name, which gets the documented default
(`ENTRA_CLIENT_SECRET`, `OKTA_API_TOKEN`, `AZURE_CLIENT_SECRET`,
`GITHUB_READ_TOKEN`, `GCP_SCANNER_KEY`, `LANGSMITH_API_KEY`,
`MCP_<LABEL>_TOKEN`). Its other fields carry the configuration's own names,
optional ones included, and are held to the configuration's own rules. To
choose a variable's name, give the configuration's field (`"apiTokenEnv":
"ACME_OKTA_TOKEN"`). `inflect` is `null`, or `{ "baseUrl", "tenantSlug",
"agentId", "readRegister" }`; without it the configuration names no tenant and
writes files only.

What it will not do:

- Replace `config.json` or `scanent.env` without `--force`. Both are looked
  for before either is written, so a refused run writes nothing.
- Replace a signing key, with or without `--force`: every earlier report was
  signed with it. An existing `signing-key.pem` is kept, and `init` says so.
- Write into a directory that is a symbolic link.

`--print-access` prints the access tables for the chosen sources on stdout and
writes nothing.

`scanent.env` names the signing key by the path `init` wrote it to. Run
`doctor` and `scan` where that path is the same: in a container, run `init`
with the directory mounted where it will be mounted for the scan.

Exit codes: 0 written; 2 a usage error, a refused overwrite, three refusals,
or no terminal and no `--answers`; 4 the answers file is unreadable, not JSON,
fails its schema, plans a configuration that is refused, or holds a
secret-shaped string (named by path, never repeated).

### `keygen`

```
scanent keygen --out <file>
```

Creates an Ed25519 signing key in a new file, mode 0600, and prints its raw
public key in hex on stdout (what `public-key` prints). The private key goes
to the file and nowhere else. An existing file is refused with exit 2; there
is no overwrite. `init` calls the same function.

A run with no tenant still signs: the signature is what lets `diff` and a
later reader show that a report was not altered. The public half needs
registering only with a tenant.

`openssl genpkey -algorithm ed25519` makes an equally good key. `keygen`
exists so a first run needs no second tool, and so the key lands in a file
(`SCANNER_SIGNING_KEY_FILE`), which survives an env file where a PEM's line
breaks do not.

### `doctor`

```
scanent doctor --config <file> [--json] [--out <dir>] [--source <kind>]...
```

`doctor` answers one question, "is this estate ready to be scanned?", by
trying it: it reads what `scan` would read, with the same credentials, through
the same wire. Three rules:

- **It writes nothing, anywhere.** No report, no file, no post. It never sends
  a write to a system to learn whether a write would be allowed. "Writable" for
  the output directory is read from permissions, and the detail says so.
- **It adds no request.** Each source's probe is the first, smallest page of
  the reads that source already makes, so the declared surface and its hash are
  unchanged, and the tests hold every request `doctor` makes to that surface.
- **Absence is never a pass.** A check passes only on something observed.

Every check has one of four statuses:

| Status | Meaning |
|---|---|
| `PASS` | What the check names was observed |
| `WARN` | It works, and something should be fixed. A fix is given |
| `FAIL` | It does not work. A fix is given, and the failure's class decides the exit code |
| `SKIPPED` | Not checked, and always with the cause: `not applicable` (nothing to check), `blocked` (something before it failed, so this could not be checked; never read it as a pass), or `not observable` (no read the scanner makes can answer it; the detail says what to confirm by hand) |

Each source gets the same six checks:

| Check | Passes when |
|---|---|
| `credential.present` | The variable, or its `_FILE`, holds a value |
| `host.resolves` | The source's hosts resolve. A host you name (a self-hosted LangSmith, an MCP server) must also resolve to an address the scanner may reach, exactly as before each request of a scan. A fixed host behind a proxy is resolved by the proxy and is `not applicable` |
| `reachable` | A request was answered. No answer names the host; an untrusted certificate is told apart, with `NODE_EXTRA_CA_CERTS` as the fix |
| `authenticated` | The token exchange succeeded, or the first read was not refused as unauthenticated |
| `read.permitted` | Every probe read succeeded. A 403 fails with the grant the source needs; a 429 is `blocked`, to be run again |
| `write.absent` | A read showed the credential's grant, and it is read-only |

`write.absent` is where honesty costs the most. Only two sources reveal a
credential's grant through a read the scanner already makes:

| Source | What shows it | Result |
|---|---|---|
| `entra-sp` | The access token's `roles` claim lists the application permissions | `PASS` naming the roles when none writes; `WARN` naming each role that does (`ReadWrite`, `Write`, `FullControl`, `Manage`, `AccessAsUser`) |
| `cicd` | GitHub's `X-OAuth-Scopes` header lists a classic token's scopes | `WARN` for `repo`, `public_repo`, `workflow`, `delete_repo`, `admin:…` or `write:…`; `PASS` naming the scopes otherwise. A fine-grained or installation token gets no such header: `not observable` |
| `code` | The file permissions of each root | `WARN` when the scanner could write a root (mount it read-only) |
| every other source | Nothing the scanner reads | `not observable`, with what to confirm in the product's own console |

Okta's administrator role, a Key Vault role assignment and Google's
`testIamPermissions` would each need a request the scanner does not declare
(one of them a POST), so `doctor` does not make them and does not guess.

The `inflect` output's key is used only to post, which is a write, so `doctor`
checks that the key is present and reports whether it may post as `not
observable`: the first `scan` shows it.

The local checks, under the scope `local`:

| Check | What it looks at |
|---|---|
| `config.valid` | The file parses under the strict schema. If it does not, every other check is `blocked` |
| `config.mode` | The file is not writable by group or others |
| `signing-key` | The key resolves and is Ed25519 in PKCS#8 PEM; the detail is its public half |
| `secret-files` | Every `_FILE` in use passes the rules below. A file readable by group or others outside `/run/secrets/` and `/var/run/secrets/` is a warning |
| `output.dir` | The file output's directory (or `--out`) exists, is a directory and not a link, and is writable by this user, or does not exist and can be created. Writable by other users is a warning |
| `inventory` | The inventory, when one is configured, loads; the detail is its row count |
| `tls.verification` | `NODE_TLS_REJECT_UNAUTHORIZED` is not `0`. When it is, no source is contacted |
| `tls.extra-ca` | `NODE_EXTRA_CA_CERTS`, when set, names a readable file holding a certificate |
| `proxy` | `HTTPS_PROXY`, when set, is a URL, and `NODE_USE_ENV_PROXY=1` on a Node that honours it. Otherwise requests would not use the proxy, which is a failure. The detail is the proxy's host and port, never its userinfo |
| `proxy.customer-hosts` | A host you name is not reached through the proxy (see below) |
| `clock` | The largest difference between this machine's clock and the `Date` header of the probe responses: under 60 seconds passes, up to 300 warns, more fails. No header seen is `not observable` |
| `egress` | The egress proof, when the configuration has an `egress` block |

`--source <kind>` limits the source checks to the kinds named, and may repeat;
the local checks always run. `--out <dir>` checks that directory in place of
the configuration's file output.

The default output is a table on stdout, with a last line that counts each
status and says how many checks were not checked and why. It says "all checks
passed" only when every check did. `--json` prints one document instead:

```json
{
  "doctor": "scanent-doctor/1",
  "estate": "acme-prod",
  "at": "2026-11-12T09:00:00.000Z",
  "scanner": { "version": "0.12.0", "manifestHash": "sha256:…" },
  "ready": false,
  "counts": { "PASS": 14, "WARN": 2, "FAIL": 0, "SKIPPED": 5 },
  "exitCode": 3,
  "checks": [{ "scope": "local", "id": "config.valid", "status": "PASS", "detail": "9 sources" }]
}
```

No detail or fix holds a credential, a response body or a URL: they are built
from fixed sentences, the configuration's own names, status codes, counts and
role or scope names.

`doctor` exits by the first row that applies:

| Code | When |
|---|---|
| 2 | A usage error |
| 4 | The configuration could not be read or parsed, or any other configuration failure |
| 5 | A credential is missing or was refused |
| 6 | A host could not be resolved or reached |
| 3 | Nothing failed, and there is a warning or a blocked check |
| 0 | Every check passed, or was `not applicable` or `not observable` |

`not observable` does not change the exit code, because no rerun can turn it
into a pass. It is always shown and always counted as not checked.

### `hosts`

```
scanent hosts --config <file> [--format lines|json|egress-allow]
```

Prints the hosts the configuration makes the scanner reach, each on port 443.
It is offline: it needs no credential and makes no request. The list is
derived from the same constants the declared surface is built from, and a test
holds it equal to the hosts a full scan contacts.

| Source | Hosts |
|---|---|
| `entra-sp` | `login.microsoftonline.com`, `graph.microsoft.com` |
| `vault` | `login.microsoftonline.com`, each vault's host |
| `okta-app` | The org's host |
| `cicd` | `api.github.com` |
| `gcp-sa` | `oauth2.googleapis.com`, `iam.googleapis.com` |
| `runtime` | `api.smith.langchain.com` or `eu.api.smith.langchain.com`, or the self-hosted host |
| `mcp` | Each server's host |
| `inflect-register`, and the `inflect` output | The tenant's host |
| `code` | None |

`lines` (the default) prints `host:443`, sorted, one per line. `egress-allow`
prints the comma-separated value the bundled proxy's `EGRESS_ALLOW` takes.
`json` prints each entry with its source and purpose.

## Secrets from files

For each variable the configuration names, and for no other, `<NAME>_FILE`
may name a file holding the value instead:

| `NAME` | `NAME_FILE` | Result |
|---|---|---|
| set | unset | The variable's value |
| unset or empty | set | The file's content |
| set | set | Refused. A precedence rule would silently ignore one of two credentials, and the one ignored may be the one just rotated |
| unset or empty | unset | Absent: a source reports `AUTH_FAILED`, and a missing signing key stops the run |

The file's path is absolute. The file is a regular file (a link to one is
followed, as a Kubernetes secret is one), at most 64 KiB, UTF-8 text, and not
writable by other users: a world-writable file would let any local user
replace the signing key. One trailing line break is removed. A world-readable
file is accepted, because Docker mounts a secret 0444 and Kubernetes 0644
inside a mount only that container sees; `doctor` warns about one outside
such a mount.

A refusal names the variable and a reason code (`BOTH_SET`, `FILE_PATH`,
`NOT_A_FILE`, `TOO_LARGE`, `WORLD_WRITABLE`, `EMPTY`, `NOT_TEXT`,
`UNREADABLE`), never anything of the file's content, and the command exits 4.
Files are read once, at start: under `schedule`, a rotated file takes effect
at the next start.

Use the file form for the signing key and a Google key file. Both have line
breaks, which an env file cannot carry.

## Proxy and certificate authority

**Proxy.** The scanner's requests are Node's own `fetch`, which honours
`HTTPS_PROXY` and `NO_PROXY` when `NODE_USE_ENV_PROXY=1` (Node 24, and 22.21
or later). The container image sets that variable; with no proxy variable it
changes nothing. From source, set it yourself: `doctor` fails the `proxy`
check when `HTTPS_PROXY` is set without it, because the requests would
silently go direct. scanent adds no proxy library, and never logs or prints a
proxy URL, which may carry a password.

`NO_PROXY` follows Node's rules: `*`, an exact name, `.suffix` or `*.suffix`,
and an optional `:port`. A bare name exempts that name only, not its
subdomains.

**The host check is not weakened by a proxy.** A host you name (a self-hosted
LangSmith, an MCP server) is resolved and checked before every request,
proxied or not. Two consequences:

- A host on your own network belongs in `NO_PROXY`. It is then reached
  directly, and the check is about the connection that is made.
- A host reached through the proxy is still resolved here first. If this
  machine cannot resolve it, the read is `UNREACHABLE`: add it to `NO_PROXY`,
  or give this machine a resolver that can. If it does resolve, the check
  passes on this machine's answer while the proxy resolves again on its own.
  `doctor` raises that as `proxy.customer-hosts`.

**Certificate authority.** To trust a private authority, for example behind
TLS inspection, mount its certificate as a PEM file and set
`NODE_EXTRA_CA_CERTS` to its path. Node reads it at start and adds it to its
own authorities. That is the whole mechanism: there is no configuration key,
and nothing turns verification off. `scan` and `schedule` refuse to run with
`NODE_TLS_REJECT_UNAUTHORIZED=0` (exit 4, before the configuration is read),
and `doctor` fails `tls.verification` and contacts no source: a scanner that
carries an estate's read credentials does not send them over an unverified
connection.

A certificate that is not trusted reaches the report as `UNREACHABLE`, like
any host that could not be reached. `doctor` tells it apart and names the fix.

## Exit codes

| Code | Name | Meaning |
|---|---|---|
| 0 | OK | The command did what it was asked. `scan`: every output delivered. `diff`: no difference. `doctor`: ready |
| 1 | FAILED | The command failed: an output was not delivered, the ingest refused the report, the signing key is missing, or an error with no class of its own. `diff`: a difference |
| 2 | USAGE | Wrong arguments, an unknown flag, nowhere to deliver, a refused overwrite. Nothing was read or written |
| 3 | INCOMPLETE | Nothing failed, and not everything could be established. `scan --strict`: delivered, but a source was `INCOMPLETE` or no agent was found. `diff`: could not compare everything. `doctor`: warnings or blocked checks |
| 4 | CONFIG | The configuration, the answers file, the inventory or a secret file was refused; `NODE_TLS_REJECT_UNAUTHORIZED=0` |
| 5 | CREDENTIAL | `doctor`: a credential is missing or refused |
| 6 | NETWORK | `doctor`: a host could not be resolved or reached |
| 130 | SIGINT | Interrupted |
| 143 | SIGTERM | Terminated |

0, 1 and 2 mean what they did before the other codes existed. In particular
`scan` without `--strict` exits 0 for a delivered run whether or not it was
complete, and a missing signing key is 1.

## Local results

The file output writes one directory per run and a pointer to the newest:

```
<dir>/
  latest.json                    { scanId, dir, asOf, complete, agentCount }
  runs/
    <scanId>/
      report.signed.json         the signed report, byte for byte what would be posted
      results.json               the local results (schema `scanent-results/1`)
      agents.csv
      findings.csv
      summary.html
      manifest.json              the names, sizes and SHA-256 of the other five
```

A run is rendered in memory, checked, written under a temporary name and
renamed into place, so a run directory is whole or absent. Nothing that exists
is replaced except `latest.json`, and that by a rename; a run whose directory
already exists fails. Directories are created `0750` and files `0640`, one
level at a time; a `runs` that is a link to somewhere else is refused. If the
run is in place and only `latest.json` cannot be replaced, the run is kept and
the output fails, saying so: the pointer then names an earlier run. Nothing
is ever removed unless `retainRuns` is set; then, after a successful write, the
oldest runs beyond that number are removed, and only a directory whose name is
a scan id and that holds a `manifest.json`.

Before the first byte is written, the results are walked for any string with a
secret's shape, and each rendered file is checked again as one text. A hit
refuses the whole run and names the member or the file, never the value.

What the results say, and do not:

- **A level is stated only for an agent that can be judged.** An agent is
  judged when every source it was found through was read in full, and so was
  every source that reports on agents other sources find (today, the
  register). Otherwise it is `NOT_JUDGED` with the reasons, and has no level,
  bar or shortfall in any file: the page says "Not judged" and the CSV cells
  are empty.
- **What the run could not have evidenced is listed.** Each criterion is
  marked readable or not: whether any reader this run configured could have
  reported it met. `coverage.reachableLevel` is the highest level the run could
  have stated. Without the `inflect-register` source that is H1 at most (with
  an inventory), because two H2 criteria have no other reader; with it, H3.
  No reader evidences H4 or H5. So in a run with no register every judged
  agent is below its bar, and the files say that this is a limit of what was
  read.
- **Declared is not observed.** What the inventory supplies is labelled
  "declared by the operator" in every file, and `observedLevel` is the level
  with the declarations removed.
- **An empty scan is a finding** (`EMPTY_SCAN`), never a clean result.

`summary.html` is one self-contained file: no script, no image, no font, no
link to anywhere, and a Content-Security-Policy that makes the browser hold
that. Every scanned string is escaped. It prints, and follows the reader's
light or dark setting.

`agents.csv` and `findings.csv` are UTF-8 with a byte-order mark, CRLF line
ends and every field quoted. A cell that a spreadsheet would evaluate as a
formula (it starts with `=`, `+`, `-`, `@`, a tab or a carriage return) is
prefixed with a single quote.

The same report, inventory and configuration give the same `results.json`,
CSV files and page, byte for byte.

### Comparing two runs

```bash
scanent diff <old> <new> [--format text|json] [--trust-key <hex>] [--allow-different-scanner]
```

Each argument is a `results.json` or a signed report; which is decided by the
file's content. A signed report is verified first, against `--trust-key` when
given and otherwise against the key the report itself carries (which shows it
was not altered, not who signed it; the output says "signer not pinned"), and
is then scored with no inventory.

Absence is evidence only on a full read:

| Entry | When |
|---|---|
| agent `new` | in the newer run and not the older |
| agent `gone` | in the older run only, and every source it was found through was read in full by the newer run |
| agent `not seen` | in the older run only, and one of those sources was incomplete or not listed, or the newer run found no agent at all. Nothing is concluded |
| level up or down | only when both runs judged the agent |
| orphan credential or finding `closed` | only on the evidence that would close it: its source read in full, the agent present and judged, the scan complete where the rule needs it. An unpinned write tool closes only when the source its tools were read from (`code`, or `mcp`) is listed and read in full. An empty newer run closes no orphan credential |
| `no longer reported, not concluded` | everything else that is absent from the newer run |

Refused, with exit code 2: a file that cannot be read or is neither kind, a
results file that fails its schema, a report that fails verification, a newer
run that is not later than the older, different ladder versions, and different
scanners unless `--allow-different-scanner` (and then nothing absent is
concluded). Two runs that name different estates are compared with the warning
`ESTATE_DIFFERS`, and nothing absent is concluded either.

The strings in a diff are scanned data. In the text output every control
character, line separator and bidirectional control is written as a visible
`\u{..}`, so an id cannot add a line or send the terminal an escape sequence;
in the JSON output they are `\uXXXX` escapes, and the values are unchanged.

| Exit code | Meaning |
|---|---|
| 0 | No difference, and every comparison could be made |
| 1 | At least one difference |
| 2 | A usage or input error; nothing was compared |
| 3 | No difference found, but something could not be compared: an incomplete scan, an agent not judged or not seen |

## The egress proxy

The scanner carries its own egress proxy, `packages/scanner/src/egress-proxy.ts`
(compiled to `dist/egress-proxy.js`): CONNECT tunnels to exact allowlisted
hostnames on 443 (`EGRESS_ALLOW`), and 403 or 405 for everything else, an empty
allowlist refusing all. Put the scanner on a network whose only exit is that
proxy, and point the scanner at it with `HTTPS_PROXY` and
`NODE_USE_ENV_PROXY=1`. Name the proxy and a canary host in the configuration's
`egress` block, and every scan proves the confinement before it reads: the
proxy admits the ingest host, refuses the canary, and a direct connection to
the ingest host fails. The result is the scanner's own `H3.egress_enforced`.

## Container

`deploy/Dockerfile` builds the image, from the repository root:

```bash
docker build -f deploy/Dockerfile -t scanent .
```

The image is built and checked in CI and is not published anywhere. Its build
stage compiles the packages with `tsc`; its runtime stage holds the
compiled JavaScript, the package manifests and the production dependencies
(`zod`, `js-yaml` with `argparse`, and `typescript`, whose parser the `code`
source reads JavaScript and TypeScript with). It holds no TypeScript source, no
compiler step at start and no package manager: `npm`, `npx`, `corepack` and
`yarn` are removed. The base image is `node:24-alpine`, pinned by digest, so
the image does contain a shell (BusyBox); starting the scanner does not use it.

- User: `node` (uid 1000). Nothing under `/app` is writable by it.
- Entrypoint: `node /app/packages/scanner/dist/cli.js`, in exec form, so `node`
  is PID 1 and receives the signal `docker stop` sends.
- Default command: `schedule --config /etc/scanent/config.json`.
- The scanner writes only under the file output's directory. Run it with a
  read-only root filesystem, every capability dropped and no privilege gain,
  and mount that directory as the one writable volume (`-v <host dir>:/out`,
  writable by the user the container runs as: uid 1000, or the one given with
  `--user`) when the file output is used. Keep that directory private to its
  owner: the runs are evidence, and a directory every local user can write
  lets any of them replace a run or the pointer:

```bash
docker run --rm \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -e SCANNER_SIGNING_KEY -e INFLECT_INGEST_KEY \
  -v /path/to/config-dir:/etc/scanent:ro \
  scanent
```

Mount the configuration directory read-only, and each `code` root read-only at
the path the configuration names. Secrets are passed as environment variables
whose names the configuration gives, or as mounted files named by
`<NAME>_FILE` ([Secrets from files](#secrets-from-files)); none is in the
image. The image sets `NODE_USE_ENV_PROXY=1`, so `HTTPS_PROXY` and `NO_PROXY`
take effect when they are set
([Proxy and certificate authority](#proxy-and-certificate-authority)).

`deploy/smoke.sh <image>` is the image's smoke test. It builds nothing. It
runs the image with those flags and no network, and checks the user, the
absence of package managers and TypeScript source, `public-key`, a dry-run
scan of a two-agent estate verified inside the image through the image's own
contract module (`deploy/smoke-verify.js`), that a scan with nowhere to
post exits non-zero, and that `scan --dry-run --out /out` on the read-only
root with one writable mount writes the six files of a run and that a second
run leaves the first as it was. It then runs as the invoking user (`--user`,
or `--userns=keep-id` with `CONTAINER_RUNTIME=podman`) into an output
directory of mode 0700 and reads the run back without the container, gives the
signing key as a mounted file, runs `init --answers` and `doctor` on what it
wrote, and `hosts` on a code-only configuration. CI runs it, followed by a
Trivy scan that fails on a fixed CRITICAL or HIGH vulnerability.

Compose, the Helm chart and the air-gapped bundle are described in
[deployment.md](deployment.md); a first run at a site is
[quick-start.md](quick-start.md).
