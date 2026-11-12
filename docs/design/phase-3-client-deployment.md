# Phase 3: client deployment

Design note for P3.1 to P3.5: the setup wizard, the preflight, secret files,
proxy and certificate-authority support, the exit codes, and the packaging
(Compose, Helm, the air-gapped bundle, the multi-arch release).

It is written to be built from without further questions. Where a choice is the
owner's, section 12 lists it with the default this note builds.

## 0. Decisions in one table

| # | Question | Decision |
|---|---|---|
| 1 | How the wizard is driven | One pure planner (`planInit(answers)`), two front ends: prompts over `node:readline`, and `--answers <file>` (strict JSON). Both produce the same answers object |
| 2 | What `init` writes | `config.json` (0600), `scanent.env` (0600, NAMES with empty values), and, unless told not to, a signing key (0600). Never overwrites without `--force` |
| 3 | Signing key | `scanent keygen --out <file>`; `init` calls the same function. No `openssl` needed for a first run |
| 4 | Secret files | `NAME_FILE` beside `NAME`, for the names the configuration gives and no other. Both set is an error. One trailing newline removed. 64 KiB cap. A world-readable file is accepted; a world-writable one is refused |
| 5 | Proxy | Node's own environment proxy (`NODE_USE_ENV_PROXY=1`, set in the image). No new dependency. The host guard is unchanged and is never skipped for a proxied host |
| 6 | Custom CA | `NODE_EXTRA_CA_CERTS` only: a mounted file, additive. No configuration key. `NODE_TLS_REJECT_UNAUTHORIZED=0` is refused |
| 7 | `doctor` requests | Only requests already in `scanner-surface.ts`. The manifest hash does not change in this phase |
| 8 | Write-access warning | Only where a declared read reveals it: Entra (token roles) and GitHub classic tokens (`X-OAuth-Scopes`). Everywhere else the check is `SKIPPED` with reason `NOT_OBSERVABLE`, never `PASS` |
| 9 | Exit codes | 0, 1 and 2 keep their meaning. New: 3 incomplete, 4 configuration, 5 credential, 6 network. `scan` returns 3 only with `--strict` |
| 10 | NetworkPolicy | Default: DNS plus TCP 443 to public addresses. Exact hosts through an optional Cilium FQDN policy or the bundled egress proxy. The limit is stated in the chart and the docs |
| 11 | Hosts for a policy | A new offline command, `scanent hosts --config <file>`, derives them from the declared surface and the configuration |
| 12 | Chart and secrets | `existingSecret` only. The chart has no value that can hold a secret, and its schema refuses unknown keys |
| 13 | Release | Tag builds on native amd64 and arm64 runners, one manifest, pushed to `ghcr.io/rodnapamet/scanent`. No signing, SBOM or provenance yet (Phase 4) |
| 14 | New run-time dependency | None |

## 1. What exists today, and what this phase must not break

Read before building; each line is a constraint.

- The configuration is strict JSON holding environment variable NAMES
  (`config.ts`). `parseScannerConfig` refuses a secret-shaped string anywhere,
  by path. Sources read `env[name]` and `.trim()` it (`scan.ts`).
- Every request goes through `createSourceWire` (`http.ts`): GET-only reader,
  token exchange, MCP listing, register read. `fetchImpl` defaults to the
  global `fetch`. Nothing in the wire reads a proxy variable.
- Customer-named hosts (self-hosted LangSmith, MCP servers) are checked at
  configuration and re-resolved with `dns.lookup` before every request
  (`customer-host.ts`). Hosts fixed by kind are not resolved by the scanner.
- `egress-proof.ts` already expects `HTTPS_PROXY` and `NODE_USE_ENV_PROXY=1`
  when the configuration has an `egress` block. `egress-proxy.ts` is a
  CONNECT-only proxy with an exact-hostname allowlist, shipped in the image.
- Pinned exit codes (tests in `cli.test.ts`, `cli-out.test.ts`,
  `diff-command.test.ts`): 0 delivered; 1 an output failed or the command
  threw (including a missing signing key on `public-key`); 2 usage, unknown
  flag, nowhere to deliver; `diff` 0/1/2/3.
- `tests/outputs.test.ts` pins `scannerManifestHash()` to its value before
  outputs existed. It must still pass unchanged at the end of this phase.
- The image is `node:24-alpine` by digest, user `node` (uid 1000), exec-form
  entrypoint. `image.test.ts` holds `.dockerignore` to the `COPY` lines.

## 2. `scanent init` (P3.1)

### 2.1 Command

```
scanent init [--dir <dir>] [--answers <file>] [--force] [--no-keygen] [--print-access]
```

| Flag | Meaning |
|---|---|
| `--dir <dir>` | Where the files are written. Absolute, no `..`. Default: `./scanent` resolved against the working directory |
| `--answers <file>` | Non-interactive: read the answers from a JSON file. No prompt is shown. Without it, and when stdin is not a terminal, `init` exits 2 and says to pass `--answers` |
| `--force` | Replace existing `config.json` and `scanent.env`. Never replaces a signing key (see 2.5) |
| `--no-keygen` | Do not create a signing key; the env template then lists `SCANNER_SIGNING_KEY_FILE=` empty |
| `--print-access` | Print the access tables for the chosen sources and write nothing |

`init` makes no network request and reads no credential.

### 2.2 The answers object

Schema id `scanent-init-answers/1`, strict (unknown key refused), in
`packages/scanner/src/init/answers.ts`:

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
    { "kind": "vault", "vaultUrls": ["https://acme-agents.vault.azure.net"], "directoryTenantId": "<id>", "clientId": "<guid>" },
    { "kind": "cicd", "repositories": ["acme/payments-api"] },
    { "kind": "gcp-sa", "projects": ["acme-prod"] },
    { "kind": "runtime", "endpoint": { "cloud": "eu" }, "workspaceId": "<guid>" },
    { "kind": "code", "roots": [{ "label": "support-bot", "path": "/estate/support-bot" }] },
    { "kind": "mcp", "servers": [{ "label": "crm", "url": "https://mcp.acme.example/crm/mcp", "readToken": true }] }
  ],
  "inflect": null
}
```

Rules:

- `sources` holds one to eight entries, each kind once. `product` is filled
  by the planner (each kind has one product). Optional fields of the source's
  configuration schema are accepted with the same names and pass through.
- Environment variable names are not asked for. The planner assigns the
  documented defaults: `ENTRA_CLIENT_SECRET`, `OKTA_API_TOKEN`,
  `AZURE_CLIENT_SECRET`, `GITHUB_READ_TOKEN`, `GCP_SCANNER_KEY`,
  `LANGSMITH_API_KEY`, `MCP_<LABEL>_TOKEN` (label upper-cased, `-` to `_`),
  `SCANNER_SIGNING_KEY`, `INFLECT_INGEST_KEY`. An answers file may override one
  with `"<field>Env": "NAME"`; it is held to the configuration's name pattern.
- `outputDir` defaults to `/out`; `everyHours` to 24; `retainRuns` and
  `inventoryPath` are optional.
- `inflect` is `null` (the default) or
  `{ "baseUrl", "tenantSlug", "agentId", "readRegister": false }`. When set,
  the planner adds the `inflect` block, the `inflect` output beside the file
  output, and the `inflect-register` source when `readRegister` is true. When
  null, `scanner.agentId` is `scanent-<estate>` cut to 64 characters.
- The `inflect-register` source cannot be listed in `sources`; it comes only
  from `inflect.readRegister`.

### 2.3 The planner

`planInit(answers): InitPlan` in `init/plan.ts`. Pure: no file, clock or
environment access.

```ts
interface InitPlan {
  readonly config: ScannerConfig;          // parsed through parseScannerConfig
  readonly configText: string;             // JSON, two-space indent, trailing newline
  readonly envTemplate: string;            // see 2.4
  readonly credentialNames: readonly { name: string; file: boolean; for: string }[];
  readonly access: readonly AccessTable[]; // see 2.6, one per chosen source
  readonly nextSteps: readonly string[];
}
```

It builds the configuration object, then passes it through
`parseScannerConfig`, so what `init` writes is by construction a file `scan`
accepts, and the secret-shape refusal runs over every answer. A failure is an
`InitError` carrying the configuration's issue paths, never a value.

### 2.4 The env template

`scanent.env`, one line per credential the configuration names, in the order
of `credentialEnvNames(config)`. Values are empty. Multi-line credentials use
the file form, because an env file cannot carry a line break:

```
# scanent credentials. Fill in each value, or use a secret store.
# This file is read by `docker run --env-file` and by Compose. Keep it 0600.

# The Ed25519 signing key (PKCS#8 PEM). A file, because a PEM has line breaks.
SCANNER_SIGNING_KEY_FILE=/etc/scanent/signing-key.pem

# Entra: client secret of the application holding Application.Read.All.
ENTRA_CLIENT_SECRET=

# Google Cloud: the service-account key file (JSON). A file, for the same reason.
GCP_SCANNER_KEY_FILE=
```

- The signing key and the Google key default to the `_FILE` form
  (`file: true`). Every other credential defaults to the plain form.
- The one non-empty value `init` writes is the signing key's path, and only
  when `init` created the key. A path is not a secret. It is the path the
  container sees (`/etc/scanent/signing-key.pem`) when `--dir` is going to be
  mounted there, which is what the printed next steps say.
- A test asserts that every line of the template that is not a comment matches
  `^[A-Z][A-Z0-9_]*=(/[^\s]*)?$`: a name, then nothing or a path.

### 2.5 Writing

`writeInit(plan, dir, { force, keygen })` in `init/write.ts`:

1. Create `dir` with mode `0700` if absent. Refuse a `dir` that is a symbolic
   link.
2. For `config.json` and `scanent.env`: open with `O_WRONLY | O_CREAT | O_EXCL`
   and mode `0600`. If the file exists: without `--force`, stop before writing
   anything, exit 2, naming the file; with `--force`, write to a temporary
   name in the same directory (`O_EXCL`, `0600`) and rename over it.
3. The existence check for both files happens before either is written, so a
   refused run writes nothing.
4. The signing key (`signing-key.pem`): created only when absent, by
   `generateSigningKey` (section 3). An existing key is never replaced, with
   or without `--force`: replacing it silently would orphan every earlier
   report's signature. `init` prints that it kept the existing key.
5. `chmod` each written file to its mode after writing, so a permissive umask
   does not matter and a restrictive one is not loosened.

### 2.6 The access tables

One module, `init/access-guide.ts`, exports `ACCESS_GUIDE: Record<kind, AccessTable>`:

```ts
interface AccessTable {
  readonly kind: SourceKind;
  readonly title: string;
  readonly grant: string;          // the role or scope, exactly as the product names it
  readonly where: readonly string[];   // the steps to create it
  readonly reads: readonly string[];   // what it lets the scanner read
  readonly notNeeded: readonly string[]; // what must not be granted
  readonly credential: string;     // the variable it goes in
  readonly hosts: readonly string[];   // from hostsFor (section 6.4)
}
```

The content, taken from the source implementations and `docs/scanner.md`:

| Source | Grant | Where it is created | Lets the scanner read | Not needed |
|---|---|---|---|---|
| `entra-sp` | Microsoft Graph application permission `Application.Read.All`, with admin consent | Entra admin centre: App registrations, new registration; API permissions, add, Microsoft Graph, Application permissions; grant admin consent; Certificates and secrets, new client secret | Application registrations and service principals, their credential metadata (ids, dates) and owners | Any `ReadWrite` permission, `Directory.*`, any delegated permission, any directory role |
| `vault` | `Key Vault Reader` on each listed vault (RBAC vaults). For a vault on access policies: List on secrets and List on certificates, and nothing else | Each vault: Access control (IAM), add role assignment, to the application's service principal | Names, tags and dates of secrets and certificates | `Key Vault Secrets User`, `Key Vault Administrator`, Get on secrets: each reads or changes secret values |
| `okta-app` | An SSWS API token created by a user holding the Read-only Administrator role only | Okta admin console: Security, Administrators (assign the role to a dedicated user); signed in as that user: Security, API, Tokens, Create token | Service apps, API token metadata, the token's own id | Super, Org, App or API Access Management administrator roles |
| `cicd` | A fine-grained personal access token (or a GitHub App installation) limited to the listed repositories, with Contents: Read-only and Secrets: Read-only. Metadata: Read-only is added by GitHub | GitHub: Settings, Developer settings, Fine-grained tokens; Repository access: only select repositories | Workflow files on the default branch, and the names of Actions secrets | Any Read and write permission, Actions, Administration, Workflows; a classic token with `repo` |
| `gcp-sa` | `roles/iam.serviceAccountViewer` on each listed project, held by a dedicated service account; one JSON key for that account | Google Cloud console: IAM and admin, Service accounts, create; IAM, grant access on each project; Keys, add key, JSON | Service accounts and the metadata of their user-managed keys | `roles/iam.serviceAccountAdmin`, `serviceAccountKeyAdmin`, `serviceAccountUser`, `serviceAccountTokenCreator`, Editor, Owner |
| `runtime` (LangSmith) | A service key holding the workspace Viewer role | LangSmith: Settings, API keys, create a service key, role Viewer | Tracing projects and their aggregate tool statistics; deployments only when `readDeployments` is set | Editor or Admin role; a personal access token of an administrator |
| `mcp` | Per server, a token that can list tools and nothing else; none when the server takes none | The server's own administration | Tool names, annotations and definitions (kept as hashes) | Any scope that lets the token call a tool |
| `code` | Read access to the listed directories for the user the scanner runs as | The file system or the read-only mount | Python, JavaScript and TypeScript files under the roots | Write access; mount the roots read-only |
| `inflect-register` and the `inflect` output | An API key bound to the scanner agent with `admin:harness_ingest`, plus `mcp:read` when the register is read | The Inflect tenant's API keys page | The tenant's agent register, through one tool | Any other scope |

Each printed table ends with the hosts the source reaches, from `hostsFor`
(section 6.4), so the same run tells the network team what to open.

`docs/access.md` is the same content as Markdown, generated by
`npm run docs:access` (`scripts/render-access.js`, which requires the compiled
module). A test renders it in memory and compares it with the committed file,
so the wizard and the document cannot disagree.

### 2.7 The prompts

`init/prompts.ts` exports `collectAnswers(io): Promise<InitAnswers>` where

```ts
interface PromptIo {
  ask(question: string): Promise<string>;   // one line, without the newline
  say(text: string): void;
}
```

The command line builds `io` from `node:readline/promises` on stdin and
stderr (stdout stays clean for `--print-access`). The tests pass a scripted
`io`. Order: estate name; then, for each kind in a fixed order, "Do you have
X? [y/N]"; for each yes, that source's fields; output directory; schedule;
inventory; Inflect ("Post results to an Inflect tenant? [y/N]", default no).

Every answer:

1. is passed to the contract's `looksLikeSecret`. A hit is refused with
   "That looks like a credential. It was not stored. scanent never asks for a
   secret value; if it was real, rotate it." and the question is asked again.
   The answer is not echoed by scanent, written or logged. After three
   refusals of one question `init` exits 2.
2. is validated by the field's own schema (the same zod schema the
   configuration uses); an invalid answer repeats the question with the rule,
   never the value.

No question asks for a secret, and no question's wording could be read as
asking for one: the Entra prompt asks for "the application (client) ID", and
the next line printed is "The client secret is not asked for here: it goes in
ENTRA_CLIENT_SECRET."

The terminal echoes what a person types; scanent cannot undo that. This is why
the refusal tells the person to rotate.

### 2.8 Output

On success `init` prints, to stderr: the files written and their modes; the
signing key's public half (hex), with "register this only if you post to a
tenant"; the access table for each chosen source; and the next steps:

```
1. Create the access above and put each credential in scanent.env (or your secret store).
2. scanent doctor --config <dir>/config.json
3. scanent scan --config <dir>/config.json --out <outputDir>
```

Exit codes: 0 written; 2 usage, a refused overwrite, or stdin is not a
terminal with no `--answers`; 4 the answers file is unreadable, not JSON,
fails its schema, or holds a secret-shaped string (named by path).

## 3. `scanent keygen`

```
scanent keygen --out <file>
```

`generateSigningKey(path)` in `keygen.ts`: `crypto.generateKeyPairSync('ed25519')`,
exported as PKCS#8 PEM, written with `O_WRONLY | O_CREAT | O_EXCL`, mode
`0600`. It prints the raw public key in hex on stdout (what `public-key`
prints) and the path on stderr. It never prints the private key and has no
option to. An existing file is refused, exit 2; there is no overwrite flag.

Why not document `openssl`: a first run then needs a second tool, and the
obvious way to pass its output (`-e SCANNER_SIGNING_KEY="$(openssl …)"`) does
not survive an env file. With `keygen` and `SCANNER_SIGNING_KEY_FILE` the
first run is `init`, fill in credentials, `doctor`, `scan`. The README keeps
the `openssl` line as an alternative.

A standalone user still signs: the signature is what lets `diff` and a later
reader show a report was not altered. The public half needs registering only
with a tenant.

## 4. Secrets from files (P3.3)

### 4.1 Rule

For each name `N` in `credentialEnvNames(config)`, and for no other variable:

| `N` | `N_FILE` | Result |
|---|---|---|
| set, non-empty | unset | the value of `N`, as today |
| unset or empty | set | the content of the file `N_FILE` names |
| set, non-empty | set | refused: `SecretFileError` `BOTH_SET`, naming `N` |
| unset or empty | unset | absent, as today (a source reports `AUTH_FAILED`; a missing signing key stops the run) |

Refusing both rather than choosing: a precedence rule means one of two
credentials is silently ignored, and the one ignored may be the one somebody
just rotated.

### 4.2 Reading a file

`resolveSecretEnv(config, env, fsImpl?) → Env` in `secrets.ts`:

- The path must be absolute with no `..` segment and no control character
  (`FILE_PATH`).
- `stat` (following links: a Kubernetes secret file is a link into `..data`).
  It must be a regular file (`NOT_A_FILE`), at most 64 KiB (`TOO_LARGE`;
  the largest real credential, a Google key file, is under 3 KiB), and not
  writable by others, mode bit `0o002` (`WORLD_WRITABLE`).
- Read as UTF-8. Remove exactly one trailing `\n` or `\r\n`. An empty result
  is `EMPTY`. A NUL byte is `NOT_TEXT`.
- A read error is `UNREADABLE` with the errno code (`ENOENT`, `EACCES`).

A world-readable file is accepted. Docker mounts a secret `0444` by default,
and Kubernetes `0644`, inside a mount only that container sees; refusing
those modes would refuse the two platforms the feature exists for. The
protection there is the mount, not the mode. `doctor` warns when a secret file
is group- or world-readable and is not under `/run/secrets/` or
`/var/run/secrets/` (section 5.4), which is the case where the mode is the
only protection.

A world-writable file is refused because any local user could replace the
signing key or point a token at their own.

`SecretFileError` carries the variable name and the reason code. Its message
never contains the file's content, and contains the path only as the operator
wrote it in their own environment.

### 4.3 Where it is called

Once, in `cli.ts`, for `scan`, `schedule`, `public-key` and `doctor`, after
the configuration is parsed:

```ts
const resolved = resolveSecretEnv(config, env);   // throws SecretFileError → exit 4
```

The result is a copy of `env` with each `N` filled in; `scan.ts`, the sources
and `outputs.ts` are not changed and never learn where a value came from. The
proxy variables and everything else pass through untouched. `schedule`
resolves once at start: a rotated secret file takes effect at the next start,
which the documents say.

`resolveSecretEnv` is exported from the package entry; `public-entry.test.ts`
pins the export list exactly, and that list grows by the new names (stated in
the commit).

## 5. `scanent doctor` (P3.2)

### 5.1 Command

```
scanent doctor --config <file> [--json] [--out <dir>] [--source <kind>]…
```

`--out` checks that directory instead of (or in the absence of) the
configuration's file output. `--source` limits the source checks to the kinds
named; local checks always run. `doctor` writes nothing anywhere: no report,
no file, no post. It reads the same credentials `scan` would.

### 5.2 Result model

`doctor/types.ts`:

```ts
type CheckStatus = 'PASS' | 'WARN' | 'FAIL' | 'SKIPPED';
type SkipCause = 'NOT_APPLICABLE' | 'BLOCKED' | 'NOT_OBSERVABLE';
type FailClass = 'CONFIG' | 'CREDENTIAL' | 'NETWORK';

interface Check {
  readonly scope: string;        // 'local' or a source kind; an MCP server is 'mcp:<label>'
  readonly id: string;           // e.g. 'credential.present'
  readonly status: CheckStatus;
  readonly cause?: SkipCause;    // with SKIPPED, always
  readonly class?: FailClass;    // with FAIL, always
  readonly detail: string;       // what was found: kinds, counts, role names. Never a value
  readonly fix?: string;         // with WARN and FAIL, always: one sentence
}
```

Rules that hold the honesty of it, each with a test:

- A check is `PASS` only when the thing it names was observed. There is no
  default status; the runner's type makes every branch state one.
- A check whose prerequisite failed is `SKIPPED` `BLOCKED`, naming the
  prerequisite. It is never left out and never `PASS`.
- A check the declared surface cannot answer is `SKIPPED` `NOT_OBSERVABLE`,
  with the reason and what to verify by hand.
- The summary line counts each status. It says "ready" only when there is no
  `FAIL`, no `WARN` and no `BLOCKED`. It never says "all checks passed" unless
  every check is `PASS`; otherwise it says how many were not checked.
- `detail` and `fix` are built from fixed strings, the configuration's own
  names, status codes, counts and role or scope names. A unit test runs every
  fake's secret markers and tokens through a full doctor run and asserts none
  appears in the table or the JSON.

### 5.3 Source checks

Each source gets the same six checks, in order. A source's probe lives in its
own file as a second method on the interface, so a new source cannot ship
without one:

```ts
interface HarnessSource {
  readonly kind: SourceKind;
  readonly product: string;
  read(ctx: SourceContext): Promise<SourceRead>;
  preflight(ctx: SourceContext): Promise<readonly ProbeStep[]>;   // new, required
}
```

`ProbeStep` is `{ id, outcome: 'ok' | SourceReadError, observed?: {...} }`;
`doctor/run.ts` turns steps into `Check`s. `SourceReadError` gains an optional
third constructor argument, `status?: number`, set by `http.ts` where it knows
the HTTP status. Nothing else about the error changes, and the report builder
does not read it.

| Check id | PASS when | Otherwise |
|---|---|---|
| `credential.present` | the variable (or its file) resolves to a non-empty value | `FAIL` `CREDENTIAL`: "Set `N` or `N_FILE`." |
| `host.resolves` | customer-named host: `assertResolvesReachable` accepts it. Fixed host, direct: `dns.lookup` returns an address | Fixed host behind a proxy: `SKIPPED` `NOT_APPLICABLE` ("resolved by the proxy"). Refused or not resolving: `FAIL` `NETWORK` |
| `reachable` | the first declared request got any HTTP answer | `UNREACHABLE` or `TIME_BOX` with no answer: `FAIL` `NETWORK`. The fix names the host and, when a proxy is in effect, the proxy |
| `authenticated` | the token exchange succeeded, or the first read was not 401 | 401, or a refused exchange: `FAIL` `CREDENTIAL` |
| `read.permitted` | every probe read in the table below returned 2xx | 403: `FAIL` `CREDENTIAL`, with the grant from `ACCESS_GUIDE`. 429: `SKIPPED` `BLOCKED` ("rate limited; run again later") |
| `write.absent` | see the last column | `WARN`, or `SKIPPED` `NOT_OBSERVABLE` |

The probe reads. Every one is a request the source's `read` already makes,
with the smallest page the API allows; `doctor` stops after the first page.

| Source | Requests, in order | What reveals write access |
|---|---|---|
| `entra-sp` | token exchange (Graph scope); `GET /v1.0/applications?$top=1&$select=id`; `GET /v1.0/servicePrincipals?$top=1&$select=id` | The access token is a JWT whose `roles` claim lists the application permissions granted. Decode the payload (base64url, no verification: it is our own token and the result is advice). `PASS` when `roles` is exactly `Application.Read.All`. `WARN` naming each role that matches `/ReadWrite|Write|FullControl|Manage|AccessAsUser/`; other extra roles are listed in `detail` under `PASS`. A token that does not decode: `SKIPPED` `NOT_OBSERVABLE` |
| `vault` | token exchange (vault scope); per vault `GET /secrets?maxresults=1&api-version=…` and `GET /certificates?maxresults=1&api-version=…` | Not observable: the data-plane token carries no role, and reading role assignments is a management-plane request the scanner does not declare. `SKIPPED` `NOT_OBSERVABLE`: "Confirm in the vault's Access control that the application holds Key Vault Reader only." |
| `okta-app` | `GET /api/v1/api-tokens/current`; `GET /api/v1/apps?limit=1&filter=…` | Not observable: the token's administrator role is read from `/api/v1/users/{id}/roles`, which is not declared. `SKIPPED` `NOT_OBSERVABLE` |
| `cicd` | per repository `GET /repos/{owner}/{repo}`; `GET …/contents/.github/workflows` (`absentOk`); `GET …/actions/secrets?per_page=1` | `GET /repos/…` answers with an `X-OAuth-Scopes` header for a classic token. Present: `WARN` when it holds `repo`, `workflow`, `admin:…`, `write:…` or `delete_repo` (a classic token cannot be read-only for private repositories), naming the scopes. Absent (a fine-grained or installation token): `SKIPPED` `NOT_OBSERVABLE`; the response's `permissions` object describes the token's owner, not the token, and is not used |
| `gcp-sa` | (local) the key JSON parses and signs; JWT-bearer exchange; per project `GET /v1/projects/{project}/serviceAccounts?pageSize=1` | Not observable: `testIamPermissions` is a POST the wire cannot send. `SKIPPED` `NOT_OBSERVABLE` |
| `runtime` | `GET /api/v1/sessions?limit=1` (with the source's filter parameters); with `readDeployments`, the deployments listing with `limit=1` | Not observable. `SKIPPED` `NOT_OBSERVABLE` |
| `mcp` | per server: `open` (`initialize`, `notifications/initialized`), one `tools/list` page | Not observable. `SKIPPED` `NOT_OBSERVABLE`. Each server is its own scope, `mcp:<label>`, so one failing server does not hide the others |
| `inflect-register` | `register.read` (the exchange, the handshake, the one tool call) | Not observable from the register read. `SKIPPED` `NOT_OBSERVABLE` |
| `code` | `lstat` each root; `readdir` its top level | `credential.present`, `host.resolves`, `reachable` and `authenticated` are `SKIPPED` `NOT_APPLICABLE`. `read.permitted` passes when each root is a directory, not a link, and listable. `write.absent`: `WARN` when `access(W_OK)` succeeds on a root ("mount it read-only"), else `PASS` |

`doctor` never sends a write to test for one. The Inflect ingest is the one
place a credential's use is a write (the POST of a report), so for the
`inflect` output `doctor` checks that the key is present and reports
`read.permitted` as `SKIPPED` `NOT_OBSERVABLE`: "doctor does not post; the
first `scan` shows whether the key may post."

Each source probe runs in its own wire (`createSourceWire`) with a 30-second
deadline and a 1 MiB source budget, in parallel, exactly as `runScan` builds
them. Every request therefore keeps the origin pin, the redirect refusal and
the byte cap.

The Entra token leaves `tokens.clientCredentials` as a string and is decoded
inside `entra.ts`'s `preflight`; only the role names leave that function.

### 5.4 Local checks (scope `local`)

| Check id | PASS when | Otherwise |
|---|---|---|
| `config.valid` | the file parses under the strict schema | `FAIL` `CONFIG` with the issue paths. Every later check is `SKIPPED` `BLOCKED` |
| `config.mode` | the file is not writable by group or others | `WARN`: "chmod 0600" |
| `signing-key` | the key resolves, parses as PKCS#8 and is Ed25519; `detail` is the public key in hex | Missing: `FAIL` `CREDENTIAL`. Wrong type or unparseable: `FAIL` `CONFIG` |
| `secret-files` | every `_FILE` in use passes section 4.2 | A refusal: `FAIL` `CONFIG` with the reason code. Group- or world-readable outside `/run/secrets/` and `/var/run/secrets/`: `WARN` |
| `output.dir` | the directory exists, is a directory and not a link, and `access(W_OK \| X_OK)` succeeds; or it is absent and its parent passes the same test. `detail` says "by permission; nothing was written" | Not writable: `FAIL` `CONFIG`, naming the uid the process runs as. Writable by others (`0o002`): `WARN` (the runs are evidence). No file output in effect: `SKIPPED` `NOT_APPLICABLE` |
| `inventory` | `loadConfiguredInventory` accepts the file; `detail` is the row count | Refused: `FAIL` `CONFIG` with its row and field. Not configured: `SKIPPED` `NOT_APPLICABLE` |
| `tls.verification` | `NODE_TLS_REJECT_UNAUTHORIZED` is not `0` | `FAIL` `CONFIG`: "Remove it; add your CA with NODE_EXTRA_CA_CERTS." |
| `tls.extra-ca` | `NODE_EXTRA_CA_CERTS` is unset (`SKIPPED` `NOT_APPLICABLE`), or names a readable file holding at least one `-----BEGIN CERTIFICATE-----` | `FAIL` `CONFIG` |
| `proxy` | no proxy variable is set (`SKIPPED` `NOT_APPLICABLE`); or `HTTPS_PROXY` parses as an `http:` or `https:` URL and `NODE_USE_ENV_PROXY` is `1` and the Node version honours it (22.21 or later) | `HTTPS_PROXY` set without `NODE_USE_ENV_PROXY=1`, or on an older Node: `FAIL` `NETWORK` ("requests would not use the proxy"). `detail` is the proxy's host and port only, never its userinfo |
| `proxy.customer-hosts` | no customer-named host is proxied | `WARN` per host that is not in `NO_PROXY`: "The address check binds this machine's resolver, not the proxy's. Add the host to NO_PROXY if it is on your network." |
| `clock` | at least one probe response carried a `Date` header, and the largest difference from the local clock is under 60 seconds | 60 to 300 seconds: `WARN`. Over 300: `FAIL` `CONFIG` (token exchanges and signed assertions fail). No `Date` seen (a configuration with no network source, or every probe failed): `SKIPPED` `NOT_OBSERVABLE` |
| `egress` | no `egress` block (`SKIPPED` `NOT_APPLICABLE`); or `proveEgress` reports met | `FAIL` `NETWORK` with the proof's failure code |

`clock` uses the `Date` header `getJson` already returns; it adds no request.
`egress` runs the existing proof, whose three connections are declared in
`provesEgress`.

### 5.5 Output

Text (default), on stdout; the log stays on stderr:

```
scanent doctor  estate acme-prod  2026-11-12T09:00:00Z

local
  PASS     config.valid         9 sources
  PASS     signing-key          ed25519 3f9a…(64 hex)
  WARN     output.dir           /out is writable by other users
           fix: chmod 0700 /out
entra-sp
  PASS     credential.present   ENTRA_CLIENT_SECRET
  PASS     reachable            graph.microsoft.com
  PASS     authenticated
  PASS     read.permitted       2 reads
  WARN     write.absent         the token also holds Application.ReadWrite.All
           fix: Remove Application.ReadWrite.All; the scanner needs Application.Read.All only.
okta-app
  …
  SKIPPED  write.absent         not observable: confirm the token's user is a Read-only Administrator

14 passed, 2 warnings, 0 failed, 5 not checked (5 not observable). Not ready: fix the warnings or accept them.
```

Every scanned or configured string printed goes through the terminal escaper
`diff` uses (control characters and bidirectional controls shown as
`\u{..}`).

`--json` prints one document, schema `scanent-doctor/1`:

```json
{
  "doctor": "scanent-doctor/1",
  "estate": "acme-prod",
  "at": "2026-11-12T09:00:00.000Z",
  "scanner": { "version": "0.12.0", "manifestHash": "sha256:…" },
  "ready": false,
  "counts": { "PASS": 14, "WARN": 2, "FAIL": 0, "SKIPPED": 5 },
  "exitCode": 3,
  "checks": [ { "scope": "local", "id": "config.valid", "status": "PASS", "detail": "9 sources" } ]
}
```

### 5.6 Exit code

The first row that applies:

| Code | When |
|---|---|
| 2 | usage |
| 4 | the configuration could not be read or parsed, or any `FAIL` of class `CONFIG` |
| 5 | any `FAIL` of class `CREDENTIAL` |
| 6 | any `FAIL` of class `NETWORK` |
| 3 | no `FAIL`, and at least one `WARN` or one `SKIPPED` `BLOCKED` |
| 0 | none of the above: every check is `PASS`, or `SKIPPED` as `NOT_APPLICABLE` or `NOT_OBSERVABLE` |

`NOT_OBSERVABLE` does not change the exit code, because no rerun can turn it
into a `PASS`; it is always shown and always counted as not checked.

## 6. Proxy, certificate authority and the host guard (P3.3)

### 6.1 What the wire does today

Nothing. `fetch` ignores `HTTPS_PROXY` unless Node is started with
`NODE_USE_ENV_PROXY=1` (Node 24, and 22.21 or later), and trusts Node's
bundled authorities plus `NODE_EXTRA_CA_CERTS`. On a network whose only exit
is a proxy every source is `UNREACHABLE`; behind TLS inspection every source
is `UNREACHABLE` too, with no hint why.

### 6.2 Proxy

- The image sets `ENV NODE_USE_ENV_PROXY=1`. With no proxy variable set it
  changes nothing. From source, the operator sets it; `doctor`'s `proxy` check
  fails when `HTTPS_PROXY` is set without it.
- No proxy library and no dispatcher: the scanner's import rule (Node
  built-ins, `zod`, `typescript`, `js-yaml`, the contract) stands, and
  `undici` is not a built-in.
- `HTTPS_PROXY`, `https_proxy`, `NO_PROXY`, `no_proxy` are honoured as Node
  honours them. `HTTP_PROXY` is irrelevant: every request is https.
- The proxy URL may carry userinfo. It is the operator's environment, where
  credentials live. scanent never logs or prints it: `proxy-env.ts` exposes
  `describeProxy(env) → { host, port, scheme } | null` and nothing else.
- `proxy-env.ts` also exports `isProxied(hostname, env): boolean`, a pure
  matcher of `NO_PROXY` (exact name, a leading-dot or bare suffix, `*`, an
  optional port). It is used only for `doctor`'s wording. It decides nothing
  about a request; Node does. A table test holds it to Node's documented
  rules.

### 6.3 The host guard is not weakened

`assertResolvesReachable` runs before every request to a customer-named host,
proxied or not. Nothing in this phase adds a way to skip it.

Two consequences, both documented and both reported by `doctor`:

- A customer-named host on the estate's own network belongs in `NO_PROXY`. It
  is then reached directly, and the guard's answer is about the connection
  that is made, as today.
- A customer-named host reached through the proxy is still resolved locally
  first. If the local resolver cannot resolve it, the read is `UNREACHABLE`
  and the fix is `NO_PROXY` or a resolver that can. If it resolves, the check
  passes on the local answer while the proxy resolves again on its own. That
  gap is the existing residual (the scanner does not pin the connection to the
  checked address) with a second resolver in it. It is recorded in
  `customer-host.ts`'s header and raised by `proxy.customer-hosts`.

The literal-address and blocked-name rules at configuration time do not depend
on the proxy and are unchanged.

### 6.4 `scanent hosts`

```
scanent hosts --config <file> [--format lines|json|egress-allow]
```

Offline and pure: `hostsFor(config): HostEntry[]` in `hosts.ts`, where
`HostEntry` is `{ host, port: 443, source, purpose: 'read' | 'token' | 'ingest', named: 'fixed' | 'configured' }`.

| Source | Hosts |
|---|---|
| `entra-sp` | `login.microsoftonline.com`, `graph.microsoft.com` |
| `vault` | `login.microsoftonline.com`, each vault's host |
| `okta-app` | the org's host |
| `cicd` | `api.github.com` |
| `gcp-sa` | `oauth2.googleapis.com`, `iam.googleapis.com` |
| `runtime` | the cloud host for the region, or the self-hosted host |
| `mcp` | each server's host |
| `inflect-register`, `inflect` output | the `inflect.baseUrl` host |
| `code` | none |

Each fixed host is read from the constant the source exports
(`GRAPH_ORIGIN`, `AZURE_LOGIN_ORIGIN`, `GITHUB_API_ORIGIN`, `GCP_IAM_ORIGIN`,
`GOOGLE_OAUTH_ORIGIN`, `LANGSMITH_CLOUD_ORIGINS`), the same constants
`scanner-surface.ts` is built from. A test runs a scan of every fake and
asserts the set of hosts in the request log equals `hostsFor` of that
configuration, so the list cannot fall behind the code.

`lines` prints `host:443`, sorted, one per line. `egress-allow` prints the
comma-separated value `EGRESS_ALLOW` takes. `json` prints the entries.

### 6.5 Certificate authority

- `NODE_EXTRA_CA_CERTS=/path/to/ca.pem`: a mounted PEM file, added to Node's
  authorities at start. This is the whole mechanism.
- No configuration key. Node reads the variable once, at process start, so a
  key in the file could not be honoured by the process reading it without a
  custom TLS dispatcher, which is the dependency this phase does not take.
- It is additive. There is no switch that turns verification off, and both
  `scan` and `doctor` refuse to run with `NODE_TLS_REJECT_UNAUTHORIZED=0`
  (`scan`, `schedule`: exit 4, one line, before the configuration is read).
  This is new behaviour and a deliberate one: a scanner that sends an estate's
  read credentials must not do it over an unverified connection because a
  variable was left in a shell profile.
- A TLS failure reaches the operator as `UNREACHABLE`. `classifyThrow` in
  `http.ts` gains one branch: when the thrown error's `cause.code` is one of
  Node's certificate codes (`SELF_SIGNED_CERT_IN_CHAIN`,
  `UNABLE_TO_VERIFY_LEAF_SIGNATURE`, `UNABLE_TO_GET_ISSUER_CERT_LOCALLY`,
  `DEPTH_ZERO_SELF_SIGNED_CERT`, `CERT_HAS_EXPIRED`), the message becomes
  "the TLS certificate was not trusted". The reason stays `UNREACHABLE`, so
  the report is unchanged; `doctor` turns that message into the fix "Mount
  your CA and set NODE_EXTRA_CA_CERTS."

## 7. Exit codes across the command line

| Code | Name | Meaning |
|---|---|---|
| 0 | OK | The command did what it was asked. `scan`: every output delivered. `diff`: no difference. `doctor`: ready |
| 1 | FAILED | The command failed: an output was not delivered, the ingest refused the report, or an error with no class of its own. `diff`: a difference |
| 2 | USAGE | Wrong arguments, an unknown flag, nowhere to deliver, a refused overwrite. Nothing was read or written |
| 3 | INCOMPLETE | Nothing failed, and not everything could be established. `scan --strict`: delivered, but a source was `INCOMPLETE` or the scan found no agent. `diff`: could not compare everything. `doctor`: warnings or blocked checks |
| 4 | CONFIG | The configuration, the answers file, the inventory or a secret file was refused; `NODE_TLS_REJECT_UNAUTHORIZED=0` |
| 5 | CREDENTIAL | `doctor`: a credential is missing or refused |
| 6 | NETWORK | `doctor`: a host could not be resolved or reached |
| 130, 143 | | `SIGINT`, `SIGTERM` |

What stays exactly as it is, because tests pin it:

- `scan` without `--strict` returns 0 for a delivered run, complete or not.
  The report, the page and the CSV files say what was incomplete, as today.
- A missing signing key is 1 (`public-key`, `scan`, `schedule`), as is any
  thrown error that is not one of the typed ones below.
- Every existing 2.

What is new:

- `scan --strict` (and `schedule` ignores it: a schedule does not exit):
  after delivery, return 3 when `population.sources` holds an `INCOMPLETE`
  entry or `agents` is empty; a failed output is still 1 and wins.
- `ConfigError`, `SecretFileError`, an inventory refusal, and a configuration
  file that cannot be read or is not JSON return 4 from `main`, with one line
  on stderr naming the paths. Today these surface as 1 through the generic
  handler in `run`. No test pins 1 for them; the implementer confirms that by
  running the suite before and after, and if one does, that case keeps 1 and
  the table says so.

`exit-codes.ts` exports the table as a frozen object; `cli.ts` and
`diff-command.ts` use the names. A test asserts `docs/scanner.md`'s table has
the same rows.

`HELP` grows by the five commands and `--strict`. `USAGE` stays byte for byte.

## 8. Packaging

### 8.1 The one-liner (P3.3)

Documented in the quick start, and held by the smoke test:

```bash
docker run --rm --user "$(id -u):$(id -g)" \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --env-file scanent/scanent.env \
  -v "$(pwd)/scanent:/etc/scanent:ro" \
  -v "$HOME/scanent-out:/out" \
  ghcr.io/rodnapamet/scanent:<version> scan --config /etc/scanent/config.json --out /out
```

Podman: the same line with `--userns=keep-id` in place of `--user`.

### 8.2 `deploy/compose.yaml`

One service, the image's default command (`schedule`):

```yaml
name: scanent
services:
  scanent:
    image: ghcr.io/rodnapamet/scanent:${SCANENT_VERSION:?set SCANENT_VERSION}
    user: "${SCANENT_UID:-1000}:${SCANENT_GID:-1000}"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    restart: unless-stopped
    init: false
    pids_limit: 256
    mem_limit: 1g
    env_file: [./scanent.env]
    environment:
      SCANNER_SIGNING_KEY_FILE: /run/secrets/scanner_signing_key
    secrets: [scanner_signing_key]
    volumes:
      - ./config:/etc/scanent:ro
      - ./out:/out
secrets:
  scanner_signing_key:
    file: ./secrets/signing-key.pem
```

- No `ports`, no `privileged`, no `cap_add`, no host network, no Docker
  socket, no `tmpfs` (the scanner writes only under `/out`).
- Comments in the file show how to add a second file secret and a read-only
  mount for a `code` root, and note that a Compose file secret is a bind
  mount, so the file must be readable by `SCANENT_UID`.
- `deploy/compose.egress.yaml` is an overlay: it adds the `egress-proxy`
  service (same image, `entrypoint: ["node", "/app/packages/scanner/dist/egress-proxy.js"]`,
  same hardening, `EGRESS_ALLOW` from `scanent hosts --format egress-allow`),
  puts `scanent` on an `internal: true` network only, and sets
  `HTTPS_PROXY=http://egress-proxy:3128`.
- `deploy/examples/` holds one configuration per shape: `code-only.json`,
  `cloud-identities.json` (Entra, Key Vault, Okta), `ci-and-cloud.json`
  (GitHub, Google Cloud), `everything.json`, each with its `.env` template as
  `init` would write it.

### 8.3 `deploy/helm/scanent` (P3.4)

```
Chart.yaml            apiVersion v2, type application, appVersion = image tag
values.yaml
values.schema.json    draft-07, additionalProperties: false at every level
templates/_helpers.tpl
templates/configmap.yaml
templates/cronjob.yaml
templates/serviceaccount.yaml
templates/pvc.yaml
templates/networkpolicy.yaml
templates/ciliumnetworkpolicy.yaml
templates/egress-proxy.yaml       Deployment + Service + its NetworkPolicy
templates/NOTES.txt
README.md
```

Values (defaults shown):

```yaml
image:
  repository: ghcr.io/rodnapamet/scanent
  tag: ""                 # defaults to .Chart.AppVersion
  digest: ""              # when set, used instead of the tag
  pullPolicy: IfNotPresent
imagePullSecrets: []

schedule: "17 2 * * *"
timeZone: ""
strict: false             # pass --strict to scan
activeDeadlineSeconds: 1800
history: { successful: 3, failed: 5 }

config: {}                # the scanner configuration, as an object; rendered to config.json
existingConfigMap: ""     # or a ConfigMap holding config.json (and inventory.json)

secrets:
  existingSecret: ""      # required when any credential is listed
  files:                  # each key of the Secret, mounted as a file and named by NAME_FILE
    - { env: SCANNER_SIGNING_KEY, key: signing-key.pem }

output:
  type: pvc               # pvc | existingClaim | emptyDir
  size: 1Gi
  storageClassName: ""
  existingClaim: ""

proxy: { httpsProxy: "", noProxy: "" }
extraCa: { existingConfigMap: "", key: ca.pem }

networkPolicy:
  flavor: kubernetes      # none | kubernetes | cilium
  dns: { namespace: kube-system, podLabels: { k8s-app: kube-dns } }
  extraEgress: []         # [{ cidr: 10.20.0.0/16, port: 443 }] for hosts on private addresses
  proxy: { cidr: "", port: 3128 }   # when set, 443-to-anywhere is replaced by this
egress:
  fqdns: []               # from `scanent hosts`; used by the cilium flavor and the egress proxy
egressProxy: { enabled: false }

resources:
  requests: { cpu: 100m, memory: 256Mi }
  limits: { memory: 1Gi }
podAnnotations: {}
nodeSelector: {}
tolerations: []
```

The CronJob:

- `concurrencyPolicy: Forbid`, `backoffLimit: 0`, `restartPolicy: Never`,
  `ttlSecondsAfterFinished: 86400`.
- `args: ["scan", "--config", "/etc/scanent/config.json", "--out", "/out"]`,
  plus `--strict` when set. The image's entrypoint is used as built; no
  `command`, so no shell.
- Pod: `automountServiceAccountToken: false`; `securityContext`
  `runAsNonRoot: true`, `runAsUser: 1000`, `runAsGroup: 1000`,
  `fsGroup: 1000`, `seccompProfile: RuntimeDefault`.
- Container: `readOnlyRootFilesystem: true`,
  `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`,
  `privileged: false`.
- Volumes: the ConfigMap at `/etc/scanent` (read-only); the Secret at
  `/run/secrets/scanent` (read-only, `defaultMode: 0440`, readable through
  `fsGroup`); the output at `/out`; the CA ConfigMap, when set, at
  `/etc/scanent-ca` with `NODE_EXTRA_CA_CERTS` pointing at it.
- Env: for each `secrets.files` entry, `<env>_FILE=/run/secrets/scanent/<key>`;
  `HTTPS_PROXY` and `NO_PROXY` when set. No `valueFrom.secretKeyRef` and no
  literal value: a credential reaches the process only as a file.
- The ConfigMap's checksum is a pod annotation, so a changed configuration is
  visible in the Job's template.

The configuration's `schedule.everyHours` is still required by the schema and
is unused by a CronJob; the chart's README says to set it to the cron's
period, because a tenant reads it as the cadence.

Secrets: the chart creates no Secret and has no value that can hold one. The
values schema refuses unknown keys, so `secrets.values` or an `env` list
cannot be added by a values file. `templates/NOTES.txt` prints the
`kubectl create secret generic … --from-file=` line for the configured keys.

Output: `pvc` creates a `ReadWriteOnce` claim; `existingClaim` uses one;
`emptyDir` keeps nothing after the pod ends, so the chart refuses it
(`fail`) unless the configuration's outputs include `inflect` or `stdout`.
Object-store output is not built: it needs a write client for a client's
storage, which is its own decision (section 12).

### 8.4 NetworkPolicy, and its limit

A Kubernetes NetworkPolicy matches addresses and ports, not names. The hosts
in the declared surface are names whose addresses belong to large providers
and change. So a plain NetworkPolicy cannot list "exactly the hosts in the
surface", and the chart does not pretend to.

`flavor: kubernetes` (default) renders one policy for the scanner pod:

- `policyTypes: [Ingress, Egress]`, no ingress rule: nothing may connect in.
- Egress to the cluster's DNS (UDP and TCP 53, to `networkPolicy.dns`).
- Egress on TCP 443 to `0.0.0.0/0` except `10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`, `100.64.0.0/10`, `169.254.0.0/16`, and to `::/0` except
  `fc00::/7` and `fe80::/10`.
- Each `extraEgress` entry, for a self-hosted LangSmith or an MCP server on a
  private address.
- With `networkPolicy.proxy.cidr` set, the 443 rule is replaced by one rule to
  that address and port.

What that gives: no inbound, no cleartext, no cluster-internal or metadata
address, no port but 443. What it does not give: it does not stop a
connection to a public address that is not in the surface. The chart's README
and `NOTES.txt` say this in those words.

Exact hosts, two optional ways, both fed by `scanent hosts`:

- `flavor: cilium` renders a `CiliumNetworkPolicy` instead: DNS to kube-dns
  with a `rules.dns` match on each name in `egress.fqdns`, and
  `toFQDNs: [{ matchName }]` on port 443 for each. It requires Cilium and
  fails to render when `egress.fqdns` is empty: an empty list would deny
  everything, and the chart says so rather than install a scanner that can
  read nothing.
- `egressProxy.enabled: true` runs the bundled CONNECT proxy as a Deployment
  with a Service, `EGRESS_ALLOW` from `egress.fqdns`. The scanner pod's policy
  then allows egress to the proxy pod only (and DNS), and the proxy pod's
  policy allows 443 to public addresses. The exact-host rule is enforced by
  the proxy, on any CNI that enforces NetworkPolicy. A customer-named host on
  a private address needs `noProxy` and an `extraEgress` entry.

`flavor: none` renders no policy, for clusters that manage policy elsewhere.

On a cluster whose CNI does not enforce NetworkPolicy, the policy is accepted
and does nothing. The README says how to check.

A test holds the chart's README table of hosts per source equal to `hostsFor`
over `deploy/examples/everything.json`.

### 8.5 The air-gapped bundle (P3.5)

`deploy/airgap/build-bundle.sh <version> <amd64-image-ref> <arm64-image-ref> <out-dir>`
builds nothing; it packages two images that already exist locally.

```
scanent-<version>-airgap/
  VERSION
  LICENSE  NOTICE
  images/scanent-<version>-linux-amd64.tar     docker save, one image each
  images/scanent-<version>-linux-arm64.tar
  load.sh
  verify.sh
  deploy/compose.yaml  deploy/compose.egress.yaml
  deploy/helm/scanent-<version>.tgz            (tar of the chart directory)
  examples/                                    deploy/examples, as committed
  docs/quick-start.md  docs/scanner.md  docs/deployment.md  docs/access.md
  sbom/README.txt                              or the hook's output
  SHA256SUMS                                   every file above, sorted by path
```

- The directory is then archived as `scanent-<version>-airgap.tar` with sorted
  names, numeric owner 0, and `SOURCE_DATE_EPOCH` as the modification time, so
  two builds from the same inputs give the same archive apart from the image
  tars themselves.
- Two single-architecture `docker save` archives rather than one OCI layout:
  `docker load`, `podman load`, `nerdctl load` and `ctr images import` all
  read them with no registry.
- `load.sh`: picks the archive by `uname -m` (`x86_64`, `aarch64`/`arm64`;
  anything else exits 1 naming it), runs `verify.sh` first and stops if it
  fails, loads with `${CONTAINER_RUNTIME:-docker}`, and prints the loaded
  image reference and the one-liner. POSIX `sh`, no network.
- `verify.sh`: `sha256sum -c SHA256SUMS` (or `shasum -a 256 -c`), then checks
  that the set of files present equals the set listed, both ways, so an added
  file fails as a missing one does.
- SBOM hook: when `SCANENT_SBOM_CMD` is set, the script runs it once per image
  reference and stores its stdout as `sbom/<arch>.cdx.json`. When unset it
  writes `sbom/README.txt`: "No SBOM in this bundle. Phase 4 adds one." It
  never writes an empty or placeholder file under an SBOM's name.
- No signature yet. `docs/deployment.md` says what that means: the checksums
  detect a damaged copy, not a replaced one; obtain the bundle over a channel
  you trust until Phase 4 signs it.

### 8.6 The release workflow

`.github/workflows/release.yml`, on `push` of a tag `v*.*.*` and on
`workflow_dispatch` (which builds and tests and pushes nothing).

| Job | Runner | Does |
|---|---|---|
| `build` (matrix: amd64, arm64) | `ubuntu-24.04`, `ubuntu-24.04-arm` | `docker build` natively; `deploy/smoke.sh`; the Trivy gate; on a tag, push `…/scanent:<version>-<arch>`; `docker save` to a workflow artifact |
| `manifest` (tags only) | `ubuntu-24.04` | `docker buildx imagetools create` one manifest `…:<version>` and `…:<major>.<minor>` over the two pushed digests; inspect it and fail unless it lists exactly `linux/amd64` and `linux/arm64` |
| `bundle` | `ubuntu-24.04` | download both image artifacts, `docker load`, run `build-bundle.sh`, run `verify.sh` and `load.sh` against the result, then one code-only scan of the loaded image with `--network none`, upload the archive as a workflow artifact |

- Native runners rather than emulation: each architecture's image is smoke
  tested on the architecture it is for.
- No new third-party action. Login is `docker login ghcr.io` with the
  workflow token on stdin; buildx is on the runner. The actions used are the
  ones `ci.yml` already pins by SHA.
- Permissions: `contents: read` at the top; `packages: write` on the two jobs
  that push, and only on a tag.
- No `latest` tag. A client names a version.
- `docker build` is called with `--provenance=false --sbom=false`, so each
  pushed reference is a plain image manifest. Signing, SBOM and provenance are
  Phase 4, and are not half-added here.
- The base image digest in the Dockerfile must be the multi-architecture index
  digest. The implementer checks it with `docker buildx imagetools inspect`
  and records the result in this note's implementation record; if it is a
  single-architecture digest, it is replaced by the index digest of the same
  tag in the same commit.
- The version is the tag without `v`. The workflow fails when it differs from
  `SCANNER_VERSION` in `scanner-surface.ts`.

`ci.yml` gains a `chart` job (section 9.6) and the new smoke steps. It still
publishes nothing.

### 8.7 Dockerfile

Two changes: `ENV NODE_USE_ENV_PROXY=1` in the runtime stage, and nothing
else in the image. `image.test.ts` gains the assertion for that line. The
container rules stand: non-root, read-only root, capabilities dropped,
no-new-privileges, exec-form entrypoint with no shell.

## 9. Tests

All behavioural, deterministic, with no real network: the source fakes
(`tests/helpers/agent-harness-source-fakes.ts`), temporary directories, and
injected clocks. Coverage stays at or above 80% on all four metrics; each new
module below has its own suite.

### 9.1 `init` (`init-plan.test.ts`, `init-prompts.test.ts`, `init-write.test.ts`, `keygen.test.ts`)

- Every example answers file plans a configuration that `parseScannerConfig`
  accepts; the env template holds names with empty values or paths only.
- Scripted prompts produce the same answers object as the equivalent answers
  file (one test per source kind, and one with every kind).
- A secret-shaped answer is refused at each free-text prompt, is absent from
  everything `say` printed and from every file, and three refusals exit 2. A
  secret-shaped string in an answers file exits 4 naming its path.
- Inflect is absent unless asked for: the default plan has no `inflect` block,
  no `inflect` output and no register source.
- Files are `0600`, the directory `0700`; an existing file is refused without
  `--force` and nothing is written; `--force` replaces by rename; an existing
  signing key is kept in both cases; a directory that is a link is refused.
- `keygen` writes a key `loadSigningKey` accepts, prints the public half
  `public-key` prints for it, never prints the private key, and refuses an
  existing file.
- The access tables: one per chosen source and none for the others;
  `docs/access.md` equals the rendered guide.

### 9.2 Secret files (`secrets.test.ts`)

The four-row table of 4.1; each refusal code of 4.2, including a link to a
regular file (accepted), a directory, a 64 KiB + 1 byte file, a world-writable
file, a `0444` file (accepted); one trailing `\n` and one `\r\n` removed and a
second one kept; only configured names are looked up (an unrelated `X_FILE`
is ignored); no error message contains file content. End to end through
`main`: `scan --dry-run` with the signing key given only as a file produces a
report that verifies.

### 9.3 `doctor` (`doctor.test.ts`, `doctor-local.test.ts`, `doctor-render.test.ts`)

Against `createSourceFakes`:

- The all-good estate: every source's checks pass or are
  `NOT_OBSERVABLE` as section 5.3 says; exit 0.
- Per source, through the fakes' `override`: a 401 (`authenticated` fails,
  later checks `BLOCKED`), a 403 on the permission read, a thrown fetch
  (`reachable` fails), a 429 (`BLOCKED`, exit 3), a missing credential.
- Entra: a token whose `roles` holds a `ReadWrite` role warns and names it; a
  token that does not decode is `NOT_OBSERVABLE`. GitHub: an `X-OAuth-Scopes`
  header with `repo` warns; no header is `NOT_OBSERVABLE`.
- Every request any doctor run makes is in the declared surface
  (`isDeclaredRequest`, `isDeclaredMcpMessage`, `isDeclaredRegisterMessage`,
  `isDeclaredRegisterExchange`), no request has a method other than GET or a
  declared POST, and the ingest path is never requested.
- No fake token, secret marker or credential value appears in the text or the
  JSON output or the log.
- Local checks: each row of 5.4, with injected `fs`, environment and clock,
  including a `Date` header 30, 120 and 600 seconds off and none at all.
- The exit-code table of 5.6, one case per row, and the precedence between
  rows.
- No check object is ever `PASS` with a `cause`, `SKIPPED` without one, or
  `FAIL`/`WARN` without a `fix` (a property test over every scenario above).
- `scannerManifestHash()` equals its value before this phase.

### 9.4 Proxy, CA, hosts, exit codes

- `proxy-env.test.ts`: the `NO_PROXY` table; `describeProxy` never returns
  userinfo.
- `hosts.test.ts`: `hostsFor` per source; equality with the request log of a
  full fake scan; the three formats.
- `http` suite, added cases: a thrown error with a certificate `cause.code`
  is `UNREACHABLE` with the TLS message; the report is unchanged.
- `customer-host` behaviour with a proxy variable set: the guard is still
  called before each request (the existing spy tests, run again with
  `HTTPS_PROXY` in the environment).
- `cli` suite, added cases: `--strict` (complete: 0; incomplete: 3; empty: 3;
  failed output: 1); a refused configuration is 4; `NODE_TLS_REJECT_UNAUTHORIZED=0`
  is 4 before anything is read; every existing exit-code test unchanged.
- Exact-equality lists that grow, each stated in its commit: the package
  entry's exports (`public-entry.test.ts`), `HELP`, the Dockerfile's `ENV`
  lines (`image.test.ts`).

### 9.5 Deployment templates (`deploy-templates.test.ts`): closes issue 9

- Every file under `deploy/examples/` and `examples/` that is a configuration
  parses under the strict schema, and `credentialEnvNames` of each equals the
  names in its `.env` template.
- No example, template or values file holds a secret-shaped string
  (`looksLikeSecret` over every string of every parsed document and every
  line of every text file under `deploy/`).
- `compose.yaml` and the overlay, parsed with `js-yaml`: every service has
  `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges:true`, a `user`
  that is not root, no `privileged`, no `cap_add`, no `ports`, no
  `network_mode: host`, no Docker socket mount; the configuration mount is
  `:ro`; the image reference carries no `latest`.
- `values.schema.json` is valid JSON Schema with `additionalProperties: false`
  at every object, and `values.yaml` holds no key named `password`, `token`,
  `secret` (other than `secrets.existingSecret` and `secrets.files`) or `key`
  with a string value.
- The chart, rendered. When `helm` is on the path the test runs
  `helm template` for four value sets (defaults with a configuration; cilium;
  egress proxy; a proxy and an extra CA) and asserts on the parsed documents:
  the pod and container security context of 8.3, no `command`, no `env` entry
  with `value` or `secretKeyRef` for a credential name, every credential as a
  `_FILE` path under `/run/secrets/scanent`, the NetworkPolicy rules of 8.4,
  the Cilium policy's names equal to `egress.fqdns`, `emptyDir` refused for a
  file-only configuration, an empty `egress.fqdns` refused for `cilium`.
  When `helm` is absent the cases are reported as skipped by name, and with
  `REQUIRE_HELM=1` (set in CI) their absence fails the suite. They never pass
  unrun.
- The bundle scripts: `build-bundle.sh` with two small stand-in image archives
  produces the tree of 8.5; `verify.sh` passes on it, and fails after a byte
  is changed, a file is removed and a file is added; `load.sh` picks the
  archive for each `uname -m` (with `uname` and the runtime replaced by
  stubs on the path) and refuses an unknown one.

### 9.6 Image and cluster (CI)

`deploy/smoke.sh`, new steps:

7. **Closes issue 14.** `mkdir -m 0700` an output directory owned by the
   invoking user; run `scan --dry-run --out /out` with
   `--user "$(id -u):$(id -g)"`; then, as the invoking user and without the
   container, read `latest.json` and `runs/*/summary.html`, and assert the
   run directory is `0750`, the files `0640`, and both are owned by the
   invoking uid. `CONTAINER_RUNTIME=podman` uses `--userns=keep-id` instead of
   `--user`; CI runs the Docker form, and the Podman form is run by hand and
   recorded in the implementation record with its result.
8. The signing key as a `0444` mounted file with `SCANNER_SIGNING_KEY_FILE`:
   `public-key` prints the expected key.
9. `init --answers` into a writable mount, then `doctor --json` on what it
   wrote: exit 0 or 3, the JSON parses, and no check is `FAIL`.
10. `hosts` on the code-only configuration prints nothing and exits 0.

`ci.yml` job `chart`: `helm lint`; `helm template` with each value set; the
Jest template suite with `REQUIRE_HELM=1`; then on `kind`: load the image
built by the `image` job, create the Secret from a generated key, install the
chart with the code-only example and `output.type: pvc`, create a Job from
the CronJob, wait for it to complete, and assert from the Job's log that a
run was written. If the default CNI does not enforce NetworkPolicy the job
says so in its log and asserts only that the policy object exists; it does not
claim the policy was enforced.

What cannot run in a sandbox without `helm` or `kind` is stated in the
implementation record, not assumed.

## 10. Documents

- `docs/quick-start.md`, "Run it at your site in 15 minutes": pull (or
  `load.sh`); `init`; create the access the wizard printed; fill in
  `scanent.env`; `doctor`; `scan`; open `summary.html`; then the Compose file
  for a schedule. Six steps, each one command, with the expected last line of
  output. No step needs `openssl`, Node or a checkout.
- `docs/deployment.md`: the one-liner, Compose, the egress overlay, Helm and
  its NetworkPolicy limit, the air-gapped bundle, secret files, proxy and CA,
  rootless Docker and Podman, the exit-code table.
- `docs/access.md`: generated (2.6).
- `docs/scanner.md`: `init`, `keygen`, `doctor`, `hosts`, `--strict`, the
  `_FILE` rule and the exit-code table.
- `README.md`: status line to Phase 3, a pointer to the quick start, and the
  container quick start reduced to the pulled image.

No document names a client, an internal host, or a credential.

## 11. Files and order of work

New in `packages/scanner/src`: `exit-codes.ts`, `secrets.ts`, `keygen.ts`,
`proxy-env.ts`, `hosts.ts`, `init/{answers,plan,prompts,write,access-guide}.ts`,
`doctor/{types,run,local,render}.ts`. Changed: `cli.ts` (five commands,
`--strict`, typed exit codes, the TLS refusal), `source.ts` (`preflight`,
`status`), `http.ts` (`status`, the TLS message), each file in `sources/`
(`preflight`), `index.ts`.

The lint boundaries are unchanged: `sources/code` still may not spawn or
evaluate, and nothing new is imported from outside the allowed set.

Order, each step ending green (lint, typecheck, build, tests with coverage):

1. Exit codes, `secrets.ts`, `keygen`, the TLS refusal; tests.
2. `proxy-env.ts`, `hosts.ts`, the Dockerfile line; tests.
3. `init`: answers, planner, access guide, writer, prompts; `docs/access.md`.
4. `doctor`: `preflight` per source, local checks, renderers.
5. Compose, examples, template tests; smoke steps 7 to 10.
6. Helm chart, its tests, the `chart` job.
7. Bundle scripts, `release.yml`.
8. Documents; close issues 9 and 14 with the commits that hold them.

## 12. Open points for the owner

Each has a default this note builds; none blocks the work.

1. **Is the image public?** `release.yml` pushes to
   `ghcr.io/rodnapamet/scanent`. A package's visibility is set in its
   settings, and BUSL-1.1 permits distribution of the image. Default: the
   workflow is written and pushes on a tag; no tag is pushed until the owner
   says the package may be public.
2. **Should an incomplete scan exit non-zero by default?** Default: no, to
   keep `scan`'s existing meaning; `--strict` opts in. Flipping the default is
   a breaking change best made at 1.0.
3. **Okta write check.** Reading the token user's roles needs
   `GET /api/v1/users/{id}/roles` added to the declared surface, which changes
   the manifest hash. Default: not added; the check is `NOT_OBSERVABLE`.
4. **Key Vault and Google write checks** need a management-plane read and a
   POST respectively. Default: not added.
5. **Object-store output** for the chart. Default: not built; a volume only.
6. **GitHub Release.** Attaching the bundle to a release needs
   `contents: write`. Default: the bundle is a workflow artifact.

## 13. Implementation record: the command-line half

What was built for P3.1 to P3.3 (the wizard, the preflight, secret files, proxy
and certificate-authority support, the exit codes), and where it differs from
the sections above. Sections 8 and 9.5 to 9.6 (Compose, Helm, the bundle, the
release, the smoke steps) and `docs/quick-start.md` and `docs/deployment.md`
are not part of this record.

### Checked here

- **The proxy.** On Node 22.22.0, with a local CONNECT proxy: `fetch` sends
  its request through `HTTPS_PROXY` when `NODE_USE_ENV_PROXY=1`, and directly
  when it is not set. Node 22 prints an experimental warning on stderr when it
  does.
  The same was then observed in the built image (Node 24.22.2, which sets
  the variable itself): with `--network none` and a proxy listening inside
  the container, the proxy saw `CONNECT api.github.com:443`, and a host named
  in `NO_PROXY` was dialled directly.
- **`NO_PROXY`.** Observed in the Node 22 run: a bare name exempts that name
  only (`example.test` does not exempt `sub.example.test`); `.suffix` and
  `*.suffix` exempt subdomains and not the name itself; `name:port` exempts
  that port only. Section 6.2 said a bare name is a suffix; `isProxied`
  follows what Node does.
- **No test pinned exit code 1 for a refused configuration.** The existing
  tests pin that `main` REJECTS for a missing, malformed or refused
  configuration, so `main` still rejects with the same error, and the process
  (`run`) exits 4 through `exitCodeForError`. Section 7 said `main` returns 4.
- **The manifest hash is unchanged**; `outputs.test.ts`, which pins it by
  value, passes unmodified.
- **The prompts on a real terminal** (a pseudo-terminal, answers piped in at
  once). `readline`'s `question` drops lines that arrive before the question
  that wants them, so the terminal front end queues lines itself.

### Differences from the note

| Section | The note | What was built, and why |
|---|---|---|
| 2.2 | The answers schema lists each source's fields | A source is checked for its `kind` only in the answers schema, and for everything else by the configuration's own schema in the planner: one copy of the rules. `signingKeyEnv` and `inflect.apiKeyEnv` may be given |
| 2.4 | The signing key's path in `scanent.env` is the path the container sees | It is the path `init` wrote the key to (`<dir>/signing-key.pem`). `init` cannot know where a directory will be mounted; run it with the directory mounted where the scan will have it, and the two are the same |
| 2.8 | Exit codes 0, 2, 4 | Also 1 when the directory or a file cannot be written (a full disk, a permission) |
| 5.3 | `ProbeStep` is `{ id, outcome, observed }`, and each source produces all six checks | A step is `exchange`, `read` or `write`, with the host asked. `credential.present` and `host.resolves` are decided by the runner from the configuration, which already knows each source's variable and hosts |
| 5.3 | `code`: `write.absent` uses `access(W_OK)` in the source | The runner makes that call. The `code` source's file operations are declared in the surface (`lstat`, `readdir`, `readFile`), and adding one would change the manifest hash |
| 5.3 | Entra passes when `roles` is exactly `Application.Read.All` | It passes when no role writes, and names the roles it saw. A token with no `roles` claim is not observable |
| 5.3 | GitHub warns on `repo`, `workflow`, `admin:…`, `write:…`, `delete_repo` | Also `public_repo`, which writes to public repositories. A classic token holding none of them passes, naming its scopes |
| 5.3 | The ingest is reported as `read.permitted`, not observable | The check is named `post.permitted`: what it cannot observe is a post |
| 5.3 | Outcomes for 401, 403, 429 and no answer | Three more, each seen while testing: the time box ending after some requests were answered (the rest are blocked, not a network failure); a credential that cannot be used at all, such as a Google key that is not a key file (nothing is sent; `authenticated` fails); a 5xx or an answer that is not the API's (`read.permitted` fails as NETWORK without blaming the credential) |
| 5.4 | `proxy` fails when `HTTPS_PROXY` is set without `NODE_USE_ENV_PROXY=1` | Not applicable for a configuration that reaches no host: there is no request for a proxy to carry |
| 6.5 | `doctor` refuses to run with `NODE_TLS_REJECT_UNAUTHORIZED=0` | It runs its local checks, fails `tls.verification`, contacts no source (each is blocked behind that check) and exits 4. `scan` and `schedule` refuse outright, as written |
| 7 | `schedule` ignores `--strict` | `schedule` refuses it (exit 2). The command line's rule is that a flag is refused, never ignored |
| 7 | An unknown command | Now refused before the configuration is read (it was read first). Same message, same exit code 2 |

### Not established

- No source was probed against the real product. Every probe is a request the
  source's `read` already makes, against the same fakes the reads are tested
  with.
