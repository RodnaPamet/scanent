# The report contract

The normative description of the signed report scanent produces, for somebody
writing a consumer: a verifier, an ingest, a dashboard. It is written from the
code in `packages/contract/src`, which is the reference implementation. A test
(`packages/contract/tests/contract-doc.test.ts`) holds every limit and every
list on this page equal to the constants the code exports, so the page cannot
drift from what a report is checked against.

The words "must" and "is refused" describe what the reference verifier
(`verifyAndParseHarnessReport`) does. A consumer that accepts less is safe; one
that accepts more is not reading this contract.

## At a glance

- A report is one JSON object: a **body** and a `signature` member.
- The body names its contract id in `contract`. The id selects a strict schema:
  an unknown member anywhere is a refusal.
- The signature is Ed25519 over the SHA-256 of the body's canonical JSON.
- A report carries what a scanner saw: agents, their credentials by reference,
  their tools, the verdicts it holds evidence for, and how far each source was
  read. It does not carry a level, a completeness flag or a credential value.
  Those are derived, or refused.

## Contract ids

Four ids of the agent report have existed. A new id is a new strict schema
beside the others, never a looser schema that reads several. The integrations
scanner's report has ids of its own: see "The integrations contract".

<!-- contract:ids -->
| Id | State | What it adds |
|---|---|---|
| `inflect-agent-harness/1` | Retired: refused as `SCHEMA` | The first contract |
| `inflect-agent-harness/2` | Accepted | The `code` source kind, the `UNPARSEABLE` reason, `unboundCredentials[]`, a tool's optional `calls` and `windowDays`, an agent's optional `models[]` |
| `inflect-agent-harness/3` | Accepted | The `gcp-sa` source kind, and nothing else |
| `inflect-agent-harness/4` | Accepted; what scanent writes | An agent's optional `paymentCapabilities[]`, and nothing else. See "Payment capabilities" |
<!-- /contract:ids -->

The source kinds are a closed list on the wire, which is why `/3` is a new id
and not a wider `/2`: a `/2` report that names `gcp-sa` is refused, and a `/2`
verifier refuses a `/3` report. `/4` is a new id for the same reason: a `/3`
verifier refuses the new member, and a `/3` report that carries it is refused
here. The id names itself with the product it was
first written for; it is an identifier and is not changed.

## The body

Every object is strict. Limits are in "Limits".

| Member | Type | Meaning |
|---|---|---|
| `contract` | string | The contract id |
| `scan.id` | id | The scan's id, chosen by the scanner |
| `scan.asOf` | ISO 8601 date-time | The moment the scan describes |
| `scan.scanner.agentId` | id | The scanner's own id, as the consumer registers it |
| `scan.scanner.version` | id | The scanner's version |
| `scan.scanner.manifestHash` | `sha256:` and 64 hex | The hash of the scanner's declared surface: what it can reach |
| `population.sources[]` | 1 to `MAX_SOURCES` | Every source the scan was configured to read, read or not. Each kind once |
| `agents[]` | 0 to `MAX_AGENTS` | Every agent found. Each `discoveredId` once |
| `findings[]` | 0 to `MAX_FINDINGS` | What the scanner itself raises. A consumer does not act on it; see "Findings" |
| `unboundCredentials[]` | 0 to `MAX_UNBOUND_CREDENTIALS` | Credentials a source saw bound to no agent |

### A source

| Member | Type | Meaning |
|---|---|---|
| `kind` | source kind | Where the scanner looked |
| `status` | `COMPLETE` or `INCOMPLETE` | Whether it was read in full |
| `reason` | incomplete reason | Present exactly when `status` is `INCOMPLETE` |
| `rows` | integer, 0 or more | Rows read from the inventory, whether or not each became an agent |

Source kinds, by the id that carries them:

<!-- contract:source-kinds -->
| Kind | Since | What it is |
|---|---|---|
| `entra-sp` | `/2` | Microsoft Entra service principals and app registrations |
| `okta-app` | `/2` | Okta service applications and API tokens |
| `vault` | `/2` | A vault's credential metadata |
| `mcp` | `/2` | MCP servers' tool listings |
| `runtime` | `/2` | An agent runtime's projects, deployments or sandboxes |
| `cicd` | `/2` | CI/CD workflows and the secrets they name |
| `inflect-register` | `/2` | The consumer's own agent register |
| `code` | `/2` | Agent definitions read from source code |
| `gcp-sa` | `/3` | A Google Cloud project's service accounts |
<!-- /contract:source-kinds -->

Why a source was not read in full:

<!-- contract:incomplete-reasons -->
| Reason | Meaning |
|---|---|
| `BYTE_CAP` | A size or count bound was reached: a response, a source's budget, a page count, or a cap of the report itself |
| `TIME_BOX` | The source's deadline passed |
| `AUTH_FAILED` | The credential was missing, refused, or could not be used |
| `UNREACHABLE` | The source did not answer, or answered with an error that is none of the others |
| `PAGINATION_TORN` | An answer was not the listing it should be, or a next link could not be followed |
| `RATE_LIMITED` | The source answered that it was rate limited |
| `UNPARSEABLE` | A definition was read and could not be resolved |
<!-- /contract:incomplete-reasons -->

**Completeness is derived, never declared.** A scan is complete when it lists
at least one source and every source it lists is `COMPLETE` (`isScanComplete`).
Zero sources is not complete: a scan that looked nowhere evidences nothing.

### An agent

| Member | Type | Meaning |
|---|---|---|
| `discoveredId` | id | The agent as the source names it, for example `entra:sp:<objectId>` |
| `discoveredVia[]` | 1 or more source kinds | Every source that found it |
| `registeredAgentId` | id or null | The register row this agent is. Only a register source may set it; a consumer decides for itself whether it holds such a row |
| `owner` | object or null | `kind` (`user` or `group`), `id`, and `source`: where the scanner read it |
| `credentials[]` | 0 to `MAX_CREDENTIALS_PER_AGENT` | See below |
| `tools[]` | 0 to `MAX_TOOLS_PER_AGENT` | See below |
| `models[]` | optional, 0 to `MAX_MODELS_PER_AGENT` | Model endpoints the agent calls. Absent means not reported; an empty list means reported as none |
| `paymentCapabilities[]` | `/4` only; optional, 0 to `MAX_PAYMENT_CAPABILITIES_PER_AGENT` | Where the agent's code calls a payment client. See "Payment capabilities" |
| `skills[]` | 0 to `MAX_SKILLS_PER_AGENT` | `name`, `license` (or null), `declared` |
| `verdicts[]` | 0 to twice the number of criteria | The criteria the scanner holds evidence about |

A **credential** is named by reference and never carried:

| Member | Type | Meaning |
|---|---|---|
| `ref` | `scheme://locator`, no white space | Where the credential is. A raw value has no scheme and is refused |
| `ageDays` | integer or null | Its age at `asOf` |
| `expires` | boolean or null | Whether it has an expiry |
| `boundToAgent` | boolean | Whether it is bound to this agent rather than shared |
| `grant` | `delegated`, `app-only` or `unknown` | Whether a named person bounds what it can reach |

A **tool**:

| Member | Type | Meaning |
|---|---|---|
| `server` | URL | The MCP server that serves it, or a `code://` locator for a tool the agent's code defines |
| `name` | id | The tool's name |
| `manifestHash` | `sha256:` and 64 hex, or null | The hash of the tool's definition |
| `pinned` | boolean | Whether the estate pinned that hash |
| `readOnlyHint` | boolean or null | As the server declares it. Unknown counts as a write |
| `calls`, `windowDays` | optional integers | Calls over a window of days. Both or neither. A count, and nothing of what was called with |

A **model endpoint** is `endpoint` (a `scheme://locator` or a host, with no
userinfo) and `model` (an id or null).

A **verdict** is `criterion` (an id of the ladder), `met` (boolean) and
`evidence` (a pointer of at most `MAX_EVIDENCE_CHARS` characters, or null).

### Payment capabilities

`/4` adds one optional member to an agent, `paymentCapabilities[]`: each place
the agent's code calls a recognised payment CLIENT, so the agent can initiate a
payment. An entry is:

| Member | Type | Meaning |
|---|---|---|
| `protocol` | payment protocol | From the closed list below |
| `library` | payment client library | From the closed list below |
| `at` | `code://` locator | Where the code makes the call |

Never an amount, an address, a wallet, a key or a token: what a call would pay,
and with what, is out of a static reader's sight, and a value there is refused
as secret-shaped anyway.

<!-- contract:payment-libraries -->
| Library | Protocol | Where |
|---|---|---|
| `x402-fetch` | `x402` | npm |
| `x402-axios` | `x402` | npm |
| `@x402/fetch` | `x402` | npm |
| `@x402/axios` | `x402` | npm |
| `x402` | `x402` | PyPI |
<!-- /contract:payment-libraries -->

Each is the payer side of its protocol. Seller-side middleware accepts payments
and initiates none, and is not on the list.

Four rules, each a refusal:

- the member is carried only by an agent whose `discoveredVia` includes `code`:
  only a code read can state it, even empty;
- each (library, locator) pair appears once;
- the protocol and the library are from the lists above;
- `at` is a `code://` locator.

**Three states, never collapsed.** Absent is NOT REPORTED: no code read saw
this agent. An empty list is a code read that saw no payment client called in
the agent's own file. That is what the reader saw, not evidence that the agent
cannot pay: a client wrapped in another module, or reached through a name the
reader cannot follow, is out of its sight. Entries are what it saw. Like every
fact code yields, a capability shows that the agent CAN pay, never that a
control over the payment works.

### An unbound credential

`ref` (a credential reference) and `sourceKind`. Three rules, each of which
refuses a report that contradicts itself:

- each (source kind, reference) pair appears once;
- the source kind is one the report lists in `population.sources`;
- no agent in the same report holds the reference.

## Limits

<!-- contract:limits -->
| Constant | Value | What it bounds |
|---|---|---|
| `MAX_REPORT_BYTES` | 5,242,880 | The whole report as UTF-8 bytes, checked before it is parsed |
| `MAX_SOURCES` | 50 | Entries of `population.sources` |
| `MAX_AGENTS` | 5,000 | Entries of `agents` |
| `MAX_CREDENTIALS_PER_AGENT` | 100 | Credentials of one agent |
| `MAX_TOOLS_PER_AGENT` | 500 | Tools of one agent |
| `MAX_SKILLS_PER_AGENT` | 100 | Skills of one agent |
| `MAX_MODELS_PER_AGENT` | 50 | Model endpoints of one agent |
| `MAX_PAYMENT_CAPABILITIES_PER_AGENT` | 50 | Payment capabilities of one agent (`/4`) |
| `MAX_FINDINGS` | 20,000 | Entries of `findings` |
| `MAX_UNBOUND_CREDENTIALS` | 10,000 | Entries of `unboundCredentials` |
| `MAX_TOOL_CALLS` | 1,000,000,000 | A tool's `calls` |
| `MAX_WINDOW_DAYS` | 366 | A tool's `windowDays` |
| `MAX_ID_CHARS` | 256 | An id, a name, the signature's `signerKey` and `sig` |
| `MAX_EVIDENCE_CHARS` | 512 | An evidence pointer, a tool's `server`, a model endpoint |
<!-- /contract:limits -->

The byte limit and the counts are independent, and the bytes are reached first
on an estate whose agents hold tools: see "Limits and scale" in
[scanner.md](scanner.md). scanent refuses to sign a report over the byte limit.

## No credential value

A report names credentials and never holds one. Two checks, both made before
anything is stored:

1. A credential reference must be `scheme://locator`.
2. No string value anywhere in the body may have the shape of a secret
   (`looksLikeSecret`, `firstSecretShapedMember`). The shapes are a short
   list on purpose: GitHub tokens, AWS access key ids, Slack tokens, `sk-` and
   `sk-ant-` keys, a PEM private key header, a JSON web token, and a URL with a
   password in its userinfo. A match inside a longer string is a match. A
   member's name is checked as a value is, and the refusal writes `<key>` in
   its place.
3. No string and no number anywhere in the body may contain a payment card
   number (`containsCardNumber`, part of `looksLikeSecret`; a number is read
   as its digits by `firstSecretShapedPath`). A card number is 13 to 19
   digits that pass the Luhn check and start with 2 to 6, written
   contiguously or in the groups cards are printed in, with one kind of
   separator. A run of digits joined to a letter (a hex digest, a UUID) is
   never one, and neither is a run after a `+` or beside a decimal point. So
   no reader of a report is brought into PCI DSS cardholder-data scope by
   it.

A refusal names the member's path and never the value.

## Canonical JSON

One form, used for the signature and for every hash (`canonicalJson`):

- object keys are sorted by code unit, at every depth;
- arrays keep their order;
- no white space;
- strings and numbers are written as `JSON.stringify` writes them;
- `undefined` is written as `null`.

## The signature

```json
"signature": { "alg": "ed25519", "signerKey": "<public key>", "sig": "<signature>" }
```

- `signerKey` is the scanner's raw 32-byte Ed25519 public key, in hex or
  base64.
- The **signed message** is the 32 bytes of SHA-256 over the canonical JSON of
  the body: the report with its `signature` member removed.
- `sig` is the Ed25519 signature over that message, as 128 hex characters or
  as base64 of 64 bytes.

A scanner signs what the wire will carry: it serialises the body, parses it
back, and signs that, so a member holding `undefined` (written as `null` in
canonical JSON and dropped by a JSON serialiser) cannot make the two differ.

## Verification, in order

The order is the contract. Each step refuses with one code, and nothing of a
later step is read before the earlier one passes:

<!-- contract:refusals -->
| Step | Refusal | When |
|---|---|---|
| 1 | `TOO_LARGE` | The report is over `MAX_REPORT_BYTES` |
| 2 | `NOT_JSON` | It does not parse as JSON |
| 3 | `NOT_AN_OBJECT` | It parses to something that is not an object |
| 4 | `UNSIGNED` | It has no `signature` member |
| 5 | `MALFORMED_SIGNATURE` | The signature is not the three members above, or the key or the signature does not decode |
| 6 | `UNTRUSTED_SIGNER` | `signerKey` is not one of the keys the verifier was given |
| 7 | `BAD_SIGNATURE` | The signature does not verify over the body |
| 8 | `SCHEMA` | The body names no accepted contract id, or fails that id's strict schema |
<!-- /contract:refusals -->

Two points a consumer must hold:

- **The signer is checked against keys the verifier already trusts**, compared
  as key material and not as text (a key in hex and the same key in base64 are
  one key). A report signed by any other key is refused even when its
  signature is mathematically valid. A reader that takes the key from the
  report itself has shown that the report was not altered, and nothing about
  who wrote it.
- **The schema is chosen by the id the body names, and only after the
  signature verified.** A refusal names the member's path and a rule, never a
  value, and an unknown member is counted, never named.

## The ladder

A report carries verdicts. The level they amount to is computed by the reader
(`scoreHarness`), never stated by the scanner.

<!-- contract:levels -->
| Level | Name | Criteria that first appear on it |
|---|---|---|
| `H0` | Shadow | (none) |
| `H1` | Registered | `H1.registered`, `H1.owner`, `H1.axes_declared`, `H1.tier_scored_fresh` |
| `H2` | Bounded | `H2.credential_bound`, `H2.grant_kind_declared`, `H2.tools_allowlisted`, `H2.audience_tokens`, `H2.policy_card` |
| `H3` | Guarded | `H3.manifests_pinned`, `H3.payloads_guarded`, `H3.propose_not_commit`, `H3.prior_state_reads`, `H3.skills_declared`, `H3.delegation_narrows`, `H3.egress_enforced` |
| `H4` | Observed and stoppable | `H4.ledger_baseline`, `H4.receipts`, `H4.kill_switch_drilled`, `H4.token_budget` |
| `H5` | Evidenced | `H5.asi_coverage`, `H5.evidence_emitted`, `H5.skills_evaluated`, `H5.sample_audit`, `H5.independent_audit` |
<!-- /contract:levels -->

How a level is derived:

- **Unanswered counts as no.** An agent is at a level only when every
  criterion on that level and on every level below it is met **with** an
  evidence reference. A criterion the report does not answer is not met, and a
  criterion answered `met: true` with no evidence is not met either.
- **A criterion reported more than once is judged on its least favourable
  answer** (`collapseVerdicts`): unanswered, then not met, then met without
  evidence, then evidenced.
- **Order is the index of the level** in the list above, and comparison is
  ordinal (`levelAtLeast`).
- **The ladder reports and does not gate.** An agent that holds a tool that
  can write, or whose reach is unknown, is expected at `H3`; one that only
  reads, at `H2` (`shortfallBarFor`). Below that bar is a finding, never a
  refusal.

The ladder has a version, `LADDER_VERSION`: `sha256:` over the canonical JSON
of its levels, its criteria and those bars. It is not a member of the report;
results derived from a report carry it, and two sets of results compare level
for level only when they carry the same one.

<!-- contract:ladder-version -->
Ladder version of this page: `sha256:b3aa459c8e48dc7dc7528f117de754cf1be24e53f7ec47c8ac81c471ec28d7ae`
<!-- /contract:ladder-version -->

## Findings

The report has a `findings` member with these codes:

<!-- contract:report-finding-codes -->
`SHADOW_AGENT`, `UNPINNED_WRITE_TOOL`, `ORPHAN_CREDENTIAL`, `INCOMPLETE_SOURCE`
<!-- /contract:report-finding-codes -->

**A consumer does not act on it.** scanent itself writes only
`INCOMPLETE_SOURCE` there, one for each source it could not read in full. What
a scan means is planned by the reader from the body (`planHarnessScan`), so a
scanner cannot raise or close a finding by saying so. The planner's codes, and
the reference each finding is keyed by:

<!-- contract:planned-finding-codes -->
| Code | Keyed by | Opened when |
|---|---|---|
| `SHADOW_AGENT` | the agent | The agent is not in the register the reader holds, and the scan read a sign that it runs a model (below) |
| `UNPINNED_WRITE_TOOL` | the agent | It holds a tool that can write and is not pinned |
| `LEVEL_DROP` | the agent and the scan | Its level fell since the reader's last scan. An event: never closed by a scan |
| `HARNESS_SHORTFALL` | the agent | Its level is below its bar |
| `EMPTY_SCAN` | the scanner | The scan found no agent at all |
| `INCOMPLETE_SOURCE` | the scanner and the source kind | A source was not read in full |
| `ORPHAN_CREDENTIAL` | the scanner, the source kind and the reference | A source read in full saw a credential bound to no agent, and every source that could name the agent it belongs to was read in full too |
| `SPENDING_AGENT_UNDECLARED` | the register row | `/4`: an agent linked to the row has code that calls a payment client, and the reader holds no spending authority for the row. Closed only by a spending authority a second person reviewed: a scan never closes it |
| `UNREGISTERED_IDENTITY` | the agent | The agent is not in the register, and nothing the scan read shows that it runs a model. In place of `SHADOW_AGENT` |
<!-- /contract:planned-finding-codes -->

**An unregistered identity is not a shadow agent.** A principal with no
register row is a shadow agent when the scan read a sign that it runs a model:
it was found through `code`, `runtime` or `mcp`, or it lists a tool or a model
endpoint (`MODEL_SIGNS`, `modelSignsOf`). A credential's name is not a sign.
With none, it is an unregistered automated identity: one finding of medium
severity, and no `HARNESS_SHORTFALL`, because it is held to no bar. A sign is a
presence and counts on any scan. Its absence counts only on a complete one, so
an incomplete scan leaves a principal the reader holds on record as an agent
(an open `SHADOW_AGENT` or `HARNESS_SHORTFALL`) as one.

**Spending authority is the register's, never the report's.** The finding is
keyed by the register row the planner linked, so an unregistered agent that
can pay is a shadow agent and nothing more, and a report cannot raise it
against a row the reader does not hold. A spending authority awaiting review
holds it: neither opened nor closed. An empty `paymentCapabilities[]` closes
nothing, for the reason under "Payment capabilities".

**A scan closes a finding only on positive evidence.** An agent now registered,
a level now at the bar, a source now read in full, a population now not empty.
"No unpinned write tool" closes only when every source that could have reported
the agent's tools was read in full: `code` for a tool whose `server` is a
`code://` locator, `mcp` for any other, and, for a tool the report left out,
`code` for an agent found through `code` and `mcp` otherwise
(`toolEvidenceSourcesOf`). An agent absent from a scan closes nothing about
it, and an empty scan is a finding and never a clean result.

## The table

A reader that shows a scan as a table of agents against criteria builds it
with `buildHarnessMatrix` (`harness-matrix-model`), and does not work out a
cell, a level or a row order for itself. scanent's local results are built from
it, and Inflect's harness tab is to read it too, so two tables of one scan say
the same about each agent. [design/table-model.md](design/table-model.md)
describes what goes in and what comes out.

A cell has one of seven states, in this order. Only the first two are met:

<!-- contract:matrix-cell-states -->
`EVIDENCED`, `DECLARED`, `MET_UNEVIDENCED`, `NOT_MET`, `NOT_MET_DECLARED`, `UNANSWERED`, `NOT_READABLE`
<!-- /contract:matrix-cell-states -->

- A cell is `criterionState` over `collapseVerdicts`, so it never disagrees
  with the level.
- A declared verdict (an operator's inventory) never outvotes an observed NOT
  MET, and a cell it decides says so.
- `NOT_READABLE` is a criterion no configured reader could have reported met:
  nothing in the run could have seen it, which is not the same as `UNANSWERED`.
- An agent is given a level only when every source that could have reported a
  verdict about it was read in full (`harnessJudgementOf`). Otherwise its row
  states no level at all.
- A scan with no agents is `EMPTY`, never complete.
- Rows are read worst first (`compareHarnessMatrixRows`): not judged, below the
  bar, then by level and id.

## The integrations contract

The integrations scanner's report: what a directory has granted to the
applications in it, and who owns them. It is a report of its own beside the
agent report, written by the same run with the same signing key and the same
scan id (`report.integrations.signed.json` beside `report.signed.json`), and
neither verifier reads the other's report.

<!-- contract:integrations-ids -->
| Id | State | What it adds |
|---|---|---|
| `scanent-integrations/1` | Accepted; what scanent writes | The first integrations contract: Microsoft Entra ID's applications |
<!-- /contract:integrations-ids -->

**The same rules as the agent report.** The same byte limit, the same
canonical JSON, the same signature over the same message, and the same seven
checks in the same order (`verifySignedEnvelope`); then this contract's own
strict schema, chosen by the id the body names. The refusal codes are those of
"Verification, in order". The reference verifier is
`verifyAndParseIntegrationsReport`. Every string member is held to the same
secret-shape walk (`firstSecretShapedMember`), card numbers included.

**What it cannot carry, by its schema.** No person: a delegated grant made for
named people says how many, never who. No credential value: a credential is a
`scheme://locator` reference. No URL: no member holds one, and a reader that
later reports a webhook reports its target's host alone, because a URL's path
and query can carry a secret. No finding and no completeness flag: both are
derived by the reader (`planIntegrationsScan`, `isIntegrationsScanComplete`).

### Its body

| Member | Type | Meaning |
|---|---|---|
| `contract` | string | The contract id |
| `scan` | object | `id`, `asOf` and `scanner` (`agentId`, `version`, `manifestHash`), as in the agent report. A run's two reports carry the same `scan.id` |
| `sources[]` | 1 to `MAX_INTEGRATIONS_SOURCES` | Every integrations source the run was configured to read, read or not. Each kind once |
| `applications[]` | 0 to `MAX_APPLICATIONS` | Every application found. Each `id` once |

A **source** is `kind`, `status` (`COMPLETE` or `INCOMPLETE`), `reason`
(present exactly when `INCOMPLETE`, from the agent report's list of reasons),
`rows`, and `signInActivity`: `{ "status": "NOT_READ" }` when the source was
not configured to read sign-in activity, or `COMPLETE` or `INCOMPLETE` (with a
reason) and the rows that read returned. A sign-in read that fails leaves the
source's own status as it was.

<!-- contract:integrations-source-kinds -->
| Kind | Since | What it is |
|---|---|---|
| `entra-integrations` | `/1` | Microsoft Entra ID: applications' service principals, delegated grants and application permissions |
<!-- /contract:integrations-source-kinds -->

An **application**:

| Member | Type | Meaning |
|---|---|---|
| `id` | `entra:<directory id>:sp:<object id>` | Directory-scoped: two directories' applications never share one |
| `sourceKind` | source kind | The source that found it, one the report lists |
| `appId` | GUID or null | The application's id, the same in every directory |
| `displayName` | string or null | As the directory holds it, when it is printable, at most `MAX_DISPLAY_NAME_CHARS` characters and not secret-shaped; otherwise null |
| `origin` | `THIS_DIRECTORY`, `OTHER_DIRECTORY` or `UNKNOWN` | Which directory registered it |
| `publisherVerified` | boolean or null | Whether a verified publisher is recorded for it; null when the read could not tell |
| `owners` | 0 to `MAX_OWNERS_PER_APPLICATION`, or null | Each `kind` (`user`, `servicePrincipal`, `other`) and `id`. Null is not read; empty is read and none |
| `delegatedGrants` | object | `read` (whether the whole listing was read) and `grants[]` (at most `MAX_DELEGATED_GRANTS_PER_APPLICATION`): `resourceAppId`, `consentType` (`AllPrincipals` or `Principal`), `principalCount` (null exactly for `AllPrincipals`), `scopes[]` (at most `MAX_SCOPES_PER_GRANT`) and `unreadableScopes` (scope names seen and not reportable) |
| `applicationPermissions` | object | `read` and `permissions[]` (at most `MAX_APPLICATION_PERMISSIONS_PER_APPLICATION`): `resourceAppId`, `roleId`, and `name`, the app role's value, or null when the read could not resolve it |
| `signIn` | object | `read` and `lastSeen` (`YYYY-MM-DD` or null). A sign-in not read has no date |
| `credentials[]` | 0 to `MAX_CREDENTIALS_PER_APPLICATION` | `ref`, `ageDays` and `expires`, by reference as in the agent report |

A list whose `read` is false holds what was seen: a presence in it is real,
and an absence from it says nothing.

<!-- contract:integrations-limits -->
| Constant | Value | What it bounds |
|---|---|---|
| `MAX_INTEGRATIONS_SOURCES` | 10 | Entries of `sources` |
| `MAX_APPLICATIONS` | 5,000 | Entries of `applications` |
| `MAX_OWNERS_PER_APPLICATION` | 20 | Owners of one application: Graph expands at most 20 |
| `MAX_DELEGATED_GRANTS_PER_APPLICATION` | 200 | Delegated grants of one application |
| `MAX_SCOPES_PER_GRANT` | 300 | Scopes of one grant |
| `MAX_APPLICATION_PERMISSIONS_PER_APPLICATION` | 1,000 | Application permissions of one application |
| `MAX_CREDENTIALS_PER_APPLICATION` | 100 | Credentials of one application |
| `MAX_DISPLAY_NAME_CHARS` | 256 | A display name |
| `MAX_PERMISSION_NAME_CHARS` | 128 | A scope or permission name |
<!-- /contract:integrations-limits -->

**Completeness is derived** (`isIntegrationsScanComplete`): at least one
source, every source `COMPLETE`, and no sign-in read `INCOMPLETE`. Sign-in
activity that was not asked for leaves a scan complete, and leaves "unused"
not concluded.

### Its findings

Planned by the reader (`planIntegrationsScan`), from the body and the reader's
own window for "unused" (90 days unless set otherwise), never stated by the
scanner:

<!-- contract:integrations-finding-codes -->
| Code | Severity | Keyed by | Opened when |
|---|---|---|---|
| `INTEGRATION_HIGH_PRIVILEGE_GRANT` | HIGH | the application | It holds a permission the classification calls high: it reaches the directory, mail, files, chats or calendars, or it writes |
| `INTEGRATION_UNVERIFIED_PUBLISHER` | HIGH | the application | It holds such a permission, it is not this directory's own, and `publisherVerified` is false |
| `INTEGRATION_NO_OWNER` | MEDIUM | the application | It holds any grant, and its owners were read and are none |
| `INTEGRATION_UNUSED` | LOW | the application | Its sign-in was read, and is none or older than the window |
| `INTEGRATION_EMPTY_INVENTORY` | HIGH | the source | A source read in full reported no application: not a clean result |
<!-- /contract:integrations-finding-codes -->

**A presence counts on any read; an absence only on a whole one.** A grant
seen raises its finding even when the listing it was on stopped early. "No
high-privilege grant", "no grant" and "no sign-in" are concluded only from a
list read in full. Every question that could not be answered either way is
listed, with its reason, and is never a clean result:

<!-- contract:integrations-not-concluded -->
| Reason | Meaning |
|---|---|
| `GRANTS_NOT_READ_IN_FULL` | The application's grants were not all read, and what was read raises nothing |
| `ONLY_UNKNOWN_PERMISSIONS` | Every permission it holds is one the classification does not know |
| `PUBLISHER_NOT_KNOWN` | It holds a high-privilege grant, and the read could not tell whether its publisher is verified |
| `OWNERS_NOT_READ` | It holds a grant, and its owners were not read |
| `SIGN_IN_NOT_READ` | Sign-in activity was not asked for |
| `SIGN_IN_READ_INCOMPLETE` | Sign-in activity was asked for, not read in full, and this application was not in what was read |
| `SOURCE_INCOMPLETE` | The source was not read in full and reported no application |
<!-- /contract:integrations-not-concluded -->

**Which permissions are high is a written table** (`GRAPH_PERMISSION_CLASSES`,
`classifyPermission`), Microsoft Graph's permissions by name, each with the
classes it reaches:

<!-- contract:integrations-permission-classes -->
`DIRECTORY`, `MAIL`, `FILES`, `CHAT`, `CALENDAR`, `WRITE`
<!-- /contract:integrations-permission-classes -->

`CHAT` and `CALENDAR` are the owner's decision of 2026-11-13: reading chat or
calendar content counts as mail and files do. Reading people's profiles
(`User.Read.All`) and the directory's logs (`AuditLog.Read.All`) is in the
table with no class: profiles and logs, not content. A name in the table with
no class is low; one with a class is high. A name not
in the table, and any permission on an API other than Microsoft Graph, is
unknown: never called high, never called low, and listed for a person to
judge. An application whose only grants are unknown is not concluded either
way.

## Transport

A consumer that takes reports over HTTP takes them as scanent sends them:

```
POST <base URL>/api/t/<tenant>/admin/agents/harness-scans
Authorization: Bearer <ingest key>
Content-Type: application/json

<the signed report, byte for byte>
```

- `201` accepts it. The body may carry `complete` (boolean, as the consumer
  derived it) and `agentCount`.
- Any other status refuses it. A refusal that names its code as
  `harness_report_refused: <CODE>` in the body is reported by that code; the
  body is not otherwise read.
- scanent sends the report once and follows no redirect.

A report written to a file (`report.signed.json`) is the same bytes. The
integrations report (`report.integrations.signed.json`) has no ingest yet:
scanent writes it and prints it, and does not post it.

## What a consumer must not assume

- That a report is complete because it verifies. Completeness is per source.
- That an agent absent from a report is gone.
- That `registeredAgentId` is true. It is the scanner's claim.
- That `findings` lists what is wrong. It lists where the scanner could not
  read.
- That a later contract id reads as an earlier one. Each id is its own schema.
- That an agent whose `paymentCapabilities[]` is empty, or absent, cannot pay.

## Use the reference implementation

The code this page is written from is one npm package,
`@rodnapamet/scanent-contract` (`packages/contract`). A consumer that depends
on it verifies and reads a report with the functions named above, and keeps
no copy of its own that can drift.

> **Status: published from 0.13.2.** The release workflow published
> `@rodnapamet/scanent-contract@0.13.2` to GitHub Packages on 2026-11-13, with
> build provenance. An install of it from the registry, with a person's token
> or a workflow's, has not been tried yet. What can be checked without a registry is checked on every
> change (`packages/scanner/tests/contract-package.test.ts`): what `npm pack`
> puts in the package, that it loads and type-checks where a consumer
> installs it, and that this section names its modules.

**The name.** The package is published to GitHub Packages. Its npm registry
takes scoped packages only, and the scope is the account the package belongs
to, in lower case. This repository belongs to `RodnaPamet`, so the scope is
`@rodnapamet`. The other two packages of this repository, `@scanent/report`
and `@scanent/scanner`, are not published and keep their names.

**The version** is the scanner's: the release `v<version>` publishes
`@rodnapamet/scanent-contract@<version>`, and a published version is never
replaced. The package version says which release the code is from. What a
consumer compares is on this page: the contract ids and the ladder version.

### Install it from a release, with no token

From 0.15.0 each GitHub release carries the package's tarball and its
SHA-256: `rodnapamet-scanent-contract-<version>.tgz` and
`rodnapamet-scanent-contract-<version>.tgz.sha256`. They are the bytes the
release workflow published to GitHub Packages and attested. Download both,
check them, and install the file:

```bash
sha256sum -c rodnapamet-scanent-contract-<version>.tgz.sha256
gh attestation verify rodnapamet-scanent-contract-<version>.tgz --repo RodnaPamet/scanent
npm install --save-exact ./rodnapamet-scanent-contract-<version>.tgz
```

npm records the file's integrity hash in the lockfile, so a later install of
other bytes under the same name fails. A project that installs in CI can
also name the release asset's URL instead of a committed file; the
integrity hash still binds it. The `./` matters: without it npm reads
`name/file.tgz` as a GitHub `owner/repo` shorthand.

### Install it from GitHub Packages

GitHub Packages asks for a token on every install of an npm package, whether
the package is public or private.

1. In the consuming project, in `.npmrc` beside its `package.json`. This file
   is committed:

   ```
   @rodnapamet:registry=https://npm.pkg.github.com
   ```

   Only that scope goes to GitHub Packages. Every other package still comes
   from the registry the project already uses.

2. The token, which is never committed. On a person's machine it goes in
   their own `~/.npmrc`:

   ```
   //npm.pkg.github.com/:_authToken=<token>
   ```

   `<token>` is a GitHub personal access token (classic) with the
   `read:packages` scope, and no other. GitHub Packages does not accept a
   fine-grained token. The account the token belongs to needs read access to
   the package.

3. Add the dependency at an exact version:

   ```bash
   npm install --save-exact @rodnapamet/scanent-contract@<version>
   ```

**In a GitHub Actions workflow** of the consuming repository, use the
workflow's own token and no person's:

- once, in the package's settings on GitHub, under "Manage Actions access",
  add the consuming repository with the Read role;
- give the job `permissions: packages: read`;
- let `actions/setup-node` write the token line, and give the install step
  the token:

  ```yaml
  - uses: actions/setup-node@<commit SHA>
    with:
      registry-url: https://npm.pkg.github.com
      scope: "@rodnapamet"
  - run: npm ci
    env:
      NODE_AUTH_TOKEN: ${{ github.token }}
  ```

### Import it

Each module is imported by its own path. There is no index module.

```ts
import { verifyAndParseHarnessReport } from '@rodnapamet/scanent-contract/harness-contract';
import { planHarnessScan } from '@rodnapamet/scanent-contract/harness-findings';
import { scoreHarness } from '@rodnapamet/scanent-contract/harness-ladder';
import { canonicalJson } from '@rodnapamet/scanent-contract/canonical-json';
```

<!-- contract:package-modules -->
`audit-redact`, `canonical-json`, `cidr`, `harness-contract`, `harness-contract-rules`, `harness-findings`, `harness-ladder`, `harness-matrix-model`, `integrations-contract`, `integrations-contract-rules`, `integrations-findings`, `integrations-scopes`, `receipt-verification`
<!-- /contract:package-modules -->

- The package holds compiled CommonJS and type declarations, for Node 22 or
  later. It holds no TypeScript source, no test and no source map.
- It uses Node's `crypto`, so it runs on a server and not in a browser. The
  one exception is `harness-matrix-model`: its only runtime import is
  `harness-ladder`, which imports nothing, so a page may import those two.
  The integrations planner is the same: `integrations-findings` imports only
  `integrations-scopes` at run time, which imports nothing.
- Its one dependency is `zod`, at an exact version. A consumer that passes
  the exported schemas to its own `zod` needs that same version; with another
  one, npm installs a second copy for the package.

### Check where a tarball came from

The release attests the build provenance of the tarball it publishes.
[verify-a-release.md](verify-a-release.md#the-contract-package) has the
command.
