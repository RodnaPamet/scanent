# Phase 2 design: standalone results

Status: implemented. Every step of section 8 is built; section 10 records
what was built and where the code differs from this note. Written against the
code at commit `6a1df72`. Where this note and the code disagree, the code is right and the
note is to be corrected in the pull request that finds the difference.

Phase 2 lets somebody with no Inflect tenant run one command and open a
report. It adds local scoring, local output files, a run-to-run diff and a
ladder version. It changes nothing about what the scanner reads, and nothing
in the signed `inflect-agent-harness/3` report.

## 0. Decisions in one table

| # | Decision |
|---|---|
| D1 | Local scoring is a pure function `scoreReportLocally(input)` in `@scanent/report`. It calls the contract's `planHarnessScan`, `scoreHarness`, `collapseVerdicts`, `criterionState`, `harnessBarFor`, `isHarnessShortfall` and `isScanComplete`, and re-implements none of them. |
| D2 | The signed report is not changed by anything in this phase. Inventory facts, the ladder version and local findings live in `results.json` only. |
| D3 | An agent is NOT JUDGED (no level, no bar verdict, no shortfall) when a source that could have reported a verdict about it was not read in full. The reason is stated per agent. |
| D4 | "Registered" and "owner" without Inflect come from an optional inventory file. It matches by exact `discoveredId` only. Everything it supplies is labelled `DECLARED`, never `OBSERVED`. It can evidence the four H1 criteria and nothing above H1. |
| D5 | Every result states which criteria this run could not have evidenced, and the highest level it could have stated. Without the `inflect-register` source that level is H1. With it, H3. No reader evidences H4 or H5. |
| D6 | `outputs` is an optional config array of `file`, `stdout`, `inflect`. Absent, with an `inflect` block present, it means `[{ "kind": "inflect" }]`, which is today's behaviour exactly. The `inflect` block becomes optional. |
| D7 | The file output writes one new directory per run, `<dir>/runs/<scanId>/`, created under a temporary name and renamed into place, plus a `latest.json` pointer. Nothing existing is ever overwritten except the pointer. No run is deleted unless `retainRuns` is set. |
| D8 | `scanent diff <old> <new>` reads `results.json` files or signed reports. It never calls an agent or a credential "gone" unless the source that would have listed it was read in full in the new run. Exit codes: 0 same, 1 different, 2 error, 3 same as far as could be compared. |
| D9 | `LADDER_VERSION` is a hash of the levels, the criteria table and the bar rule. It is exported from `harness-contract.ts` and carried in `results.json` and `summary.html`. It is not in the signed body. |
| D10 | `packages/contract/src` stays the eight files the package-closure test pins. Scoring, the inventory rules, the diff and the renderers go in `@scanent/report`. This differs from the roadmap's "scoring in the contract"; section 6 says why. |
| D11 | The existing usage line stays byte-for-byte. New commands and flags are described by a new `scanent help` and by the documents. |
| D12 | No new third-party dependency. `@scanent/report` depends on `@scanent/contract` and `zod`, both already in the lockfile. CSV and HTML are written by hand. |

## 1. Local scoring (P2.1)

### 1.1 Where it sits

```
runScan()  ──►  { raw, body }                       (unchanged)
                     │
     inventory file ─┤ (optional, read and parsed by the scanner)
                     ▼
     scoreReportLocally({ body, inventory, readers, meta })   pure, @scanent/report
                     ▼
                LocalResults  ──►  results.json, agents.csv, findings.csv, summary.html
```

`runScan` is not changed. Scoring happens after signing, over the same `body`
that was signed, so the local results and the signed report describe one scan.

### 1.2 Contract functions reused

| Need | Function (module) | How it is used |
|---|---|---|
| Per-agent level, reach, blocking criteria, findings | `planHarnessScan(body, prior)` (`harness-findings`) | Called once, with the prior state of 1.3 |
| One verdict per criterion | `collapseVerdicts` (`harness-ladder`) | Over observed verdicts followed by declared ones, so a tie keeps the observed verdict |
| Level | `scoreHarness` (`harness-ladder`) | Twice per agent: over all verdicts (`level`) and over observed verdicts only (`observedLevel`) |
| Cell state | `criterionState` (`harness-ladder`) | One call per criterion per agent, over the collapsed verdict |
| Reach | taken from `PlannedAgent.reach` (which is `reachOf`) | Not recomputed |
| Bar and shortfall | `harnessBarFor`, `isHarnessShortfall` (`harness-findings`) | Only for a judged agent |
| Scan completeness | `isScanComplete` (`harness-contract-rules`) | `scan.complete` |
| Secret shapes | `looksLikeSecret`, `firstSecretShapedMember` | Section 2.6 |
| Signer fingerprint | `harnessKeyFingerprint` (`harness-contract`) | By the scanner, passed in as `meta` |

`firstSecretShapedMember` is typed to take a `HarnessReportBody` but walks any
value. Its parameter type is widened to `unknown` (a type-only change; no
caller breaks) so the results, the inventory and the diff can be walked by the
same function. `config.ts` keeps its own private walker untouched.

### 1.3 The prior state given to the planner

A standalone run has no stored state, so `PriorHarnessState` is built from the
run itself:

| Member | Value | Why |
|---|---|---|
| `previousLevels` | empty | `LEVEL_DROP` is a cross-run fact; `scanent diff` reports it |
| `acceptedShortfalls` | empty | Acceptance is an Inflect workflow |
| `openOrphanCredentials` | empty | Nothing is open before the run; the planner's `resolve` list is ignored locally |
| `registeredAgentIds` | every non-null `registeredAgentId` in the body | The scanner's builder takes that member from the `inflect-register` source alone, which read it from the register, so the row exists |
| `intakeClaims` | one entry per inventory row that matches an agent: `{ registeredAgentId: 'inventory:row-<n>', status: 'ACTIVE', deleted: false }` | See below |

The inventory uses the planner's existing "the register's own record of this
agent" path (`intakeClaims`) on purpose. The rules attached to that path are
the ones an inventory should have: a link the report itself carries wins over
it; it closes `SHADOW_AGENT` only on a complete scan; on an incomplete scan it
links the agent and neither raises nor resolves the finding. No planner code
changes, and the same rule cannot drift between Inflect and a standalone run.

`PlannedAgent.linkBasis` maps to the local `registration.basis`:
`'REPORT'` → `OBSERVED_REGISTER`, `'INTAKE'` → `DECLARED_INVENTORY`,
`null` → `NONE`. `intakeConflicts` are carried into `results.json` as
`estate.registrationConflicts` (the report's link stands).

When scoring a signed report that this scanner did not build (`scanent diff`
over a third party's report), `registeredAgentIds` trusts that report's claim.
The results say so: `registration.basis` is `OBSERVED_REGISTER` and the header
carries `registerClaimsVerified: false`.

### 1.4 When an agent is judged

A level is derived from verdicts, and unanswered counts as no, so a verdict a
partial read missed cannot raise a level by its absence. It can still leave a
level too high: a source that stopped early may have held a NOT MET for a
criterion another source reported as met, and the collapse rule would have
taken the NOT MET. So:

An agent is `JUDGED` only when both hold:

1. every kind in its `discoveredVia` is `COMPLETE` in `population.sources`;
2. every listed source that reports verdicts about agents other sources
   discover is `COMPLETE`.

Rule 2 is a table, `CROSS_AGENT_VERDICT_SOURCE: Record<HarnessSourceKind, boolean>`,
exhaustive over the source kinds so a new kind is a compile error until it is
classified. Today exactly one kind is `true`: `inflect-register` (it reports
under another source's id, for example `entra:sp:<objectId>`). `vault` and
`mcp` also attach to another source's id, but report no verdicts; a scanner
test holds that (section 7.1).

Otherwise the agent is `NOT_JUDGED` with one or more reasons, each a code and
its operands, never free text:

| Reason | Meaning |
|---|---|
| `SOURCE_INCOMPLETE:<kind>:<reason>` | A source the agent was discovered through stopped early (`<reason>` is the contract's, e.g. `AUTH_FAILED`) |
| `VERDICT_SOURCE_INCOMPLETE:<kind>:<reason>` | A cross-agent verdict source stopped early |

For a `NOT_JUDGED` agent the results carry no `level`, no `observedLevel`, no
`bar`, no `shortfall` and no `blockingNextRung`. Its `HARNESS_SHORTFALL`
finding from the planner is dropped (its title states a level). Its criterion
cells are still shown, because each is what a source actually reported, and
its `SHADOW_AGENT` and `UNPINNED_WRITE_TOOL` findings stay, because both are
positive observations. Reach is kept as the planner derived it (`UNKNOWN` when
`mcp` was not read in full).

A judged agent in a scan with some other incomplete source keeps its level and
gets `caveats: ['OTHER_SOURCE_INCOMPLETE:<kind>']`, shown beside the level.

### 1.5 The inventory file

Configured, never a flag:

```json
"inventory": { "path": "/etc/scanent/inventory.json" }
```

`path` uses the existing `absolutePath` rule of `config.ts`. The format is the
extension: `.json` or `.csv`; anything else is a configuration error. The
scanner reads the file once per scan (`packages/scanner/src/inventory-file.ts`),
refuses one larger than 5 MiB, hashes its bytes (SHA-256), decodes it, and
hands the decoded rows to `parseInventory` in `@scanent/report`. A missing or
refused inventory stops the run before any source is read: scoring against
half an inventory would report known agents as shadow agents.

JSON form (strict objects throughout; an unknown key is refused):

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

| Field | Required | Rule |
|---|---|---|
| `discoveredId` | yes | 1 to 256 characters (the contract's `MAX_ID_CHARS`); unique in the file |
| `name` | yes | 1 to 256 characters, no control character |
| `owner` | yes | 1 to 256 characters, no control character |
| `purpose` | yes | 1 to 512 characters, no control character |
| `axes` | no | All three members or none: `autonomy` ∈ `human-approves`, `human-reviews`, `autonomous`; `dataClass` ∈ `public`, `internal`, `confidential`, `restricted`; `reach` ∈ `read-only`, `write`, `external` |
| `riskTier` | no | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`; comes with `riskAssessedOn` or not at all |
| `riskAssessedOn` | no | `YYYY-MM-DD`, a real date |

At most 5,000 rows (the contract's `MAX_AGENTS`).

CSV form: RFC 4180, UTF-8, an optional byte-order mark, a header row that is
exactly a subset of `discoveredId,name,owner,purpose,autonomy,dataClass,reach,riskTier,riskAssessedOn`
containing the first four. An unknown column, a missing required column, a row
with a different number of fields or a duplicate `discoveredId` refuses the
file. An empty optional cell is "absent". The decoder is a small hand-written
state machine in the scanner (no dependency); it produces the same row objects
the JSON form does, and one schema judges both.

Refusals name the row number and the field, never the value. Before the schema
runs, the decoded rows are walked for secret shapes; a hit refuses the file by
path, as `parseScannerConfig` does.

Matching: a row matches an agent when `row.discoveredId === agent.discoveredId`,
compared as exact strings. No case folding, no trimming, no prefix, no name
match. A row that matches no agent in this scan is listed in
`inventory.unmatched` ("declared by the operator, not found by this scan") and
changes nothing else. It is not a finding and is never described as "gone".

What a matched row evidences. Each verdict's evidence is
`inventory:sha256:<first 16 hex of the file hash>#row-<n>` (`n` is the 1-based
position among the agents):

| Criterion | Verdict from a matched row |
|---|---|
| `H1.registered` | met |
| `H1.owner` | met (`owner` is required and non-blank) |
| `H1.axes_declared` | met when `axes` is present; NOT MET when absent |
| `H1.tier_scored_fresh` | met when `riskTier` and `riskAssessedOn` are present, the date is not after the scan's `asOf`, and is at most `INVENTORY_TIER_MAX_AGE_DAYS` (365) before it; NOT MET otherwise |
| every H2 to H5 criterion | never. The schema has no field for them |

Provenance. Declared verdicts are appended after the observed ones before
`collapseVerdicts`, so:

- a declared "met" never outvotes an observed NOT MET (least favourable wins);
- where both say the same, the observed verdict stands and the cell is `OBSERVED`.

Each criterion cell carries `basis: 'OBSERVED' | 'DECLARED' | null` (null when
unanswered). Each agent carries `level` (observed and declared together) and
`observedLevel` (declared verdicts removed). The inventory's `name`, `owner`
and `purpose` are stored under `declared`, apart from the `owner` a source
observed. Every surface labels declared values with the words "declared by the
operator": a column prefix in the CSV, a marker and a legend in the HTML, the
`basis` member in JSON. The marker is text, not colour alone.

Declared values go to `results.json`, the CSVs and the HTML. They never enter
the signed report and are never posted to Inflect.

Two points to confirm with the owner before implementation (the mechanism does
not depend on the answer): the three axis names and their value lists, which
are scanent's own because this repository only sees Inflect's axes as one
boolean (`axesDeclared`); and the 365-day freshness window, because Inflect's
own staleness rule is not in this repository.

### 1.6 What a standalone scan can and cannot evidence

Read from the source files at this commit: which reader's code names which
criterion. The `code` source names none itself; its verdicts come from the
contract's `AGENT_SDK_OPTION_CRITERIA` and are NOT MET only. The OpenShell
reader is left out because no configuration selects it.

| Criterion | Readers that report it |
|---|---|
| `H1.registered`, `H1.owner`, `H1.axes_declared`, `H1.tier_scored_fresh` | `inflect-register`; the inventory (declared) |
| `H2.credential_bound` | `entra-sp`, `okta-app`, `gcp-sa`, `cicd`, `inflect-register` |
| `H2.grant_kind_declared` | `okta-app`, `gcp-sa`, `cicd`, `inflect-register` |
| `H2.tools_allowlisted` | `cicd`, `inflect-register`; `code` (NOT MET only) |
| `H2.audience_tokens`, `H2.policy_card` | `inflect-register` only |
| `H3.manifests_pinned`, `H3.prior_state_reads`, `H3.delegation_narrows` | `inflect-register` only |
| `H3.propose_not_commit`, `H3.skills_declared` | `inflect-register`; `code` (NOT MET only) |
| `H3.payloads_guarded` | `inflect-register`, on the scanner's own agent only; `code` (NOT MET only) |
| `H3.egress_enforced` | `inflect-register`, on the scanner's own agent only |
| all of H4 and H5 | no reader |

Consequences, stated in every output rather than left to be inferred:

- Without the `inflect-register` source, no agent can be shown above H1,
  because `H2.audience_tokens` and `H2.policy_card` have no other reader.
- With it, no agent can be shown above H3.
- So in a standalone run every judged agent is below its bar (H2 or H3) and
  has a `HARNESS_SHORTFALL` finding. That is the ladder's rule (unanswered
  counts as no) and it is kept. What the report adds is the distinction
  between "a source saw this fail" (`NOT_MET`) and "nothing in this run could
  have seen it" (`UNANSWERED` with `readable: false`).

The table is code, not prose: `CRITERION_READERS` in
`packages/scanner/src/criterion-readers.ts`, a
`Record<HarnessCriterionId, { reportedBy: readonly ReaderKind[]; metBy: readonly ReaderKind[] }>`
where `ReaderKind` is a source kind or `'inventory'`, and `metBy` (the readers
that can report the criterion met) is a subset of `reportedBy`. It is
exhaustive by type and held to the readers by tests (section 7.1). The scanner
passes it to the scorer as `readers`, together with the kinds this run
configured. From them the scorer derives:

- per criterion, `readable`: some configured reader is in its `metBy`;
- `coverage.reachableLevel`: `scoreHarness` over a met verdict for every
  readable criterion, i.e. the highest level this run could have stated;
- `coverage.unreadable`: each other criterion with `NO_READER` (nothing in
  scanent reads it) or `READER_NOT_CONFIGURED` (a reader exists; this run did
  not configure it), and the reader kinds that would.

### 1.7 The result type

`results.json` is `canonical`-ordered JSON, pretty-printed with two spaces, of
this type. It holds no clock reading of its own: the same body, inventory and
`meta` give the same bytes.

```ts
export const RESULTS_SCHEMA = 'scanent-results/1';

export interface LocalResults {
    readonly schema: typeof RESULTS_SCHEMA;
    readonly ladder: {
        readonly version: string;                          // LADDER_VERSION, section 5
        readonly levels: readonly HarnessLevel[];
        readonly criteria: Readonly<Record<HarnessLevel, readonly HarnessCriterionId[]>>;
    };
    readonly scan: {
        readonly id: string;
        readonly asOf: string;
        readonly estate: string | null;                    // the config's label; null when scored from a bare report
        readonly contract: string;
        readonly scanner: { readonly agentId: string; readonly version: string; readonly manifestHash: string };
        readonly complete: boolean;                        // isScanComplete
        readonly registerClaimsVerified: boolean;          // false when scored from a report this run did not build
    };
    readonly report: {
        readonly sha256: string;                           // of the bytes of report.signed.json
        readonly signerKeyFingerprint: string;             // harnessKeyFingerprint(signature.signerKey)
        readonly signerPinned: boolean;                    // false: verified against the key the report itself carries
    };
    readonly inventory: null | {
        readonly provenance: 'DECLARED_BY_OPERATOR';
        readonly sha256: string;
        readonly format: 'json' | 'csv';
        readonly rows: number;
        readonly matched: number;
        readonly unmatched: readonly string[];             // discoveredIds declared and not found by this scan
    };
    readonly sources: readonly {
        readonly kind: HarnessSourceKind;
        readonly status: 'COMPLETE' | 'INCOMPLETE';
        readonly reason: string | null;                    // the contract's reason; null when COMPLETE
        readonly rows: number;
        readonly agents: number;                           // agents discoveredVia this kind
    }[];
    readonly coverage: {
        readonly reachableLevel: HarnessLevel;
        readonly unreadable: readonly {
            readonly criterion: HarnessCriterionId;
            readonly why: 'NO_READER' | 'READER_NOT_CONFIGURED';
            readonly readers: readonly string[];
        }[];
    };
    readonly estate: {
        readonly empty: boolean;                           // no agents at all: EMPTY_SCAN
        readonly agentCount: number;
        readonly judgedCount: number;
        readonly notJudgedCount: number;
        readonly byLevel: Readonly<Record<HarnessLevel, number>>;   // judged agents only
        readonly shortfallCount: number;                   // judged agents below their bar
        readonly registrationBasis: 'NONE' | 'INVENTORY' | 'INFLECT_REGISTER' | 'BOTH';
        readonly shadowAgents: readonly string[];          // discoveredIds with a SHADOW_AGENT finding
        readonly orphanCredentials: readonly { readonly ref: string; readonly sourceKind: string }[];
        readonly unboundNotConcluded: readonly {           // seen unbound; the planner could not open a finding
            readonly ref: string;
            readonly sourceKind: string;
            readonly why: 'OWN_SOURCE_INCOMPLETE' | 'IDENTITY_SOURCE_INCOMPLETE';
        }[];
        readonly registrationConflicts: readonly IntakeConflict[];
    };
    readonly agents: readonly LocalAgentResult[];          // sorted by discoveredId
    readonly findings: readonly LocalFinding[];            // planner order
}

export interface LocalAgentResult {
    readonly discoveredId: string;
    readonly discoveredVia: readonly HarnessSourceKind[];
    readonly declared: null | { readonly name: string; readonly owner: string; readonly purpose: string; readonly row: number };
    readonly observedOwner: null | { readonly kind: 'user' | 'group'; readonly ref: string };
    readonly registration: {
        readonly basis: 'NONE' | 'DECLARED_INVENTORY' | 'OBSERVED_REGISTER';
        readonly ref: string | null;                       // 'inventory:row-<n>' or the register's id
    };
    readonly judgement:
        | {
              readonly state: 'JUDGED';
              readonly level: HarnessLevel;
              readonly observedLevel: HarnessLevel;
              readonly bar: HarnessLevel;
              readonly shortfall: boolean;
              readonly blockingNextRung: readonly HarnessCriterionId[];
              readonly caveats: readonly string[];
          }
        | { readonly state: 'NOT_JUDGED'; readonly reasons: readonly string[] };
    readonly reach: StoredReach;
    readonly criteria: readonly {                          // every criterion, in ladder order
        readonly criterion: HarnessCriterionId;
        readonly state: CriterionState;
        readonly basis: 'OBSERVED' | 'DECLARED' | null;
        readonly evidence: string | null;
        readonly readable: boolean;
    }[];
    readonly counts: {
        readonly credentials: number;
        readonly tools: number;
        readonly writeCapableTools: number;
        readonly unpinnedWriteTools: number;
        readonly models: number | null;                    // null: not reported
    };
}

export interface LocalFinding {
    readonly code: HarnessFindingCode;
    readonly sourceRef: string;
    readonly severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    readonly type: 'NONCONFORMITY' | 'OBSERVATION';
    readonly discoveredId: string | null;
    readonly title: string;
    readonly description: string;
}
```

There is no agent name in the contract (sources deliberately report ids, not
display names), so the only name is `declared.name`. An agent with no
inventory row is shown by its `discoveredId`.

Findings are the planner's `assert` list, with three local rules:

1. `HARNESS_SHORTFALL` for a `NOT_JUDGED` agent is dropped (1.4).
2. Titles and descriptions are the planner's own text, except `SHADOW_AGENT`
   when the register link did not come from Inflect: the planner's sentence
   names "the agent register", which a standalone run does not have. The local
   text says "is not in the operator's inventory" when an inventory was
   supplied, and "no inventory was supplied, so no agent can be shown as
   registered" when none was. Code, `sourceRef`, severity and type are
   unchanged.
3. `EMPTY_SCAN` and `INCOMPLETE_SOURCE` are kept as they are. An empty scan
   has `estate.empty: true`, no agent rows and no level anywhere.

`estate.orphanCredentials` are the planner's `ORPHAN_CREDENTIAL` findings.
`unboundNotConcluded` is every `body.unboundCredentials` entry the planner did
not open, with which of its two conditions failed.

## 2. Outputs (P2.2, P2.4)

### 2.1 Configuration

```json
"outputs": [
  { "kind": "file", "dir": "/out", "retainRuns": 90 },
  { "kind": "stdout" },
  { "kind": "inflect" }
]
```

| Kind | Fields | Effect |
|---|---|---|
| `file` | `dir` (absolute path, the `absolutePath` rule); `retainRuns` (optional integer 1 to 10,000) | Writes the files of 2.3 |
| `stdout` | none | Writes the signed report and a newline to stdout, exactly as `--dry-run` does today |
| `inflect` | none | Posts the signed report with `postReport`, to the top-level `inflect` block |

Schema rules (`ScannerConfigSchema`, all strict):

- `outputs` is optional. When present it has 1 to 3 entries, each kind at most once.
- `inflect` becomes optional. It is required (a refused configuration, by
  path) when `outputs` holds `inflect`, when `sources` holds
  `inflect-register`, or when `egress` is set (the egress proof's allowed host
  is the ingest host).
- `inventory` is optional (1.5).

Backward compatibility. A configuration with an `inflect` block and no
`outputs` parses to the same object as today plus nothing, and resolves to
`[{ kind: 'inflect' }]`. `scan` posts and exits 0 or 1 by the answer; `scan
--dry-run` prints and posts nothing; `schedule` posts every run; the ingest
key is still required before the scan starts when, and only when, the
`inflect` output is in effect. Every existing test passes unchanged.
`credentialEnvNames` includes the ingest key only when the block exists.

### 2.2 Command line

```
scanent scan      --config <file> [--out <dir>] [--dry-run]
scanent schedule  --config <file> [--out <dir>]
scanent public-key --config <file>
scanent diff <old> <new> [--format text|json] [--trust-key <hex>] [--allow-different-scanner]
scanent help
```

The outputs in effect for one run are resolved in this order
(`resolveOutputs(config, flags)` in `packages/scanner/src/outputs.ts`, pure):

1. Start from `config.outputs`; if absent, `[{ kind: 'inflect' }]` when the
   `inflect` block exists, else `[]`.
2. `--out <dir>` sets the `file` output's `dir`, adding a `file` output if
   there is none. `<dir>` must be absolute.
3. `--dry-run` removes the `inflect` output and adds `stdout` if it is not
   there. So `--dry-run` still means "post nothing, print the report", and
   `--out <dir> --dry-run` writes the files as well.
4. An empty result is an error before anything is read: exit 2, one line on
   stderr, `nowhere to deliver: configure outputs, or pass --out or --dry-run`.

Delivery order is `file`, `stdout`, `inflect`: what stays in the estate is
written before anything leaves it. Each output is attempted whatever happened
to the others; each failure is one `error` log line naming the output kind.
`scan` exits 0 only when every output delivered, else 1. `schedule` logs and
carries on, as now.

The usage error text is unchanged, byte for byte:
`usage: scanent <scan|schedule|public-key> --config <file> [--dry-run]`. A
test pins it. `diff` and `help` are dispatched before the `--config` check;
`diff` has its own usage line. `help` prints the block above to stdout and
exits 0.

Exit codes for `scan` are not otherwise changed here. "Incomplete scan" as its
own exit code is Phase 4 (operability).

### 2.3 Files

```
<dir>/
  latest.json                    pointer, rewritten each run
  runs/
    <scanId>/
      report.signed.json         the signed report, byte for byte what would be posted
      results.json               LocalResults (1.7)
      agents.csv
      findings.csv
      summary.html
      manifest.json              file names, sizes and SHA-256 of the other five
```

`<scanId>` is the scan's own id (`<estate>-<UTC stamp>-<8 hex>`); the config
schema already restricts `estate` to `[a-z0-9-]`, so it is a safe single path
segment. It is checked again against `^[a-z0-9][a-z0-9-]{0,62}-\d{8}T\d{6}Z-[0-9a-f]{8}$`
before it is used as a name.

`latest.json`: `{ "scanId", "dir": "runs/<scanId>", "asOf", "complete", "agentCount" }`.

Why a directory per run and a pointer, not fixed names: a scheduled container
with a mounted volume writes every `everyHours`. Fixed names would destroy the
previous run, which is the evidence `scanent diff` needs and the record an
assessor asks for; and a reader opening `summary.html` while the next run
writes would see a mixture. A directory per run is created whole or not at
all. The pointer is a small JSON file rather than a symbolic link because
mounted volumes are often network or object-store file systems where links are
unsupported or unreadable from the host.

Write procedure (`packages/scanner/src/file-output.ts`):

1. Render all five payloads in memory and run the checks of 2.6. A refusal
   writes nothing.
2. `mkdir -p <dir>/runs` (mode `0o750`), then `mkdir <dir>/runs/.<scanId>.tmp`
   (mode `0o750`, not recursive: an existing one is an error).
3. Write each file with flag `wx` (fails if it exists) and mode `0o640`, then
   `fsync` it.
4. `rename` the temporary directory to `runs/<scanId>`. If the target exists
   the run fails; nothing is replaced. `fsync` the `runs` directory.
5. Write `latest.json.<scanId>.tmp`, `fsync`, `rename` over `latest.json`.
   This is the only overwrite, and it is atomic.
6. On any failure, remove the temporary directory (best effort) and report.

Modes are passed to `mkdir` and `open`; the process `umask` can only narrow
them. Group-readable, not world-readable: the container writes as uid 1000 and
a person on the host reads through the group. The files hold an inventory of
the estate; they hold no secret, by 2.6.

Retention. Nothing is deleted by default: an audit tool that removes its own
evidence unasked is worse than a volume that fills, and a full volume fails
loudly (the write fails, the run exits non-zero, the log says so). With
`retainRuns: N`, after a successful write the oldest directories under `runs/`
beyond `N` are removed, oldest by the UTC stamp in the name. Only a directory
whose name matches the scan-id pattern and that holds a `manifest.json` is
ever removed. Leftover `.<id>.tmp` directories older than one day are removed
at the start of a run.

Container. The image still runs with `--read-only`; the output directory is a
mounted volume (`-v scanent-out:/out`) writable by uid 1000. The sentence "the
scanner writes no file" in the Dockerfile and `docs/scanner.md` becomes "the
scanner writes only under the file output's directory". `deploy/smoke.sh`
gains a check that `scan --out /out --dry-run` on a read-only root with one
writable mount produces the six files and that a second run does not disturb
the first.

### 2.4 CSV

Both files: UTF-8 with a byte-order mark (the readers are spreadsheet users,
and owner names are not always ASCII), CRLF line ends, a header row, every
field quoted, `"` doubled. One function writes every cell
(`csvCell` in `@scanent/report`):

1. replace each CR, LF and other C0 control character with a space (one record
   per line, always);
2. if the first character is `=`, `+`, `-`, `@`, tab or CR, or the cell
   starts with spaces followed by one of those, prefix a single quote `'`;
3. quote.

Step 2 applies to every cell, including ones scanent wrote itself, so the rule
has no exception to get wrong. Numbers are non-negative integers.

`agents.csv`, one row per agent: `discoveredId`, `declaredName`,
`declaredOwner`, `declaredPurpose`, `observedOwnerKind`, `observedOwnerRef`,
`discoveredVia` (kinds joined by `;`), `registration`, `judged` (`yes`/`no`),
`level`, `observedLevel`, `notJudgedReasons` (joined by `;`), `reach`, `bar`,
`shortfall` (`yes`/`no`/empty when not judged), `blockingNextRung`,
`credentials`, `tools`, `writeCapableTools`, `unpinnedWriteTools`, then one
column per criterion in ladder order, named by its id, holding `EVIDENCED`,
`DECLARED` (evidenced on the operator's declaration), `MET_UNEVIDENCED`,
`NOT_MET`, `UNANSWERED` or `NOT_READABLE` (unanswered, and no configured
reader could answer). `level`, `observedLevel` and `bar` are empty for an
agent that was not judged; they are never `H0` by default.

`findings.csv`, one row per finding: `code`, `severity`, `type`, `sourceRef`,
`discoveredId`, `title`, `description`.

An empty estate gives an `agents.csv` with a header and no rows, and a
`findings.csv` holding `EMPTY_SCAN`.

### 2.5 `stdout` and `inflect`

`stdout` writes `raw + "\n"` and nothing else, so existing pipelines that read
a dry run keep working. Logs stay on stderr.

`inflect` is `scanAndPost`'s second half moved behind the output interface; the
request, its headers and its declared surface are unchanged. No new request is
added to `scanner-surface.ts` in this phase, and `scannerManifestHash()` does
not change (a test pins that).

### 2.6 Nothing secret in any output

Three layers, all before the first byte is written:

1. The body: `signReport` already refuses a secret-shaped member. Unchanged.
2. The data: `firstSecretShapedMember` over the decoded inventory (at load)
   and over the whole `LocalResults` object and the diff result. A hit refuses
   the output and names the member path, never the value.
3. The text: `looksLikeSecret` over each rendered payload as one string
   (`results.json`, both CSVs, `summary.html`, the diff text). This catches a
   renderer that assembled a secret shape out of parts. A hit names the file.

Layer 2 is the primary check, because escaping can break up a shape that layer
3 would otherwise see. A refusal is `OutputRefusedLocally` (paths only), is
logged, fails that output and leaves the others alone. The renderers' own
fixed text (class names, headings) is covered by a test that a clean fixture
passes layer 3.

## 3. `summary.html`

One file. No `<script>` element at all, no `<link>`, no `<img>`, no `<iframe>`,
no `@import`, no `url(` in the stylesheet, no web font, no inline event
handler. One `<style>` block. A
`<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">`
makes the browser enforce the same. `<meta name="referrer" content="no-referrer">`.
`<html lang="en">`, `<meta charset="utf-8">`, a viewport meta.

Escaping. The document is built by one tagged-template helper, `html`, in
`@scanent/report`: every interpolated value is escaped (`&`, `<`, `>`, `"`,
`'`, and the backtick) unless it is the result of another `html` call. There
is no "raw" escape hatch exported. Scanner data never becomes an attribute
name, a tag name, a URL, a `style` value or a class name: classes and `data-`
values are chosen from fixed lists keyed by enum values. No scanned string is
rendered as a link; evidence references and server URLs are shown as text in
`<code>`.

Order of sections (each a `<section>` with a heading and an `id`; a short
contents list links to them):

1. **Header.** Title, estate label, scan id, as-of time (UTC), one status
   line: "Complete" or "Incomplete: N of M sources were not read in full".
2. **Completeness per source.** First, before any result. A table: source,
   status, reason, rows read, agents found. An incomplete row is marked with
   the word, not colour alone. Above it, one sentence saying what incompleteness
   means for this page: which agents are not judged, and that nothing is shown
   as gone or resolved on a partial read.
3. **What this scan could not evidence.** `coverage`: the highest level this
   run could have stated, and each criterion no configured reader can answer,
   with the reader that would. When there is no inventory: "No inventory was
   supplied, so no agent can be shown as registered."
4. **Estate summary.** Agents found, judged, not judged; a count per level
   over judged agents only (a plain table, with an inline bar drawn in CSS
   width from a fixed set of classes, not from data); shortfalls; shadow
   agents; orphan credentials. For an empty scan this section is replaced by
   one block: "This scan found no agents. That is a finding, not a clean
   result", with the `EMPTY_SCAN` text, and sections 5 to 7 are omitted.
5. **Agent × criterion matrix.** Rows are agents (name when declared, id
   always), columns are the criteria grouped under their level with the
   level's name. Leading columns: registration, reach, level, bar. A cell
   shows a short text code and has a `title` and visually hidden text with the
   full state: `E` evidenced, `D` evidenced on the operator's declaration, `M`
   reported met without evidence, `N` not met, `·` unanswered, `–` not
   readable by this run. A not-judged agent shows "Not judged" in the level
   and bar cells and its reasons under its name. A legend sits above the
   table. The table scrolls horizontally inside its own container; the first
   column is sticky. Above 500 agents the matrix shows the first 500 by
   `discoveredId` and says so, naming `agents.csv` as the full list.
6. **Shadow agents.** Id, discovered via, reach. Omitted, with a sentence,
   when no inventory and no register source exist (every agent would be
   listed twice).
7. **Orphan credentials.** Reference and source; then "Seen unbound, not
   concluded" with the reason for each.
8. **Findings.** Severity, code, subject, title; description in a
   `<details>`.
9. **Inventory.** Present only when supplied: rows, matched, and the declared
   ids this scan did not find, with the words "declared by the operator".
10. **Provenance.** Scanner version, manifest hash, ladder version, contract
    id, report SHA-256, signer key fingerprint, whether the signer was pinned,
    inventory SHA-256, and the file names of the run.

Style. System font stack. Colours are custom properties on `:root`, redefined
under `@media (prefers-color-scheme: dark)`; both palettes meet 4.5:1 for text.
State is never colour alone (text codes and words throughout). Tables use
`<caption>`, `<th scope="col">` and `<th scope="row">`. A skip link is the
first element. Focus outlines are not removed.

Print (`@media print`): black on white whatever the scheme, the contents list
and skip link hidden, `<details>` content shown, the matrix at a smaller size
with `thead { display: table-header-group }` so headers repeat, `tr { break-inside: avoid }`,
each top-level section allowed to start on a new page, the scan id and as-of
time repeated in a footer line.

The page has no generation time of its own and no absolute path, so the same
results give the same bytes.

## 4. Diff (P2.3)

```
scanent diff <old> <new> [--format text|json] [--trust-key <hex>] [--allow-different-scanner]
```

Inputs. Each argument is a file path. The kind is decided by content, not by
name:

- a JSON object with `schema: 'scanent-results/1'` is parsed with the strict
  `LocalResultsSchema` and walked for secret shapes;
- a JSON object with `contract` and `signature` is a signed report. It is
  verified with `verifyAndParseHarnessReport(raw, keys)`, where `keys` is
  `--trust-key` when given and otherwise the key the report carries (integrity
  only; the output then says "signer not pinned"). It is then scored with
  `scoreReportLocally` with no inventory and the static reader table;
- anything else is an input error.

Both sides are therefore `LocalResults`, and the comparison
(`diffResults(old, new)` in `@scanent/report`, pure) has one input type. Mixed
kinds are allowed. Because a signed report carries no inventory, the diff
header states each side's inventory hash (or "none") and warns when they
differ, since declared criteria will then show as changes.

Refused (exit 2): a file that cannot be read or parsed, a failed verification,
`new.scan.asOf` not later than `old.scan.asOf`, different `ladder.version`
(levels are not comparable across ladders), and different
`scan.scanner.agentId` unless `--allow-different-scanner` (one scanner not
seeing an agent says nothing about another's).

What is compared, and the evidence rule for each:

| Section | Entry | Condition |
|---|---|---|
| Completeness | per source kind: `COMPLETE→INCOMPLETE`, `INCOMPLETE→COMPLETE`, reason changed, source added, source no longer read | always reported, first |
| Agents | `NEW` | in new, not in old |
| | `GONE` | in old, not in new, and every kind in the old agent's `discoveredVia` is `COMPLETE` in new |
| | `NOT_SEEN` | in old, not in new, and some such kind is `INCOMPLETE` or absent in new. Carries which. Never called gone |
| Levels | `LEVEL_UP`, `LEVEL_DOWN` | `JUDGED` on both sides and the level differs. Also for `observedLevel` |
| | `NOW_NOT_JUDGED`, `NOW_JUDGED` | the judgement state changed; reasons carried; no level comparison is made |
| Criteria | per agent and criterion, `state` or `basis` changed | both sides have the agent. For an agent not judged on either side the change is listed under "reported, not concluded" |
| Reach, bar, shortfall | changed | judged on both sides (reach: always) |
| Registration | basis changed | always |
| Orphan credentials | `OPENED` | in new `orphanCredentials`, not in old |
| | `CLOSED` | in old, not in new, not in new `unboundNotConcluded`, and its `sourceKind` is `COMPLETE` in new |
| | `NOT_CONCLUDED` | in old, not in new, and its source is incomplete or absent in new |
| Findings | opened and closed by `sourceRef` | a finding is "closed" only under the positive-evidence rule of its code: agent-scoped codes need the agent present and judged in new; `EMPTY_SCAN` needs agents in new; `INCOMPLETE_SOURCE` needs that source `COMPLETE` in new. Otherwise "no longer reported, not concluded" |

Output. `text` (default) is a plain report in the section order above, with a
one-line summary first and, when anything could not be concluded, a closing
block listing it. `json` is the `ResultsDiff` object. Both pass the secret
checks of 2.6 before they are written to stdout.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | No difference, and every comparison could be made |
| 1 | At least one difference |
| 2 | Usage or input error; nothing compared |
| 3 | No difference found, but at least one comparison could not be concluded (a `NOT_SEEN`, a `NOT_CONCLUDED`, a not-judged agent on either side) |

Code 3 exists so that "nothing changed" is never reported on a partial read.

## 5. Ladder version (P2.5, this repository's half)

```ts
// packages/contract/src/harness-contract.ts
export const LADDER_VERSION: string =
    `sha256:${createHash('sha256').update(canonicalJson({
        levels: HARNESS_LEVELS,
        criteria: HARNESS_CRITERIA,
        bars: {
            'read-only': shortfallBarFor('read-only'),
            'write-or-external': shortfallBarFor('write-or-external'),
            unknown: shortfallBarFor('unknown'),
        },
    }), 'utf8').digest('hex')}`;
```

It covers what changes a result: the rung order, which criterion sits on which
rung (and their order, which `blockingNextRung` follows), and the bar rule.
Display names (`HARNESS_LEVEL_NAMES`) are not included. At this commit the
value is

`sha256:b3aa459c8e48dc7dc7528f117de754cf1be24e53f7ec47c8ac81c471ec28d7ae`

and a test pins that literal, so a change to the ladder is a diff in two
places, one of them a hash nobody edits by accident.

It lives in `harness-contract.ts` because that file already imports `crypto`,
`canonical-json` and the ladder. It must not go in `harness-ladder.ts` (which
has no imports and must stay that way) or in `harness-contract-rules.ts`
(which must stay free of Node built-ins).

Carried in `results.json` (`ladder.version`, with the levels and criteria
themselves so the file is self-describing) and in `summary.html`'s provenance
section. Not added to the signed `/3` body: its schema is strict, so an extra
member would be refused by every existing verifier.

Follow-up outside this repository (Inflect's half of P2.5), recorded here and
not done here:

1. a new contract id whose `scan` object carries `ladder: <LADDER_VERSION>`,
   as a new strict schema beside `/2` and `/3`, never a widened `/3`;
2. the ingest stops refusing a report that names a criterion it does not know:
   it drops that verdict, records it as ignored with the report's ladder
   version, and accepts the rest. Today `HarnessVerdictSchema` refuses the
   whole report;
3. tests both ways (newer scanner to older ingest, older scanner to newer
   ingest).

## 6. Package boundaries

| Package | Holds | May import |
|---|---|---|
| `@scanent/contract` | The eight existing files. Two edits: `LADDER_VERSION` in `harness-contract.ts`; the parameter type of `firstSecretShapedMember` widened to `unknown` | `zod`, Node built-ins (as now) |
| `@scanent/report` | `results/score.ts` (`scoreReportLocally`), `results/types.ts` and `results/schema.ts` (`LocalResults`, `LocalResultsSchema`), `results/inventory.ts` (`InventorySchema`, `parseInventory`, declared verdicts), `results/judgement.ts` (`CROSS_AGENT_VERDICT_SOURCE`), `diff/diff.ts`, `render/escape.ts`, `render/csv.ts`, `render/html.ts`, `render/diff-text.ts`, `render/results-json.ts`. Every export is a pure function: data in, data or string out. No clock, no file, no network, no hashing | `@scanent/contract/*`, `zod`. No Node built-in at all |
| `@scanent/scanner` | `inventory-file.ts` (read, cap, hash, decode JSON or CSV), `criterion-readers.ts`, `outputs.ts` (resolve and deliver), `file-output.ts` (atomic writer, retention), `diff-command.ts` (read, verify, call the pure diff, print), and the changes to `cli.ts`, `config.ts`, `scan.ts`, `index.ts` | as now, plus `@scanent/report/*` |

Why scoring is in `@scanent/report` and not in the contract, as the roadmap's
sketch had it. `packages/scanner/tests/package-closure.test.ts` pins the
contract's source to exactly eight files, and that pin means something: the
contract is the part Inflect shares, and its file list is what the extraction
was checked against. Local results (the results schema, the inventory, the
judgement rule, the diff) are scanent's own concept and Inflect needs none of
them. Keeping them out leaves that test, and the meaning of "the contract",
as they are. If the owner prefers scoring inside the contract, the change is
to move `results/` and `diff/` there and extend that test's list in the same
pull request; nothing else in this design depends on the choice.

Wiring that follows from `@scanent/report` having code:

- `packages/report/package.json`: `exports` and `typesVersions` like the
  contract's, `dependencies: { "@scanent/contract": "0.0.0", "zod": "4.6.7" }`,
  `sideEffects: false`; a `tsconfig.json` with a reference to the contract.
- `packages/scanner/package.json`: add `"@scanent/report": "0.0.0"`;
  `packages/scanner/tsconfig.json`: add the reference.
- Root: `build` and `clean` add `packages/report`; `tsconfig.json` `paths` and
  `jest.config.js` `moduleNameMapper` gain `@scanent/report/*` → source.
- `deploy/Dockerfile` and `.dockerignore`: copy the report package's
  `tsconfig.json` and `src` into the build stage and its `dist`, `package.json`
  and `node_modules` into the runtime stage; stop removing
  `node_modules/@scanent/report`; add it to the prune step's `find` and to the
  `require` check. `packages/scanner/tests/image.test.ts` holds those lists by
  equality, so its expected lists are extended by the same lines in the same
  commit. That is the only edit to an existing test in this phase, and it
  lengthens what the test holds.
- `packages/report/README.md` and the README's package table lose "placeholder".

ESLint (`eslint.config.mjs`):

- A new block for `packages/report/src/**/*.ts`: `no-restricted-imports` with a
  pattern admitting only the report manifest's declared dependencies and no
  Node built-in (a variant of `onlyDeclaredImports` with the built-in list
  empty), and the existing `NO_RUNTIME_MODULE_LOADING` syntax list.
- In the same block, `no-restricted-globals` for `process`, `fetch`, `Buffer`,
  `setTimeout`, `setInterval`, and `no-restricted-properties` for `Date.now`
  and `Math.random`; `no-restricted-syntax` gains `NewExpression[callee.name='Date'][arguments.length=0]`.
  A renderer that reads the clock stops being a function of its input.
- The scanner block needs no edit: it reads the scanner's manifest, so
  declaring `@scanent/report` there admits it.
- The contract block is unchanged, and so the contract still cannot import the
  report package.

`package-closure.test.ts` gains cases (added, none changed): the report
package's closure escapes nowhere, imports only `@scanent/contract` and `zod`,
imports no built-in, declares exactly what it imports with exact versions.

## 7. Test plan

All tests are Jest, deterministic, with no network and a fixed clock (`now`
is already a seam). New code is aimed at 95% or better on all four metrics;
the global gate stays at 80%.

### 7.1 Scoring (`packages/report/tests/score.test.ts`, `inventory.test.ts`)

- Reuse: for a fixture body with no inventory, each agent's `level`, `reach`
  and `blockingNextRung` equal `planHarnessScan`'s; each cell equals
  `criterionState(collapseVerdicts(...).get(c))`.
- Not judged: an agent discovered via an `INCOMPLETE` source has no `level`,
  `bar` or `shortfall` member at all (asserted by key absence), carries the
  reason, and has no `HARNESS_SHORTFALL` finding; its `SHADOW_AGENT` and
  `UNPINNED_WRITE_TOOL` findings remain.
- Not judged by the cross-agent source: `inflect-register` `INCOMPLETE` makes
  every agent not judged; any other unrelated incomplete source leaves a
  judged agent judged, with the caveat.
- The property behind 1.4: for a generated set of bodies, deleting verdicts
  from a judged agent never raises its level.
- Empty scan: `estate.empty`, `EMPTY_SCAN` present, no agent rows, `byLevel`
  all zero, and no output contains a level for anything.
- Zero sources: `scan.complete` is false.
- Orphans: opened only when the planner opens them; an unbound credential with
  an incomplete identity source is in `unboundNotConcluded` with the right
  reason, and not in `orphanCredentials`.
- Inventory, schema: each refusal (unknown key, unknown column, missing
  required column, duplicate id, over-long field, control character, half an
  `axes`, tier without date, invalid date, more than 5,000 rows, wrong
  `inventory` id) names row and field and never echoes the value.
- Inventory, matching: exact id only. Rows differing by case, by surrounding
  space, by a prefix or by name match nothing and appear in `unmatched`.
- Inventory, verdicts: a full row gives H1 with `basis: DECLARED` on four
  cells and `observedLevel: H0`; missing axes gives `NOT_MET` on
  `H1.axes_declared`; a tier dated 366 days before `asOf`, or after it, is
  `NOT_MET`; 365 days is met.
- Inventory, precedence: an observed NOT MET beats a declared met; an observed
  met beside a declared met reads `OBSERVED`.
- Inventory and shadow: a matched agent has no `SHADOW_AGENT` finding; on an
  incomplete scan it is linked and the finding is neither raised nor present;
  a report-carried register link wins and the conflict is listed.
- Inventory never above H1: a table test over every H2 to H5 criterion that
  no inventory content produces a verdict for it.
- Coverage: with code-only sources `reachableLevel` is H0; with an inventory,
  H1; with `inflect-register`, H3; `unreadable` distinguishes `NO_READER`
  (all of H4 and H5) from `READER_NOT_CONFIGURED`.
- Determinism: scoring the same input twice gives byte-identical
  `results.json`; the output round-trips through `LocalResultsSchema`.
- Scanner side, `criterion-readers.test.ts`: (a) each source file is parsed
  with the TypeScript API and the criterion-id string literals it contains are
  collected; for `code` the values of `AGENT_SDK_OPTION_CRITERIA` are used.
  The set per source kind must equal that kind's entries in `reportedBy`.
  (b) Every existing source fake is run over its fixtures, and every verdict
  with `met: true` must come from a kind in that criterion's `metBy`; the
  `code` source produces none. (c) The `vault` and `mcp` fakes' observations
  carry no verdict at all (the premise of `CROSS_AGENT_VERDICT_SOURCE`).

### 7.2 Ladder version (`packages/contract/tests/harness-ladder-version.test.ts`)

- Equals the pinned literal of section 5.
- Recomputed in the test from the exported tables, it matches (the constant is
  derived, not typed in).
- A copy of the tables with one criterion moved, added, renamed or reordered,
  or one bar changed, hashes differently; a changed display name does not.
- `HarnessReportBodyV3Schema` refuses a body with a `ladder` member anywhere
  (the signed contract did not grow).

### 7.3 Outputs and config (`packages/scanner/tests/outputs.test.ts`, `file-output.test.ts`, additions to the config suite)

- Backward compatibility: every fixture configuration in the existing suites
  parses to an object deep-equal to what it parses to today; `resolveOutputs`
  gives `[inflect]`, and `[stdout]` with `--dry-run`.
- The resolution table of 2.2, row by row, including "nowhere to deliver".
- Schema: `inflect` absent is accepted alone, and refused by path with an
  `inflect` output, an `inflect-register` source, or `egress`; a duplicate
  output kind and an empty `outputs` are refused; a relative `dir` is refused.
- File output in a temporary directory: the six files exist, modes are `0o640`
  and `0o750` (under a `umask` of 0 set in the test), `manifest.json` hashes
  match, `report.signed.json` equals `raw` byte for byte and verifies,
  `latest.json` names the run.
- Atomicity: with a writer seam that fails on the n-th file, for each n no
  `runs/<scanId>` exists afterwards, no temporary directory is left, and the
  previous `latest.json` is intact.
- No overwrite: a pre-existing `runs/<scanId>` fails the run and is untouched
  (content compared).
- Two runs: two directories; the first is byte-identical after the second.
- Retention: default deletes nothing; `retainRuns: 2` after three runs leaves
  the newest two; a directory with a foreign name, or without a manifest, is
  never removed.
- Delivery: each output is attempted when another fails; the exit code is 0
  only when all delivered; order is file, stdout, inflect (recorded by seams).
- Surface: `scannerManifestHash()` equals its value before this phase, and the
  fakes see no request the surface does not declare.

### 7.4 HTML (`packages/report/tests/html.test.ts`)

- Injection: a results fixture in which every string a scanner or an operator
  controls (`discoveredId`, evidence, tool server, source reason, owner
  reference, declared name, owner and purpose, credential reference, finding
  text, scan id, estate) is one of a payload list: `<script>alert(1)</script>`,
  `"><img src=x onerror=alert(1)>`, `' onmouseover='x`, `</style><script>`,
  `javascript:alert(1)`, `&lt;` already-escaped text, a backtick template, and
  a string of `]]>` and `-->`. Assertions: the output contains no `<script`,
  no `<img`, no `<iframe`, no `<link`, no `on[a-z]+=` inside any tag, no
  `javascript:` inside any attribute, exactly one `<style>` element, and each
  payload appears only in its escaped form. The check parses the output with a
  small tag tokenizer written in the test, so "inside a tag" is decided
  structurally and not by a guess at the surrounding text.
- Self-contained: no `http://` or `https://` outside escaped text content, no
  `url(`, no `@import`, no `src=` or `href=` other than `href="#…"`.
- Order: the completeness section's offset is less than every other section's.
- Honest states: a not-judged agent's row contains "Not judged" and no `H\d`
  in its level and bar cells; the empty fixture contains the empty-scan block
  and no matrix; with no inventory the "no inventory was supplied" sentence is
  present.
- Provenance: scanner version, manifest hash, `LADDER_VERSION`, report SHA-256
  and signer fingerprint each appear.
- Accessibility basics: `lang`, one `<h1>`, heading levels that do not skip,
  a `<caption>` per table, `scope` on every `<th>`, a skip link, the dark
  media query and the print media query present; every matrix cell has text
  content.
- Determinism: two renders are byte-identical.

### 7.5 CSV (`packages/report/tests/csv.test.ts`)

- Formula: for each of `=`, `+`, `-`, `@`, tab, CR, and each preceded by
  spaces, a cell starting with it is written starting with `'`; `=cmd|' /C calc'!A0`
  and `@SUM(1+1)*cmd|' /C calc'!A0` as a declared name, an evidence string and
  a finding description each come out neutralised. A real negative-looking id
  (`-agent`) is neutralised too.
- Structure: a small RFC 4180 reader in the test parses each file back; every
  row has the header's field count; embedded quotes, commas and line breaks
  survive as data; no record spans two lines; line ends are CRLF; the file
  starts with the byte-order mark.
- Content: a not-judged agent's `level`, `observedLevel` and `bar` cells are
  empty; criterion columns are in ladder order and number 25; the empty
  fixture gives a header-only `agents.csv` and an `EMPTY_SCAN` row.

### 7.6 Secret canary (`packages/scanner/tests/output-secret-canary.test.ts`)

One table of canaries, one per shape in `SECRET_SHAPES` (built at run time
from parts so the test file itself holds no secret-shaped literal), crossed
with every place a string can enter:

- through a source: placed by a fake in a discovered id, an evidence string, a
  tool name, a server URL, an owner reference. Expect `runScan` to refuse
  (`ReportRefusedLocally`), no output directory, nothing on stdout;
- through the inventory: in `name`, `owner`, `purpose`. Expect the load to
  refuse by path, before any source is read;
- through the renderers: a `LocalResults` object built by hand with a canary
  in each string member, given to each renderer through the delivery path.
  Expect `OutputRefusedLocally` naming the path, and no file;
- a canary assembled only at render time (a renderer seam that concatenates
  two harmless halves). Expect layer 3 to refuse by file name.

In every case the test then reads everything that was written anywhere
(the temporary directory, captured stdout, captured stderr) and asserts the
canary string is absent, including from the refusal message and the log.
The same table runs through `scanent diff` in both formats.

### 7.7 Diff (`packages/report/tests/diff.test.ts`, `packages/scanner/tests/diff-command.test.ts`)

- Each entry of the table in section 4, one fixture pair each.
- The rule that matters most: an agent absent from the new run is `GONE` when
  its sources are complete in the new run, and `NOT_SEEN` when any is
  incomplete or absent; likewise `CLOSED` and `NOT_CONCLUDED` for an orphan
  credential. The text output for the second case does not contain the word
  "gone" or "closed" for that subject.
- Level changes are reported only when judged on both sides.
- Exit codes 0, 1, 2 and 3, each reached; identical inputs give 0; identical
  inputs with a not-judged agent give 3.
- Refusals: unreadable file, not JSON, a results file that fails the strict
  schema, a tampered signed report, an untrusted key with `--trust-key`,
  reversed order, different ladder version, different scanner without the flag.
- Mixed inputs (a results file against a signed report) compare, and the
  header states the inventory difference.
- `--format json` parses and equals `diffResults`' return value.

### 7.8 End to end (`packages/scanner/tests/cli-out.test.ts`)

Over `examples/code-only`, through `main`, with a generated key and `fetch`
replaced by a spy that fails the test if called:

1. `scan --config <cfg> --out <tmp> --dry-run` exits 0; stdout is the signed
   report and verifies against the key; `fetch` was not called; the run
   directory holds the six files; `results.json` parses with
   `LocalResultsSchema`, lists the one example agent, shows the `code` source
   `COMPLETE`, carries `LADDER_VERSION`, and its `report.sha256` is the hash of
   `report.signed.json`; `summary.html` names the agent's id and "no inventory
   was supplied"; `agents.csv` has one data row.
2. The same configuration with the `inflect` block removed and
   `outputs: [{ "kind": "file", "dir": <tmp> }]`: `scan` with no flags exits 0
   and writes the files; the ingest key is not required.
3. With an inventory file naming the example agent: the agent is H1 with
   `observedLevel` H0, is not a shadow agent, and the HTML carries "declared
   by the operator".
4. With a second `code` root that does not exist (an incomplete source): the
   run exits 0, the agent is not judged, and no output states a level for it.
5. A second run into the same directory, then `diff` of the two `results.json`
   files exits 0; after editing the estate copy to add an agent, `diff` exits
   1 and lists it as new.
6. `scan --config <cfg>` with no outputs, no `inflect` block and no flag exits
   2 with the "nowhere to deliver" line and reads nothing.
7. The existing `cli.test.ts` runs unchanged and passes.

### 7.9 Boundaries

- The additions to `package-closure.test.ts` and `image.test.ts` of section 6.
- A lint fixture test (as the repository's rule tests do today, or a direct
  `ESLint` API call in Jest): a file under `packages/report/src` importing
  `fs`, calling `Date.now()` or using `process` is reported; the same file
  under `packages/scanner/src` is not.

## 8. Order of work

1. `LADDER_VERSION`, the widened secret walker, their tests.
2. `@scanent/report`: results types, schema, scoring, inventory, judgement;
   package wiring, lint block, closure tests.
3. Renderers: results JSON, CSV, HTML.
4. Scanner: config (`outputs`, `inventory`, optional `inflect`),
   `resolveOutputs`, the file writer, CLI `--out`, image and smoke changes.
5. Diff: pure diff, text renderer, command.
6. Documents: README quick start (`--out`), `docs/scanner.md` (outputs,
   container volume), `examples/code-only` (an inventory example), this note
   marked implemented.

Each step ends with `npm run lint`, `npm run typecheck`, `npm run build` and
`npx jest --coverage` passing.

## 9. Open points for the owner

1. The inventory's axis names and values, and the 365-day tier window (1.5).
2. Scoring in `@scanent/report` rather than the contract (section 6).
3. Whether a later phase should let the inventory key on something other than
   `discoveredId`. This design says no: an exact id is the only match that
   cannot attach one agent's owner to another.
4. Default retention is "keep everything" (2.3).

## 10. Implementation record

Kept as the phase is built. Where the code settled a point differently from the
sections above, it is listed here and the code is right.

### Step 1 and step 2 (ladder version, local scoring, inventory): built

Built: `LADDER_VERSION` (section 5), the widened secret walker, `@scanent/report`
with `results/types`, `results/schema`, `results/score`, `results/inventory`
and `results/judgement`, and in the scanner `criterion-readers.ts`,
`inventory-file.ts`, `local-results.ts` and the `inventory` configuration
field. Not built yet: `outputs`, the optional `inflect` block, the renderers,
the file writer, `--out`, `diff` and `help`.

Differences from the sections above:

1. **Declared verdicts go through the planner** (1.2, 1.7). The planner is
   called over the body with each matched agent's declared verdicts appended
   after its observed ones, not over the bare body. Otherwise the planner's
   `HARNESS_SHORTFALL` title would state the observed level while the results
   state the level with declarations, and one file would give two levels for
   one agent. `observedLevel` is `scoreHarness` over the observed verdicts
   alone, as designed. When the two differ, the shortfall's description gains
   one sentence saying the level rests in part on the operator's declaration
   and what it is on observation alone. That is a third local wording rule
   beside the two of 1.7.
2. **The local `SHADOW_AGENT` wording applies when the report lists no
   `inflect-register` source** (1.7, rule 2). With that source listed, "no row
   in the agent register" is true as the planner words it, inventory or not.
3. **A kind in `discoveredVia` that the report does not list** makes the agent
   not judged with `SOURCE_INCOMPLETE:<kind>:NOT_LISTED` (1.4). The scanner's
   own builder never produces this; a report from elsewhere can.
4. **`metBy` for `H2.credential_bound` leaves out `okta-app`** (1.6). Okta's
   only verdict on that criterion is about an API token that acts as a person,
   and it is always NOT MET, so Okta alone does not make the criterion
   readable. The static test that reads each source's verdict literals found
   it.
5. **The property behind 1.4 is stated per criterion** (7.1). "Deleting
   verdicts never raises a level" is false for a body that answers one
   criterion twice: deleting the NOT MET of a pair raises it. That is the very
   case 1.4 describes, and the reason for the rule. A report holds one verdict
   per criterion (the scanner's builder collapses them), so the property tested
   is that leaving any set of criteria unanswered never raises a level.
6. **`scoreReportLocally`'s input** is
   `{ body, inventory, readers: { table, configuredSources }, meta }`. The
   scorer adds `'inventory'` to the configured readers itself when an inventory
   is supplied.
7. **`ladderVersionOf(ladder)` is exported beside `LADDER_VERSION`** (5), so the
   test can hash a changed copy of the ladder by the same function.
8. **Two more existing tests had their expected lists lengthened**, beside
   `image.test.ts` (section 6): `public-entry.test.ts`, because the scanner's
   entry point now exports the reader table, the inventory loader and
   `scoreScanLocally`; and `package-closure.test.ts`, which gained the report
   package's cases and changed none.
9. **CSV row numbers count records**, so a blank line between two rows is not
   counted (1.5).

Not verified in this step: a `docker build` of `deploy/Dockerfile` (no daemon
was available). The prune step's commands were run by hand over a copy of the
build context and passed.

### Steps 3 to 6 (renderers, outputs, the file writer, diff, documents): built

Built: in `@scanent/report`, `render/escape`, `render/results-json`,
`render/csv`, `render/html`, `render/files`, `render/diff-text` and
`diff/diff`; in the scanner, `outputs.ts`, `file-output.ts`, `diff-command.ts`,
the `outputs` field and the optional `inflect` block in `config.ts`, and
`--out`, `diff` and `help` in `cli.ts`; `deploy/smoke.sh` step 6; the README's
"See your results locally"; `examples/code-only/config.local.template.json`
and `inventory.example.json`.

Differences from the sections above:

1. **A not-concluded change is not a difference** (4). A criterion change for
   an agent that was not judged on one side is listed under "reported, not
   concluded" and counts towards exit code 3, not 1. A change of judgement
   (`NOW_NOT_JUDGED`, `NOW_JUDGED`) is a difference. An incomplete scan on
   either side is itself listed as not concluded (`SCAN_INCOMPLETE:<side>`),
   so two identical incomplete runs exit 3 even when they hold no agent.
2. **Two findings close on stricter evidence than "present and judged"** (4).
   `SHADOW_AGENT` closes on a register link on any scan, and on an inventory
   link only on a complete scan, which is the planner's rule (1.3).
   `UNPINNED_WRITE_TOOL` closes only on a complete scan, because the tool may
   come from a source other than the one the agent was found through. A
   finding about an agent that is `GONE` is still "no longer reported, not
   concluded" (`AGENT_GONE`): an agent absent from a scan resolves nothing
   about it.
3. **Different scanners, when allowed, conclude nothing from an absence** (4).
   With `--allow-different-scanner` no agent is `GONE` and nothing is
   `CLOSED`; each is not concluded with `DIFFERENT_SCANNER`.
4. **`ORPHAN_CREDENTIAL` findings are compared once**, in the orphan
   credentials section, and are left out of the findings section (4).
5. **An agent found through no source is `NOT_SEEN`**, never `GONE` (4): the
   rule "every kind in its `discoveredVia` is complete" is true of an empty
   list, and zero is never complete.
6. **`--out` takes an absolute path**; a relative one is exit code 2 before
   anything is read (2.2), as for the configuration's `dir`.
7. **The inventory is loaded whenever it is configured**, whichever outputs
   are in effect (2.1), so a broken inventory is found on the first run and
   not on the day somebody adds the file output.
8. **`manifest.json` names itself** (`"manifest": "scanent-run/1"`) and carries
   the scan id beside the file list (2.3).
9. **The page folds the list of unreadable criteria** into a `<details>` (3):
   in a code-only run it is all 25, and it stood between the reader and the
   results. The sentence that says what the run could have shown stays open,
   and print shows the list.
10. **A secret-shaped name in scanned code never reaches the report** (7.6).
    The `code` source already drops it, so the "through a source" canary shows
    the run delivering with the canary in no output; the refusal to sign is
    tested over every string of a report body directly.
11. **`parseScannerConfig` has an overload** (2.1): a value that carries an
    `inflect` block parses to a type that has one. It keeps
    `public-entry.test.ts`, which reads `parsed.inflect.baseUrl`, compiling
    unchanged now that the block is optional.
12. **Existing tests changed**: `public-entry.test.ts`'s export list is
    lengthened by twelve names, and nothing else. `cli.test.ts` runs unchanged.
13. **No sample output is committed.** A run's files carry its time, a random
    scan id and a signature from the key it was run with, so a committed copy
    could not be reproduced. The README gives the commands instead.
14. **Layer 3 of 2.6 reads a CSV's cell separator as a space** (2.6). Checked
    as one text, a URL with a port in one cell followed on the same record by
    a cell holding `@` matches the contract's "URL with a password" shape,
    though each cell is clean, and the whole run would be refused. Cells are
    separate values, so the `","` between two is read as `" "`; everything
    inside a cell is checked as written. The signed report is not checked as
    text at all, as 2.6 says: `signReport` already walked it.

Not verified in these steps: a `docker build` of `deploy/Dockerfile` and a run
of `deploy/smoke.sh` (no daemon was available), so step 6 of the smoke test
has been read and syntax-checked and not run. The page was checked by its
tests and by reading it; it was not opened in a browser.
