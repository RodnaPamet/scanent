# Several scanners in one scanent

> **Status: decided; the integrations scanner built and released (0.15.0,
> posted to Inflect from 0.16.0); the vulnerability scanner designed, not built
> (2026-11-15).** The owner decided the shape: one scanent with several
> scanners, the integrations scanner first, then the vulnerability scanner,
> which is also the adversarial reviewer: a static, model-assisted audit of
> code scanent already reads, which sends nothing to a client's agents and runs
> nothing it reads. The owner's answers to this page's questions are under
> "Decisions" at the end. The integrations scanner reads Entra
> (`entra-integrations`), Okta (`okta-integrations`) and GitHub
> (`github-integrations`, with the organisation's webhooks by host)
> ([scanner.md](../scanner.md#the-integrations-scanner)). Not built: the
> Google Workspace reader and the vulnerability scanner
> ([its design](vulnerability-scanner.md)).

## What exists today

scanent has one scanner: the agent scanner. Its sources (`packages/scanner/src/sources/`)
read an estate with read-only credentials, its report is the contract
`inflect-agent-harness/4` (`docs/contract.md`), its results are scored on the
harness ladder, and its outputs are the signed report, two CSVs, the summary
page and, from the next release, a PDF.

Most of what makes that safe to run at a client is not specific to agents:

| Part | Where | Specific to agents? |
|---|---|---|
| Read-only wire (GET only, one declared token exchange) | `packages/scanner/src/http.ts` | No |
| Declared request surface and its hash in every report | `packages/scanner/src/scanner-surface.ts` | No |
| Host checks, egress proxy, byte and time caps | `customer-host.ts`, `egress-proxy.ts` | No |
| Signing key, signature, canonical JSON | `report.ts`, `packages/contract/src/canonical-json.ts` | No |
| Configuration file, secret files, `init`, `doctor`, `hosts` | `config.ts`, `secrets.ts`, `init.ts`, `doctor.ts` | The command shells no; their per-source content yes |
| Outputs (`file`, `stdout`, `inflect`), schedule, support bundle | `outputs.ts`, `schedule.ts`, `support-bundle.ts` | No |
| Image, Compose, Helm chart, air-gapped bundle, release | `deploy/`, `.github/workflows/release.yml` | No |
| The honesty rules: an incomplete source closes nothing, zero is never complete, a value that cannot be read is not reported | everywhere | No |
| Sources, report schema, ladder, findings planner, table model | `sources/`, `packages/contract/src/harness-*` | Yes |

## Proposal

### One platform, several scanners

A **scanner** is a set of source kinds, a report contract, a planner that turns
a report into findings and results, and a section of the outputs. The platform
is everything in the table above that is not specific to agents. Each scanner
uses the platform and adds nothing to it but its own sources.

- **One image and one declared surface.** The surface lists every request any
  scanner can make; its hash stays in every report. A client reviews one
  network statement (`docs/network-and-permissions.md`), grouped by scanner.
- **One configuration file.** Which scanners run follows from the sources
  configured: each source kind belongs to exactly one scanner. A product read
  by two scanners (Entra, for agents and for integrations) is two source kinds
  with two entries, which may name the same credential variables.
- **One run, one signed report per scanner.** Each report names its own
  contract id and the run id they share. The agent scanner's file keeps its
  name (`report.signed.json`), so nothing that reads it today changes; the
  others are `report.<scanner>.signed.json`.
- **One results page and one PDF per run**, with a section per scanner, and the
  CSVs per scanner.
- **`doctor`, `init` and `hosts`** group their output by scanner.
- **Contract ids.** The agent scanner keeps `inflect-agent-harness/*`, because
  it is on the wire and Inflect ingests it. New scanners take
  `scanent-<scanner>/<n>`: `scanent-integrations/1`, `scanent-vulnerabilities/1`,
  `scanent-agent-review/1`. Each is a strict schema of its own, verified by the
  same signature rules.
- **Inflect.** Each scanner has its own signed ingest route, ingest key scope,
  tables with one write seam each, and its own tab. Nothing a new scanner sends
  is read by the agent ingest.

"How a new source is added" in `docs/security-pack/support-and-maintenance.md`
becomes "how a new scanner is added" plus the existing per-source steps.

### The integrations scanner (first)

What a client's directories have granted to third-party applications, and
whether anybody owns those grants. It extends what the agent scanner already
knows about credentials and owners.

Readers for version 1 are Entra, Okta and GitHub (owner decision,
2026-11-13); Google Workspace follows later. All are GET requests on the
products' documented APIs:

| Product | What is read | Least privilege |
|---|---|---|
| Microsoft Entra ID | Service principals with their verified publisher; delegated grants (`oauth2PermissionGrants`); application permissions (`appRoleAssignments`) | `Application.Read.All`, `Directory.Read.All`. Sign-in activity needs `AuditLog.Read.All` and a licence that records it; without it, "unused" is not concluded |
| Okta | Applications and their grants | Read-only Administrator |
| GitHub | App installations of the organisation, with their permissions and repository selection; organisation webhooks (target host only) | A fine-grained token with organisation Administration read and Webhooks read |
| Google Workspace | Third-party application access per user (Admin SDK tokens) | Domain-wide delegation with the user security read scope. Per-user reads are many; version 1 may leave this product out |

Findings for version 1 (owner decision, 2026-11-13: the first four):

- An application holds a high-privilege grant (directory, mail, files, or any
  write scope), HIGH.
- That application's publisher is not verified, HIGH.
- An application with any grant has no owner, MEDIUM.
- An application has not signed in within a window the client sets (90 days
  by default), where sign-in activity is readable; where it is not, the
  finding is not concluded and the report says why.

Not in version 1: linking an application to an identity the agent scanner
reported.

The same rules as the agent scanner: a source read in part closes nothing, an
empty inventory is a finding, and a webhook's URL is reported by host only,
because its path and query can carry a secret.

### The vulnerability scanner, which is also the adversarial reviewer (second)

Decided on 2026-11-15 (decisions 9 to 12): a static, model-assisted audit of
the code scanent already reads, which never runs that code and never sends a
request to a system it describes. It replaces both the alert-reading
vulnerability scanner and the separate adversarial reviewer this page first
proposed. Its design, and the questions still open, are on its own page:
[The vulnerability scanner](vulnerability-scanner.md).

## Decisions

Taken by the owner on 2026-11-13:

1. **The agent report keeps `inflect-agent-harness/*`.** New scanners take
   `scanent-<scanner>/<n>`.
2. **One declared surface for the image**, grouped by scanner, with one hash
   (as proposed; not separately asked).
3. **Integrations version 1 reads Entra, Okta and GitHub.** Google Workspace
   later.
4. **Integrations version 1 raises the four findings above**: high-privilege
   grant (HIGH), unverified publisher (HIGH), no owner (MEDIUM), unused for 90
   days by default.
5. **The adversarial reviewer's model runs where the client says**: off by
   default; a model the client hosts, or a named external provider the client
   opts in to (Anthropic, Azure OpenAI or Bedrock). Its host is declared in
   the network statement and named in the report.
6. **Chat, calendar and site content is high-privilege** (2026-11-13). A
   Microsoft Graph permission that reads chat, calendar or SharePoint site
   content counts as a high-privilege grant, as mail and files do: for example
   `Chat.Read.All`, `ChatMessage.Read.All`, `Calendars.Read`,
   `Calendars.ReadBasic.All`, `Sites.Read.All`, and their delegated and `.All`
   variants that read others' content. `User.Read.All` and `AuditLog.Read.All`
   stay below the bar (profiles and logs, not content), and are classified as
   such rather than left unknown
   (`packages/contract/src/integrations-scopes.ts`).
7. **An integrations-only configuration runs on its own** (2026-11-13). Which
   scanners run follows from the sources configured, with no agent source
   required; a run of the integrations scanner alone writes no agent report
   and no agent section, and says on its page and in its PDF which scanners
   ran.
8. **An empty GitHub organisation is a LOW finding** (2026-11-13). A GitHub
   organisation read in full with no app installed and no webhook raises
   `INTEGRATION_EMPTY_INVENTORY` at LOW, with text saying that an organisation
   with no apps is possible and asking to confirm the token can see
   installations. An empty Entra directory or Okta org stays HIGH
   (`EMPTY_INVENTORY_SEVERITY`, `packages/contract/src/integrations-findings.ts`).
9. **The vulnerability scanner does not read GitHub's alerts** (2026-11-15).
   It reviews code itself, following the method of Cloudflare's
   `security-audit-skill` (MIT): reconnaissance, hunting by attack class, an
   adversarial validation pass, and the verdicts `confirmed`,
   `needs_validation` and `rejected`.
10. **It never runs the code it reads and never touches a live system**
    (2026-11-15). A lead that would need running code stays
    `needs_validation`. From SnailSploit's `Claude-Red` (MIT) only the
    reporting vocabulary is taken (CWE, OWASP Top 10 and API Top 10, MITRE
    ATT&CK ids); none of its offensive techniques are shipped or sent to a
    model.
11. **It is the adversarial reviewer** (2026-11-15). One scanner, not two;
    decision 5's rules about where its model runs apply to it.
12. **Its findings go to Inflect's existing scanner tables** (2026-11-15),
    `ScannerRun` and `ScannerFinding`, through a signed ingest with a key of
    its own.
