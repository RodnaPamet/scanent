# Extraction record

scanent was carved out of the Inflect Compliance repository, where it was the
package `packages/agent-harness-scanner` ("the agent harness scanner"). This
file records what was copied, from where, and what was changed or left behind.

## Origin

- Repository: Inflect Compliance, branch `main`.
- Commit copied from: `8b1cb9052834a35ef32b544266b3e2cb274d9711`.
- The copy is a snapshot. The history of the files was not carried over.

## What changed in the source

Nothing about behaviour. The complete difference between the copied source
files and their originals is:

1. Import specifiers. The original used an application path alias; here the
   scanner imports `@rodnapamet/scanent-contract/<module>` and the contract's
   own files import each other relatively. (The package was named
   `@scanent/contract` until it was given the name it is published under; see
   "What remains for the originating repository".)
2. `packages/contract/src/harness-contract.ts` type-imported two view types
   (`StoredSource`, `HarnessAgentModels`) from an application read-model file.
   That import is replaced by local, structurally identical declarations (with
   the `HarnessModelEndpointView` type the second one refers to).
3. `packages/scanner/src/cli.ts`: a `#!/usr/bin/env node` first line, the
   header comment, and the usage line's program name, now `scanent`. The
   block that ran under `require.main === module` is now an exported `run()`
   that the same condition calls, so the `scanent` / `aes` launcher
   (`packages/scanner/bin/scanent.js`) starts the process through the same
   lines.

Kept exactly as they were, because they are on the wire or in the signed
report: `SCANNER_VERSION` (`0.15.0`), `SCANNER_NAME`
(`inflect-agent-harness-scanner`), the MCP client name and the GitHub
`User-Agent`, and the contract ids `inflect-agent-harness/2` and `/3`. The id
`inflect-agent-harness/4` came later, from the same repository, and is spelt
as it is there (see "Taken from the originating repository after the copy").

Comments in the source were not rewritten, with one exception: the package
name in the header of `packages/scanner/src/index.ts`. The rest still refer to
the original repository, and those references do not resolve here:

- issue and pull-request numbers (`#3686`, …) are that repository's, not this
  one's, whatever a code host links them to;
- "owner decision", "Decision 10", "DPIA condition N" and similar refer to
  decisions recorded there;
- document paths such as `docs/agent-harness-contract.md`,
  `docs/agentic-iam-roadmap.md`, `docs/agentic-harness-scanner-dpia.md` and
  `docs/claude-agent-sdk-design.md` are files of that repository. This
  repository's `docs/` holds `scanner.md` and this file;
- paths and lint-configuration names are the original layout's (the file
  mapping below translates them).

## Taken from the originating repository after the copy

The copy above is a snapshot, and the originating repository went on changing
its own copy. These changes were brought over afterwards, by reading its
`main` at `d55726e19` and porting what scanent did not already have. Each
keeps scanent's own changes beside it.

| Change there | Commit there | Here |
|---|---|---|
| Contract `inflect-agent-harness/4`: an agent's optional `paymentCapabilities[]`, the closed lists `PAYMENT_PROTOCOLS` and `PAYMENT_CLIENT_LIBRARIES`, `MAX_PAYMENT_CAPABILITIES_PER_AGENT` and the strict `/4` schema beside `/2` and `/3`. The retired-id refusal now names `/4` | `2d4d7f220` | `packages/contract/src/harness-contract-rules.ts`, `harness-contract.ts` |
| A payment card number is secret-shaped (`containsCardNumber`, `passesLuhn`, inside `looksLikeSecret`), and `firstSecretShapedPath` walks any value, reading a number as its digits. `firstSecretShapedMember` is a wrapper over it | `0276ec9bf` | `harness-contract-rules.ts`, `harness-findings.ts` |
| The planner's `SPENDING_AGENT_UNDECLARED`, keyed by register row, with `spendingAuthority` in the prior state, `spendingAuthorityStandingOf` and `spendingUndeclaredRefOf` | `2d4d7f220` | `harness-findings.ts` |
| The planner's `UNREGISTERED_IDENTITY`: `MODEL_SIGNS`, `modelSignsOf`, `onRecordAsAgent` in the prior state, `onRecordAsAgentOf`, `unregisteredIdentitiesOnRecord`, `registrableFindingOf`. The originating repository built it from scanent's local results; it is now the contract's, and the local results use the planner's class | `fc24b93f4` | `harness-findings.ts`; `packages/report/src/results/score.ts` |
| The scanner writes `/4`: the `code` source reports each agent's payment client calls (`sources/code/payment.ts`), the report builder merges them, and a dynamic `import(…)` is named `import` in the JavaScript reader | `2d4d7f220` | `packages/scanner/src/sources/code/payment.ts`, `sources/langchain.ts`, `sources/code/javascript.ts`, `report.ts`, `source.ts`, `scan.ts`, `outputs.ts`, `scanner-surface.ts` |
| The schedule waits in steps no timer misreads (`boundedSleep`), so a cadence over 596 hours does not run scans back to back | `656f25f9b` | `packages/scanner/src/schedule.ts` |

Their tests came with them, adapted to this layout: the `/4` cases of
`harness-contract.test.ts`, the identity cases of `harness-findings.test.ts`,
the fake scanner's `/4` body and malformations, and three new suites:
`packages/contract/tests/harness-spending-agent-undeclared.test.ts`,
`packages/contract/tests/card-numbers-are-refused-as-secrets.test.ts` (its
test card numbers are named by length and first digit here) and
`packages/scanner/tests/payment-capability-code-source.test.ts`, with its
record in `packages/scanner/tests/fixtures/agent-pay-scanner/`. The two
schedule cases joined `scanner-config-and-schedule.test.ts`.

What is not the same as there, on purpose:

- **`SCANNER_VERSION` is this repository's own release line.** The
  originating repository named its `/4` scanner `0.13.0`, a number this
  repository's line had already used for something else. The release that
  first carries `/4` here takes the next version; the manifest hash moved
  with the contract id, which is part of the declared surface.
- **`firstSecretShapedMember` takes `unknown`**, as it did here before: the
  local results, an inventory and a diff input are walked by it too. Both
  copies refuse a secret-shaped member name and write `<key>` in its place
  (fixed here and there separately, the same way).
- **The refusal codes are the `HARNESS_REFUSALS` array**, and the type is
  derived from it. Same codes, same order.
- **Local results word two planner findings for a run with no register
  behind it.** `UNREGISTERED_IDENTITY` names the register or inventory this
  run read; `SPENDING_AGENT_UNDECLARED` says this run read no spending
  authority, because the scanner cannot, rather than that the register holds
  none. Codes, keys and severities are the planner's.

**Nothing contract-level is now only in the originating repository.**
`scripts/compare-inflect-copy.js <path to that repository>` compares its
eight contract files and its scanner sources with the files here, ignoring
comments and import paths, and prints every code line that is only there. At
`d55726e19` it prints none outside its list of deliberate differences: the
three above that are contract-level, and, in the scanner, lines this
repository replaced with its own hardened forms (the Python reader's work
budget, the egress proxy's address check, the file reader that follows no
link, the outputs, the command line). The list names each with its reason,
and the script reports an entry that no longer matches, so it cannot outlive
what it explains.

## File mapping

| Original path | New path |
|---|---|
| `src/lib/agentic/harness-contract.ts` | `packages/contract/src/harness-contract.ts` |
| `src/lib/agentic/harness-contract-rules.ts` | `packages/contract/src/harness-contract-rules.ts` |
| `src/lib/agentic/harness-findings.ts` | `packages/contract/src/harness-findings.ts` |
| `src/lib/agentic/harness-ladder.ts` | `packages/contract/src/harness-ladder.ts` |
| `src/lib/canonical-json.ts` | `packages/contract/src/canonical-json.ts` |
| `src/lib/mcp/receipt-verification.ts` | `packages/contract/src/receipt-verification.ts` |
| `src/lib/audit-redact.ts` | `packages/contract/src/audit-redact.ts` |
| `src/lib/security/cidr.ts` | `packages/contract/src/cidr.ts` |
| `packages/agent-harness-scanner/src/**` | `packages/scanner/src/**` (same relative paths) |
| `packages/agent-harness-scanner/README.md` | `docs/scanner.md` (rewritten, see below) |
| `tests/unit/agent-harness-scanner/*.test.ts` (15 of 17) | `packages/scanner/tests/*.test.ts` |
| `tests/helpers/agent-harness-code-fixtures.ts` | `packages/scanner/tests/helpers/agent-harness-code-fixtures.ts` |
| `tests/helpers/agent-harness-estate-fixtures.ts` | `packages/scanner/tests/helpers/agent-harness-estate-fixtures.ts` |
| `tests/helpers/agent-harness-source-fakes.ts` | `packages/scanner/tests/helpers/agent-harness-source-fakes.ts` |
| `tests/helpers/agent-harness-fake-scanner.ts` | `packages/contract/tests/helpers/agent-harness-fake-scanner.ts` |
| `tests/unit/agentic/harness-contract.test.ts` | `packages/contract/tests/harness-contract.test.ts` |
| `tests/unit/agentic/harness-findings.test.ts` | `packages/contract/tests/harness-findings.test.ts` |
| `tests/unit/agentic/harness-ladder.test.ts` | `packages/contract/tests/harness-ladder.test.ts` |
| `tests/unit/mcp-receipt-verification.test.ts` | `packages/contract/tests/mcp-receipt-verification.test.ts` |
| `tests/unit/audit-trail-redact.test.ts` | `packages/contract/tests/audit-trail-redact.test.ts` |
| `LICENSE` | `LICENSE` (verbatim) |
| `NOTICE` (the agent-action receipts section and the Apache pointer only) | `NOTICE` |

The contract package has one file the copy did not: `packages/contract/src/harness-matrix-model.ts`,
the shared table of agents against criteria
([design/table-model.md](design/table-model.md)). It was written here, from
scanent's local scorer, judgement rule, HTML page and CSV writer and from the
application's harness tab (`src/lib/agentic/harness-read-model.ts`,
`MatrixCell.tsx`, `MatrixGrid.tsx`), which it is to replace there. So the
package holds nine modules: the eight copied files and this one.
`scripts/compare-inflect-copy.js` still compares the eight, because the
application has no copy of the ninth.

Rebuilt rather than copied, because the original ran TypeScript source through
a loader at start and this image runs compiled JavaScript:

| Original | Here | What differs |
|---|---|---|
| `packages/agent-harness-scanner/Dockerfile` | `deploy/Dockerfile` | Same pinned base (`node:24-alpine` at the same digest), same removal of the package managers, same non-root user. A build stage now compiles with `tsc` and prunes to production dependencies; the runtime stage holds compiled JavaScript only. `tsx` and `esbuild` are gone; `TSX_DISABLE_CACHE` with them. `corepack` and `yarn` are asserted absent as well as `npm` and `npx`. The default configuration path is `/etc/scanent/config.json`. Since Phase 4 the runtime stage is on a distroless base, which holds no shell and no package manager to remove, and the user is uid 1000 by number (`docs/scanner.md`, "Container"). |
| `packages/agent-harness-scanner/Dockerfile.dockerignore` | `.dockerignore` | The same allowlist idea, at the repository root (this repository has one image). |
| `packages/agent-harness-scanner/container/smoke.sh` | `deploy/smoke.sh` | The five checks and the estate are the original's, line for line. Changed: the configuration mount path, the verify script's path and how it is run (plain `node`), a wider package-manager check, and one added check that the image holds no TypeScript source, `tsx` or `esbuild`. |
| `packages/agent-harness-scanner/container/smoke-verify.ts` | `deploy/smoke-verify.js` | The same checks in plain JavaScript, requiring the image's compiled contract and scanner modules. |
| `container/package.json`, `package-lock.json`, `tsconfig.json` | none | The image installs from the workspace's own lockfile. |
| the scanner blocks of the original `eslint.config.mjs` | `eslint.config.mjs` | See "Lint" below. |
| the image job of the original CI | `.github/workflows/ci.yml`, job `image` | Build, smoke test, Trivy gate at CRITICAL and HIGH, fixed only. No exemption file. |

Nothing else of the original repository was copied.

`docs/scanner.md` is the scanner's README with paths rewritten, issue numbers
removed, and three parts replaced: "What it may import" (now the package
boundary), "Running" (now the compiled CLI), and "Container" (the original
described a build, a registry and a deployment that do not exist here). Links
to the original repository's contract specification and onboarding guide were
removed; those two documents were not brought over.

## Tests

Counts are Jest's (a parameterised case counts once per row), from running the
same files in both repositories at the origin commit.

| | Suites | Tests |
|---|---|---|
| Original (the 22 test files in the mapping above, all 17 scanner suites included) | 22 | 657 |
| Carried over | 20 | 639 |
| New here (`package-closure.test.ts`) | 1 | 7 |
| This repository | 21 | 646 |

Every carried-over file had its import specifiers rewritten. Beyond that:

### Left behind

| Test | Tests | Why |
|---|---|---|
| `tests/unit/agent-harness-scanner/scanner-image.test.ts` | 8 | Holds the original Dockerfile's `COPY` lines, its build-context allowlist, its container manifest and its base image to the scanner's import closure. None of those files exist here. The closure half of the property is tested by the new `packages/scanner/tests/package-closure.test.ts`; the image half is to be re-established with this repository's own image. |
| `tests/unit/agent-harness-scanner/pilot-deployment-template.test.ts` | 8 | Reads Inflect's own deployment templates and Compose overlay, which are not part of this repository. |
| `harness-contract.test.ts`: "every reason an accepted id can carry has a label in each locale the harness tab renders" | 1 | Reads the Inflect application's translation files. |
| `harness-contract.test.ts`: "an estate may declare exactly the kinds a report can carry: the newest migration's CHECK lists SOURCE_KINDS" | 1 | Reads the Inflect application's database migrations. |

These stay in the original repository, where the files they read are. The two
`harness-contract.test.ts` cases are cross-checks between the contract and the
application (a label per reason, a database CHECK per source kind). When the
application takes the contract from `@rodnapamet/scanent-contract`, they must
stay there and be pointed at the package, or a new reason or source kind can
ship without its label or CHECK. The deployment-template suite has no counterpart here until
this repository has deployment templates of its own.

Tests in the original repository that touch one of the eight contract files
but also need the application were not candidates and stay there: the
harness read-model, estate-health, staleness and acceptance-rule suites, the
skill-enumeration suite (reads an application skill file), the receipt usecase
and receipt-chain suites (database), the contract `/2` integration suite
(database), and the egress-allowlist guard (the application's allowlist beside
the CIDR parser). `canonical-json.ts` and `cidr.ts` have no suite of their own;
they are exercised through the contract and LangSmith suites.

### Changed

| Test | What changed | Why |
|---|---|---|
| `langsmith-source.test.ts`: "agrees with the application on every address in the table, so the copy cannot drift" (now "gives every address in the table the verdict the originating application gave it…") | The expected value for each of the 22 addresses was the application's `isPrivateAddress`, called live. It is now the application's verdict recorded at the origin commit. Same addresses, same assertion per address, plus a length check. | The application function is not in this repository. The test no longer detects the application changing; it still detects the scanner's copy changing. |
| `langsmith-source.test.ts`: "agrees with the application on which addresses no allowlist may admit" (now "gives the originating application's answer…") | As above, for `isNeverAllowlistable` over 15 addresses. | As above. |
| `inflect-register-source.test.ts`: "spells the exchange as the server takes it" | The two expected values were the server's exported constants; they are now those constants' values as literals (the RFC 8693 identifiers). | The server module is not in this repository. |
| `agent-sdk-code-source.test.ts`: "the connect wizard's own snippets are each found as one SDK agent…" | The two snippets were generated live by the application's connect wizard. They are now that generator's output for the same input, recorded byte for byte at the origin commit in `packages/scanner/tests/fixtures/connect-wizard/`. | The generator is not in this repository. The test no longer detects the wizard's output changing. |
| `egress-proxy.test.ts` | The hostname used as test data was replaced with `inflect.example.com` throughout. No assertion changed. | The original value was a real hostname. |

### Added with the image

`packages/scanner/tests/image.test.ts` (11 tests) re-establishes the image
half of the original `scanner-image.test.ts` for this repository's files: the
build context allowlist equals the build stage's `COPY` sources, both stages
use one digest-pinned base, the runtime stage copies only from the build stage
and only compiled output and manifests, the package managers are removed, the
user is `node`, the entrypoint is the compiled command line. It also holds
every workflow action to a full commit SHA.

With it the repository had 22 suites and 657 tests. Later additions to that
file (the nested `node_modules` copies, the licence files and label, the
command launcher) are this repository's own and are not counted here.

One further edit to a carried-over test, made for lint: an unused type-only
import line was removed from `langchain-code-source.test.ts`. No test changed.

## Lint

The original repository held the scanner's boundaries with two lint blocks.
Both are ported in `eslint.config.mjs`:

- **What the scanner may import.** The original allowlisted the application
  modules the scanner could reach. Here the rule admits Node built-ins and the
  dependencies `packages/scanner/package.json` declares (read from the
  manifest when the configuration loads), and refuses any other bare import.
  The contract package has the same rule over its own manifest.
- **No module loaded at run time.** `import()` and `require()` are refused in
  both packages' source, because a computed specifier is an import the rule
  above cannot see. The original had this for the `code` source only; the
  source used neither anywhere, so nothing changed to pass it.
- **The `code` source never runs code.** `child_process`, `vm`,
  `worker_threads`, `module`, `cluster`, `inspector` (bare and `node:`),
  `import()`, `require()`, `eval` and `Function` are refused in
  `packages/scanner/src/sources/code/**` and
  `packages/scanner/src/sources/langchain.ts`. Same lists as the original.

Not ported: the original block's application-wide syntax bans, which concern
application code that is not here. The "one HTTP verb" property was never a
lint rule; it is the type of `ReadOnlyHttp`.

The rest of the configuration is `typescript-eslint`'s recommended set, with
unused bindings allowed when their name starts with an underscore. The source
passes it unchanged.

## Checked against the original

- With the same signing key and the same one-agent estate, the original
  scanner (run from source at the origin commit) and this repository's image
  printed dry-run reports that differ only in `scan.asOf`, `scan.id` and the
  signature. This was one small `code` estate, not every source, and the
  original was run from source, not from its image.
- `scannerManifestHash()` is the same in both repositories.

## Open items

- `LICENSE` carries scanent's own parameter block (licensor decision,
  2026-11-11): the Licensed Work is scanent (Agent Estate Scanner) in this
  repository, and the Change Date is 2030-11-11. The Additional Use Grant, the
  licensing contact and the terms below the parameters are the originating
  repository's, unchanged.
- Nothing has been released: no image, no bundle and no package has been
  published or signed. `docs/roadmap.md` and `docs/release-checklist.md` say
  what the first tag does.
- The contract package is ready to publish and is not published. It carries
  `LICENSE` and `NOTICE`, as the image does. The scanner and report packages
  stay private. The next section says what the originating repository still
  has to do.
- Four drift checks against the Inflect application became recorded values
  (the "Changed" table). They belong in the application's repository once it
  consumes the package; the next section lists them.

## What remains for the originating repository

Owner decision, 2026-11-12 (issue 7): the contract is published to GitHub
Packages, so that the Inflect application depends on it and stops carrying a
copy. This repository's half is done and is described in
[contract.md](contract.md#use-the-reference-implementation): the package is
`@rodnapamet/scanent-contract`, the release workflow packs, checks, attests
and publishes it at a version tag, and its version is the scanner's.

**Published from 0.13.2** (2026-11-13). The steps below can now be taken; none
has been yet.

The name changed with that decision. GitHub Packages takes the scope of an npm
package to be the account that owns it, so `@scanent/contract` could not be
published from a repository of `RodnaPamet`. The package is
`@rodnapamet/scanent-contract`, here and in every import.

What the Inflect Compliance repository still has to do, in order:

1. **Get access to the package.** GitHub creates a package private, and an
   install needs a token whether the package is public or private. After the
   first publish, in the package's settings on GitHub: under "Manage Actions
   access", add the application's repository with the Read role, so its
   workflows install with their own token. A person's machine, and any build
   that runs outside GitHub Actions (an image build, a cloud development
   session), needs a personal access token (classic) with `read:packages`.
2. **Route the scope.** Add `@rodnapamet:registry=https://npm.pkg.github.com`
   to the application's `.npmrc`, and give each workflow job that installs
   `permissions: packages: read` and the token
   ([contract.md](contract.md#install-it-from-github-packages) has the lines). No token goes in
   the repository.
3. **Depend on it**, at an exact version, and check `zod`. The package pins
   `zod` to one exact version (`packages/contract/package.json`). At the
   origin commit the application asked for a compatible range; if its
   lockfile resolves another version, npm installs a second copy for the
   package, and a schema of one copy is not a schema of the other.
4. **Replace the eight copies with imports, and the table with the model.** Each row of the file mapping
   above whose new path is under `packages/contract/src` is one module of the
   package: `src/lib/agentic/harness-contract.ts` becomes
   `@rodnapamet/scanent-contract/harness-contract`, and so on for
   `harness-contract-rules`, `harness-findings`, `harness-ladder`,
   `canonical-json`, `receipt-verification`, `audit-redact` and `cidr`. Then
   delete the copies. Three things to hold while doing it:
   - the package declares `StoredSource` and `HarnessAgentModels` itself
     (point 2 of "What changed in the source"), where the application's copy
     imports them from its read-model file. The two are the same shape, and
     the application keeps its own;
   - the package is compiled CommonJS that uses Node's `crypto`. It is for
     the server; nothing a browser bundle reaches may import it;
   - at the origin commit the application's own scanner package, the lint
     rule over it and its image build reached contract files by path. Each of
     those references moves to the package or goes.
   - the harness tab's table moves to `harness-matrix-model` instead of being
     replaced file for file: `MatrixCell` reads a cell's `state`, the grid
     sorts with `compareHarnessMatrixRows`, and the read model's own
     `compareMatrixRows` and its per-cell `criterionState` calls go. That
     module, unlike the rest of the package, may be imported by a client
     component: at run time it imports only `harness-ladder`. The tab's own
     columns (register name, acceptance, drift, the later-ingested level) stay
     in the application, joined to a row by `discoveredId`.
5. **Keep the two cross-checks, pointed at the package.** "every reason an
   accepted id can carry has a label in each locale" and "the newest
   migration's CHECK lists SOURCE_KINDS" ("Left behind", above) read the
   application's translation files and migrations. They stay in the
   application and import `INCOMPLETE_REASONS` and `SOURCE_KINDS` from the
   package, or a new reason or source kind ships without its label or CHECK.
6. **Restore the four live drift checks there.** The four rows of the
   "Changed" table that became recorded values here compared the scanner
   with the application live: the two LangSmith address tables
   (`isPrivateAddress`, `isNeverAllowlistable`), the two RFC 8693 identifiers
   of the token exchange, and the connect wizard's two snippets. This
   repository cannot see the application, so the live comparison can only be
   made there, against this repository's scanner at a named release.
7. **Take a new version on purpose.** A release here that changes a contract
   id, a limit or the ladder says so in its notes and changes
   [contract.md](contract.md). The application moves to it by changing one
   exact version, in a pull request that its own contract tests run on.

Nothing in this repository checks that the application did any of this, and
until it has, the two copies can differ (issue 7).
