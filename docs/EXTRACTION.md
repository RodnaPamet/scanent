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
   scanner imports `@scanent/contract/<module>` and the contract's own files
   import each other relatively.
2. `packages/contract/src/harness-contract.ts` type-imported two view types
   (`StoredSource`, `HarnessAgentModels`) from an application read-model file.
   That import is replaced by local, structurally identical declarations (with
   the `HarnessModelEndpointView` type the second one refers to).
3. `packages/scanner/src/cli.ts`: a `#!/usr/bin/env node` first line, the
   header comment, and the usage line's program name, now `scanent`.

Kept exactly as they were, because they are on the wire or in the signed
report: `SCANNER_VERSION` (`0.12.0`), `SCANNER_NAME`
(`inflect-agent-harness-scanner`), the MCP client name and the GitHub
`User-Agent`, and the contract ids `inflect-agent-harness/2` and `/3`.

Comments in the source were not rewritten. They still mention the original
repository's paths, issue numbers (`#3686`, …) and lint configuration.

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

Rebuilt rather than copied, because the original ran TypeScript source through
a loader at start and this image runs compiled JavaScript:

| Original | Here | What differs |
|---|---|---|
| `packages/agent-harness-scanner/Dockerfile` | `deploy/Dockerfile` | Same pinned base (`node:24-alpine` at the same digest), same removal of the package managers, same non-root user. A build stage now compiles with `tsc` and prunes to production dependencies; the runtime stage holds compiled JavaScript only. `tsx` and `esbuild` are gone; `TSX_DISABLE_CACHE` with them. `corepack` and `yarn` are asserted absent as well as `npm` and `npx`. The default configuration path is `/etc/scanent/config.json`. |
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

These stay in the original repository, where the files they read are.

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

With it the repository has 22 suites and 657 tests.

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

- `LICENSE` is a verbatim copy. Its "Licensed Work" parameter still names
  Inflect Compliance and that repository, and its Change Date is that work's.
  Restating the parameters for scanent is the licensor's decision.
- The base image is Alpine, so the image contains a shell even though nothing
  uses one to start the scanner. A distroless base is a later step.
- No image is published, signed or given an SBOM. The image is built for the
  runner's architecture only.
- Three drift checks against the Inflect application became recorded values
  (the "Changed" table). Once Inflect consumes `@scanent/contract`, the checks
  that compare the two sides belong in the application's repository.
