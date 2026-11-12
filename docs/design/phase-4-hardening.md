# Phase 4: hardening

A plan written from the code at `190f3fb`. It covers the read-only proof,
hostile input, scale and partial failure, the supply chain, cluster and overlay
tests, operability, the threat model and privacy, and two cleanups.

The work is split into two builder tasks that share no file. The split is at
the end, under "Two builders".

## What exists today

| Area | State |
| --- | --- |
| Declared surface | `packages/scanner/src/scanner-surface.ts`: `SCANNER_SURFACE`, `isDeclaredRequest`, `isDeclaredMcpMessage`, `isDeclaredRegisterMessage`, `isDeclaredRegisterExchange`, `isDeclaredGatewayCall`, `scannerManifestHash`. |
| Recorder | `createSourceFakes` (`tests/helpers/agent-harness-source-fakes.ts`) logs every request. Each source suite holds its own log to the surface, in its own way. `doctor.test.ts` does the same for the preflights. There is no single test over all of them, and none asserts the method table. |
| Limits | `http.ts`: 4 MiB per response, 64 MiB per source, one deadline per source (`timeBoxSeconds`, 10 to 3600). 429 is `RATE_LIMITED`, 5xx `UNREACHABLE`, with no retry. `sources/code/files.ts`: 1 MiB per file, 20,000 files, 128 MiB in total, links never followed. Contract: 5 MiB per report, 50 sources, 5,000 agents, 10,000 unbound credentials, 20,000 findings. |
| Secret scan | `looksLikeSecret` and `firstSecretShapedMember` (contract), `firstSecretShaped` (`config.ts`), `assertNoSecretShape` (`file-output.ts`), the log scrub (`log.ts`), `output-secret-canary.test.ts`. |
| Host checks | `customer-host.ts` (literal and resolved addresses, private CIDR allowlist, the hand-over to a checking proxy) and `egress-proxy.ts` (CONNECT only, port 443, exact hosts, resolves and connects to the address it checked). |
| Results | `scanent-results/1`, `scanent-inventory/1`, `scanent-doctor/1`. `MATRIX_MAX_AGENTS = 500` in `render/html.ts`. |
| Image | `node:24-alpine` by digest, compiled JS, npm removed, user `node`. 285 MB. |
| CI | `ci.yml`: checks on Node 22 and 24, image build with smoke and Trivy, chart lint and render. `release.yml`: per-architecture build, bundle, publish on a pushed tag, release. Nothing is signed. |

## Measured for this plan

These were run in the build sandbox on 2026-11-12.

**Two builds give the same files.** `npm run clean && npm run build` twice:
210 files under `packages/*/dist`, the same SHA-256 for every one.

**Renderers at scale** (one agent cloned, two credentials each, three findings
per agent):

| Agents | `summary.html` | `results.json` | `findings.csv` | Render time | Heap growth |
| --- | --- | --- | --- | --- | --- |
| 500 | 5.0 MB | 3.6 MB | 0.8 MB | 0.2 s | 90 MB |
| 2,000 | 8.1 MB | 14.5 MB | 3.0 MB | 0.6 s | 207 MB |
| 5,000 | 14.3 MB | 36.3 MB | 7.6 MB | 0.9 s | 560 MB |

The matrix cap does its job, but the page still grows with the estate: about
1.4 MB per thousand agents outside the matrix, and 5 MB at the cap itself. A
14 MB page with 15,000 table rows is not usable. See C4.

**Distroless** (`gcr.io/distroless/nodejs24-debian13:nonroot`, digest
`sha256:9fc11f6e…56e3`): the runtime stage builds on it, and `scanent --help`
runs with no network, a read-only root and no capabilities. The image is
257 MB, 28 MB less. `deploy/smoke.sh` fails at step 1. Three things break:

1. The smoke test runs `id`, `sh` and `command -v` inside the image in seven
   places. There is no shell.
2. `node` is not on the path. `deploy/compose.egress.yaml` and the chart's
   `egress-proxy.yaml` start the proxy with `node …`.
3. The user is `nonroot` (65532), not `node` (1000). Compose defaults
   `SCANENT_UID` to 1000.

`typescript` is 24 MB of the 32 MB under `/app`. The Node binary and its
libraries are the rest of the image, on either base.

## A. Read-only proof (P4.2)

### A1. One recorder test over every source and every preflight

New `packages/scanner/tests/read-only-proof.test.ts`, with
`tests/helpers/request-recorder.ts`.

The helper wraps a `FetchLike` and records method, URL, the header names
(never values) and the body. It classifies each request against the surface
into one of: declared read, declared token exchange, declared MCP message,
declared register message, declared register exchange, declared ingest post.
Anything else is `UNDECLARED`.

The test is one table. Each row is a source kind from `SourceConfigSchema`
and runs twice: the source's scan read through `runScan`, and its preflight
through `runDoctor`. Assertions per row:

- No request is `UNDECLARED`.
- Every request is a GET, except those the surface lists under
  `authenticates`, `lists`, `readsRegister` and `sends`. The allowed
  non-GET set is derived from `SCANNER_SURFACE`, not written in the test.
- A request to a host fixed by kind goes to that origin.
- A POST to an MCP server carries a body `isDeclaredMcpMessage` accepts.
  A POST to `/api/mcp` or `/api/mcp/token` goes to the configured Inflect
  origin and nowhere else.
- The row made at least one request, or the source is `code`. A row that
  records nothing proves nothing.
- The `code` row: the recording `CodeFs` saw only `lstat`, `readdir` and
  `readFile`, as `readsFiles.operations` says.

Two exhaustiveness checks close the table:

- Its rows equal the kinds of `SourceConfigSchema`. A new source fails the
  test until it has a row.
- Every path in `SCANNER_SURFACE.reads` was requested by some row. A declared
  path nobody requests is a wider declaration than the code needs.

A mutation case proves the detector: a source wrapped to issue one extra
`DELETE` and one GET to an undeclared path fails both assertions.

**Gap to close while here.** `isDeclaredRequest` accepts a POST to
`/api/mcp`, `/api/mcp/token` and a gateway RPC path on any host, because the
host is configured. The proof test holds the host; the function stays as it
is, since changing it is not needed and its callers pass no configuration.

### A2. `docs/network-and-permissions.md`, generated

New `scripts/render-network-and-permissions.js`, in the style of
`scripts/render-access.js`: it reads the built `scanner-surface.js` and
`init/access-guide.js` and prints the document. `npm run docs:network` writes
it.

Content, per source: the hosts (fixed, or "the host you configure"), the
method and every path, what is read there, the grant the access guide asks
for, and what is never requested (taken from the access guide and from the
"must never make" list the fakes already carry as `NEVER_REPORTED`). Then:
the token exchanges, the one optional post to a tenant, the egress proof, the
local file operations, and the manifest hash with the scanner version.

New `packages/scanner/tests/network-and-permissions-doc.test.ts` renders the
document in memory and compares it with the committed file, byte for byte.
A stale file fails with the command to run. A second case asserts the
document names every path in the surface.

## B. Hostile input (P4.3)

### B1. A seeded generator, in the repository

New `packages/scanner/tests/helpers/prng.ts`: `mulberry32` (or xorshift32),
plus `pick`, `int`, `bytes`, `unicodeString` (lone surrogates, bidi controls,
NUL, very long lines) and `mutate(buffer)` (flip, drop, repeat, splice).
No dependency.

Every property test takes its seed and its iteration count from one helper:

- `FUZZ_SEED` (default: a fixed constant, so CI is reproducible).
- `FUZZ_ITERATIONS` (default 200 per property, a few seconds in all).
- `npm run test:long` sets `SCANENT_LONG=1`, which raises the default to
  50,000 and enables the suites that are skipped otherwise.

A failure prints the seed and the iteration, and the input is written to a
temporary file, never into the assertion message (it may be megabytes).

### B2. Properties

New `packages/scanner/tests/fuzz-*.test.ts`, one file per target.

| Target | Entry point | Property |
| --- | --- | --- |
| Response parsers | each source's `read` over a fake that answers mutated JSON, wrong types, deep nesting, huge strings, duplicate keys, a `Link` or `nextLink` that points off-origin or at itself | never throws out of `runScan`; the source is `COMPLETE` or `INCOMPLETE` with a contract reason; an off-origin next link is never followed; a paging loop ends inside the time box and the 64 MiB cap |
| Python tokenizer and reader | `tokenizePython`, `readPython` | returns or throws `PythonReadError`, nothing else; time is linear in input length (a 1 MiB file inside a stated bound); no token spans beyond the input |
| JS reader | `readJavaScript` | returns or throws `JavaScriptReadError`; never evaluates (a planted side effect in the text is not observed) |
| Recognizer | `recognizeAgents` over generated `FileFacts` | never throws; `callsWithin` stops at its depth |
| CSV and inventory | `decodeCsvRecords`, `decodeInventoryCsv`, `loadInventoryFile` | returns records or `malformedAtRecord`; round trip with the report package's CSV writer for generated fields; a refusal never quotes the cell |
| Configuration | `parseScannerConfig`, and `main` given a mutated file | `ConfigError` or a configuration; the message never repeats a value from the file |
| Diff input | `loadDiffSide`, `runDiff` | `DiffInputError` or a result; an input over `MAX_DIFF_INPUT_BYTES` is refused before it is parsed |
| Contract | `verifyHarnessReport`-style parse of a mutated signed report, `parseAddress` | a typed refusal, never a throw. `parseAddress` currently throws on an over-long IPv6 literal (#12); fix it and pin the case |

Anything a property finds is fixed in the source and pinned as a named case
beside the property.

### B3. A hostile repository, built at test time

New `packages/scanner/tests/hostile-repository.test.ts`. The tree is built in
a temporary directory in `beforeAll`, so nothing hostile is committed:

- a link to its own parent, a link out of the root, a dangling link;
- a file over 1 MiB, and a sparse file that claims gigabytes;
- nesting 2,000 directories deep;
- more files than `MAX_FILES`, and a total over `MAX_TOTAL_BYTES` (through a
  fake `CodeFs` for the byte count, so the test does not write 128 MiB);
- binary files with a `.py` name, invalid UTF-8, a UTF-16 file with a BOM;
- a file named with a newline, and one named like an option (`--out`);
- a FIFO where the platform allows it (must not be opened);
- a file that changes between `lstat` and `readFile`, and one that vanishes,
  through a `CodeFs` that swaps the content.

Assertions: the read ends inside its time box; nothing outside the root is
opened (the recording `CodeFs` proves it); each problem is reported with a
reason; the source is `INCOMPLETE`, never complete with fewer files; memory
stays under a stated bound.

### B4. SSRF and rebinding

New `packages/scanner/tests/ssrf.test.ts`.

`customer-host.ts`:

- a table of address spellings that must be refused: decimal, octal and hex
  IPv4, short forms (`127.1`), IPv4-mapped and IPv4-compatible IPv6, NAT64,
  zone ids, a trailing dot, upper case, `[::]`, userinfo in the URL, a port
  other than 443 where the rule says so;
- cloud metadata addresses (`169.254.169.254`, `fd00:ec2::254`) are refused
  with the allowlist set to their range (`isNeverAllowlistable`);
- a name that resolves to one public and one private address is refused;
- rebinding: a `ResolveHost` that answers public first and private second.
  State what the code guarantees and test exactly that: the check and the
  connection use the same answer where the scanner connects itself, and the
  proxy connects to the address it checked. If the direct path resolves
  twice, that is a finding to fix (pin the address for the connection) or to
  record as a residual risk in the threat model, with the proxy as the
  mitigation;
- a redirect to a private address is not followed.

`egress-proxy.ts`, against a real listener on loopback:

- any method but CONNECT, a port other than 443, a host off the list, a host
  on the list in a different spelling, a request line of 64 KiB, a slow
  client, a header flood: each is refused or closed, and the proxy keeps
  serving;
- an allowlisted name that resolves to loopback, link-local or a private
  address is refused, and no upstream socket is opened;
- the resolver answers differently on a second call: the proxy resolved once.

### B5. Secret canaries through every source

Extend the existing approach in a new
`packages/scanner/tests/source-secret-canary.test.ts`, with canaries from
`helpers/output-fixtures.ts` (built from parts, so no literal).

For each source fake, plant a canary in every string field of every response
that the fixture can carry: names, descriptions, labels, tags, owners, tool
names, model endpoints, error bodies, response headers, a `WWW-Authenticate`
value, a redirect location. Run `scan --out`, `scan` to stdout, `doctor`,
`doctor --json`, `hosts`, and `diff` over the results.

Assert the canary is absent from every file written, stdout, stderr, every
log line, every thrown message, and the support bundle once it exists. Where
a field legitimately reaches the report, the run is refused with the member's
path and writes nothing.

The credentials the scanner is given (the fakes' `*_VALUE` constants) get the
same treatment: after a full scan with every source failing in turn, none of
them appears anywhere.

## C. Scale, soak and partial failure (P4.4)

### C1. A synthetic estate

New `packages/scanner/tests/helpers/synthetic-estate.ts`: from a seed and
three numbers (agents, credentials, sources) it builds fixtures for the
existing fakes, paged the way each API pages. Default shape for the scale
suite: 5,000 agents, 10,000 credentials, and as many configured sources as
the contract's `MAX_SOURCES` (50) allows.

### C2. Scale assertions

New `packages/scanner/tests/scale.test.ts`. The full shape runs under
`SCANENT_LONG=1`. A bounded shape (500 agents, 1,000 credentials, 10
sources) always runs.

- The scan finishes, signs, and the report parses under its own schema.
- Heap growth and wall time stay under stated ceilings, set from a first
  measurement with headroom, and written beside the test with the numbers
  measured.
- At the contract's caps: 5,001 agents, or a report over 5 MiB, is refused
  locally with a named reason and writes nothing. It is not truncated. Check
  what a realistic 5,000-agent report weighs against the 5 MiB cap; if a real
  estate of that size cannot be reported, say so in `docs/scanner.md` and
  open an issue, because the cap is the contract's.
- `diff` reads two 5,000-agent results files inside its 64 MiB cap.

### C3. The partial-failure matrix

New `packages/scanner/tests/partial-failure-matrix.test.ts`. Rows are source
kinds; columns are failures injected through `Fakes.override`:

| Failure | Expected reason |
| --- | --- |
| connection refused | `UNREACHABLE` |
| never answers (fake clock past the deadline) | `TIME_BOX` |
| 401, 403 | `AUTH_FAILED` |
| 429, with and without `Retry-After` | `RATE_LIMITED` |
| 500, 502, 503 | `UNREACHABLE` |
| body cut mid-JSON, wrong content type, HTML error page | the reason the wire gives today, pinned per source |
| second page fails after a good first page | incomplete, and the first page's agents are still reported |
| a response over 4 MiB, a source over 64 MiB | the size reason |
| token exchange fails | `AUTH_FAILED` |

For every cell:

- the source is `INCOMPLETE` with that reason in the signed report;
- the other sources are unaffected and each still has its full deadline;
- `results.json` states no level for an agent whose sources were incomplete;
- no finding is closed, and `diff` against a clean earlier run reports
  nothing as resolved;
- `summary.html` shows the source as not read, first on the page, and the
  words for a clean result do not appear;
- `scan --strict` exits 3.

One more row: every source down at once. The scan is an `EMPTY_SCAN`
finding, not a clean bill.

### C4. `summary.html` at scale

Measure by section first (matrix, per-agent detail, findings, credentials)
and record the numbers in the test file. Then cap what grows:

- every per-agent section shows the first `MATRIX_MAX_AGENTS` agents by id,
  worst first, and a notice with the number shown, the number in the run,
  and the file that holds the rest (`agents.csv`, `findings.csv`,
  `results.json`);
- the counts at the top are always over the whole run;
- nothing is dropped from the other files.

Tests in `packages/report/tests/html-scale.test.ts`: at 5,000 agents the page
is under a stated size (target 6 MiB; set the real figure from the
measurement), the notice is present with the right numbers, the header counts
equal the full run, and at 500 agents the page is unchanged from today.

### C5. Soak

- `packages/scanner/tests/schedule-soak.test.ts`, always on: `runOnSchedule`
  for 1,000 runs under injected `now` and `sleep`, with a `run` that fails,
  overruns and throws non-errors on a seeded pattern. Assert: the run count,
  no drift (each start is anchored to the previous start), an overrun is
  followed at once, every failure is logged once, and heap does not grow
  with the run count.
- `scripts/soak.js`, opt-in (`npm run soak -- --hours 72 --every-seconds 60`):
  a real-time loop of the built CLI against the offline example and a local
  fake server, writing one line per run (duration, RSS, exit code, output
  size) and failing on RSS growth past a bound or a missed run. A five-minute
  run is the check that the script works. The 72-hour run needs the owner's
  machine or a long-lived runner.

## D. Supply chain (P4.1)

### D1. `release.yml`

Added to `publish`, which gains `id-token: write` and `attestations: write`:

1. **Sign by digest.** After the manifest is created, read its digest and
   each architecture's digest with `docker buildx imagetools inspect`, then
   `cosign sign --yes ghcr.io/rodnapamet/scanent@sha256:…` for the three.
   Keyless, through the workflow's OIDC token. `sigstore/cosign-installer`
   pinned at `756fe2d284c7292c4e9b62c8a28f1e5629c59532` (v4.1.3), with the
   cosign version named in `with:`.
2. **SBOM.** CycloneDX JSON per architecture, made by Syft through
   `anchore/sbom-action` at `66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c`
   (v0.24.3), in the `build` job from the image that was smoke-tested, with
   the Syft version pinned in `with:`. Syft reads the image's OS packages and
   `node_modules`, which is what a client asks about. It is uploaded as an
   artifact, attached to the image with `cosign attest --type cyclonedx`,
   and attached to the release.
3. **Provenance.** `actions/attest-build-provenance` at
   `4d101475d8b20a2381f78447822ac1eab6504dd8` (v4.2.2) with
   `subject-name` the repository and `subject-digest` the manifest digest,
   `push-to-registry: true`. The images are built with
   `--provenance=false` and stay so: the attestation is made for the digest
   that was tested, not by a second build.
4. **The bundle.** `build-bundle.sh` already takes `SCANENT_SBOM_CMD`; the
   workflow passes the Syft command, so `sbom/<arch>.cdx.json` is in the
   tree. After the bundle is built: `cosign sign-blob --yes --bundle
   SHA256SUMS.sigstore.json SHA256SUMS`. The signature file is stored beside
   the bundle and inside it under `signatures/`.
5. **Release.** The release holds the bundle, its SHA-256, the SBOMs and the
   signature bundle. The note drops "Nothing here is signed yet".

The tag derefs above were resolved with `git ls-remote` on 2026-11-12. The
builder resolves each again before use and uses the commit a tag points to,
not an annotated tag's own object.

`verify.sh` in the bundle:

- always checks that `sbom/` holds a non-empty CycloneDX file per image, or
  the explicit "no SBOM" notice (never both, never an empty file);
- when `signatures/SHA256SUMS.sigstore.json` is present and `cosign` is on
  the path, runs `cosign verify-blob --bundle … --certificate-identity …
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
  SHA256SUMS` and fails if it fails. A Sigstore bundle carries the
  transparency-log proof, so this works with no network (`--offline`);
- when the signature is present and `cosign` is not, says so in one line and
  exits non-zero unless `--no-signature` is given. Silence would read as
  verified.

`deploy-templates.test.ts` already runs `verify.sh` and `load.sh` against a
built bundle with a stub runtime. It gains cases with a stub `cosign` on the
path: present and passing, present and failing, absent, signature absent.

### D2. `docs/verify-a-release.md`

The exact commands, with the identity spelled out:

```
cosign verify ghcr.io/rodnapamet/scanent:<version> \
  --certificate-identity "https://github.com/RodnaPamet/scanent/.github/workflows/release.yml@refs/tags/v<version>" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

Then: verifying the SBOM attestation, `gh attestation verify
oci://ghcr.io/rodnapamet/scanent:<version> --repo RodnaPamet/scanent`, the
bundle's checksum and blob signature, and what each check does and does not
prove. A test holds the identity string in the document equal to the
workflow's path and tag pattern.

### D3. CI gates

| Gate | Decision | Why |
| --- | --- | --- |
| Grype beside Trivy | Add. `anchore/scan-action` at `27805bf3b4e84b4a5c980df22ed233c00390a439` (v7.4.2), fail on high, fixed only | A second database catches what one misses; one more minute. |
| Licence allowlist | Add, as `scripts/check-licences.js` | Reads `package-lock.json`, takes production packages only, reads each `license` from `node_modules/*/package.json`, fails on anything outside the allowlist or with no licence. No dependency. The four runtime packages make a short list. |
| `npm audit` | Add: `npm audit --omit=dev --audit-level=moderate` in `checks`, and a weekly scheduled run | Trivy scans the image; this catches it at the pull request. Retries on a registry error, and fails closed after them. |
| CodeQL | Add `codeql.yml`: `javascript-typescript`, on pull requests, pushes to main and weekly. `github/codeql-action` at `33d7b85da1a04171e211befe2c739303b9a4c066` (v4.39.3) | The repository is public, so it costs nothing. `security-events: write` on that job only. |
| OpenSSF Scorecard | Add `scorecard.yml`, weekly and on pushes to main, `ossf/scorecard-action` at `fa7117db83c52d787ae5a89f350999701505d78e` (v2.5.0), results to code scanning; `publish_results: true` only once the owner agrees to the public badge | A client's security team reads the score. It also checks the pinning and permissions this plan relies on. |
| Dependency review action | Skip | Dependabot, `npm audit` and the licence script cover it for four runtime packages. |
| Secret scanning in CI | Skip a third-party scanner | GitHub's own secret scanning and push protection are settings the owner turns on. Listed in the release checklist. |
| Fuzzing service (OSS-Fuzz, ClusterFuzzLite) | Skip | The in-repository properties with a long budget cover the parsers; a service adds a moving part for little. |

### D4. Reproducible build

`scripts/check-reproducible-build.js`: build, hash every file under
`packages/*/dist`, clean, build again in a copy of the tree at a different
path and with a different `TZ` and `SOURCE_DATE_EPOCH`, compare. It prints
the first file that differs. A CI step runs it. A Jest case runs the
comparison function over two fixture trees (same, one byte different, one
file missing), so the detector is proved without two builds in `npm test`.

Image reproducibility (same digest from two builds) is not claimed: the base
is pinned, but `npm ci` timestamps and layer metadata differ. The document
says so.

### D5. Distroless (#11)

Adopt only if the whole smoke test passes on it. The work that makes that
possible:

1. Rewrite the in-image checks of `smoke.sh` so they need no shell: read the
   user from `docker image inspect`, and prove the absence of npm and of a
   shell by running `node -e` with `fs.existsSync`.
2. Use the absolute Node path in the Dockerfile's entrypoint, the Compose
   overlay and the chart's proxy container, or set `PATH` in the image.
3. Decide the user: keep uid 1000 with `USER 1000:1000` (no change for
   Compose, the chart and the documents), not `nonroot`.
4. Run steps 1 to 10 of the smoke test, the Trivy and Grype gates, and the
   Compose and chart tests.

If any step cannot pass, keep Alpine, record why in #11, and still do the
part that needs no new base: the smoke test asserting there is no package
manager. Pruning `typescript` to its parser is evaluated separately and
adopted only if `require('typescript')` and both code readers still pass
their suites inside the image; it removes at most about 20 MB.

## E. Cluster and overlay tests (#18)

### E1. kind

New `chart-install` job in `ci.yml`. `helm/kind-action` at
`ea822c7bf1874f08e5a491df991c228edffc3376` (v1.15.2), with the kind and node
image versions pinned.

1. Build the image, `kind load docker-image`.
2. Create the namespace, a Secret with a signing key made by `scanent
   keygen` in the job, and a ConfigMap from `examples/code-only`.
3. `helm install` with `ci/base-values.yaml` and the image set to the loaded
   one, `pullPolicy: Never`.
4. `kubectl create job --from=cronjob/…`, wait for completion, read the
   pod's log and the output volume through a second pod.
5. Assert: the job succeeded, `results.json` parses, the pod ran as non-root
   with a read-only root, and no pod restarted.
6. The NetworkPolicy: kind's default CNI does not enforce policy. Either
   install Calico in the job and prove a pod of the release cannot reach a
   host off the list, or state in the job and in `docs/deployment.md` that
   enforcement is not tested. Prefer the first if it adds under three
   minutes.

Nothing is pushed. The job has `contents: read` only.

### E2. MCP through the Compose egress overlay

New step 11 in `deploy/smoke.sh`, and `deploy/smoke-mcp-server.js`: a small
HTTPS MCP server (the three declared messages, a self-signed certificate
made in the step) run from the image itself on the proxy's outer network.

`docker compose -f compose.yaml -f compose.egress.yaml` with `EGRESS_ALLOW`
naming the fake server, its address range in
`EGRESS_PRIVATE_CIDR_ALLOWLIST`, and the certificate as the extra CA.
Assert: the scan reports the MCP source `COMPLETE` with the fake's tools; the
proxy's log has one `egress allowed` for that host; a second run with the
host off the list reports the source `UNREACHABLE` and the proxy logs
`egress refused`; the scanner container has no route out except the proxy.

### E3. `--user` (#14)

Step 7 of the smoke test already scans as the invoking user. What is left:
the same step under Podman with `--userns=keep-id`, run in CI on a runner
that has Podman (`ubuntu-24.04` does), as a second invocation of the smoke
test with `CONTAINER_RUNTIME=podman`. If rootless Podman cannot run on the
runner, say so in #18 and leave it for the owner's machine.

## F. Operability (P4.5)

### F1. `scanent support-bundle`

New `packages/scanner/src/support-bundle.ts`, wired in `cli.ts`.

`scanent support-bundle --config <file> [--out <file>] [--include-identifiers]`
writes one JSON document, `scanent-support/1`, to a file or stdout:

| Member | Content |
| --- | --- |
| versions | scanner, contract ids, ladder version, manifest hash, Node, platform, architecture |
| config | source kinds and counts, output kinds, schedule, time box, which credential variables are named and whether each is set (from env, from file, absent). No value, no URL, no estate name |
| environment | proxy variables present or not, CA bundle present or not, the two egress variables. Presence only |
| doctor | the doctor report, with hosts and labels replaced |
| lastRun | from `latest.json` in the output directory if there is one: per-source status and reason, counts, exit code, durations |

Without `--include-identifiers`, every estate identifier is replaced by a
stable token (`host-1`, `agent-1`, `source-1`) made by a keyed hash with a
key that lives for the one run, so the same thing reads the same within a
bundle and cannot be matched across bundles. With the flag, hosts, labels
and discovered ids are kept; secrets are still never read.

The whole document passes `assertNoSecretShape` before it is written, and
the command never resolves a secret's value: it reads `secretOrigin`, not
`resolveSecretEnv`.

Tests (`packages/scanner/tests/support-bundle.test.ts`): the schema; a
canary in every credential variable and secret file is absent; every host,
label, estate name and agent id of the configuration and the last run is
absent by default and present with the flag; the same identifier maps to the
same token within one bundle and to a different one in the next; the command
makes no network request without a doctor section being asked for; a missing
output directory gives `lastRun: null`, not an error.

### F2. Log fields

New `docs/operations.md`: every log event (`msg`), its level and its fields,
with types; the exit codes; the files of a run. A test collects every
`log.info|warn|error('…')` literal in `packages/scanner/src` with the
TypeScript parser and fails when one is missing from the document or the
document names one that no longer exists.

### F3. Upgrade and compatibility

Fixtures under `packages/scanner/tests/fixtures/compat/0.12.0/`, produced
once from a checkout of `190f3fb` by running the offline example:
`report.signed.json`, `results.json`, `latest.json`, an inventory in CSV and
JSON, a doctor report, and the example configurations.

`packages/scanner/tests/compat.test.ts`:

- each fixture still parses with the current code, and `diff` between the
  old results and a current run of the same example works;
- the old signed report still verifies with its key;
- a results file with an unknown schema id (`scanent-results/2`), a missing
  id, and a known id with an unknown member are each refused with a message
  that names the schema found and the ones this version reads. It is never
  half-read;
- the same for the inventory;
- every example configuration under `deploy/examples` from that commit still
  parses.

A rule for the future goes in the release checklist: a release adds a
fixture directory; none is deleted while that version is supported.

### F4. `SECURITY.md`

At the repository root: report through GitHub Security Advisories (private
vulnerability reporting, which the owner enables in settings), what to
include, what is in scope (the scanner, the image, the chart, the bundle),
supported versions, and the expected response. No e-mail address.

### F5. `docs/release-checklist.md`

Before the tag (versions agree in `scanner-surface.ts`, the chart and the
changelog; generated documents are current; long tests and the soak were
run and where the record is), the tag, after it (verify the signature and
attestations with the commands of D2, load the bundle on a machine with no
network), and the settings that must be on (private vulnerability reporting,
secret scanning, push protection, branch protection on main).

## G. Threat model and privacy

### G1. `docs/threat-model.md`

- **Assets:** the credentials the scanner is given; the signing key; the
  estate's inventory as read; the signed report and the local results; the
  client's network position.
- **Trust boundaries:** operator to CLI (configuration, inventory, answers
  file); scanner to each provider API; scanner to an MCP server or
  OpenShell gateway the estate names; scanner to the file system of a code
  root; scanner to the egress proxy and the proxy to the outside; scanner to
  the output directory; scanner to a tenant's ingest; the release pipeline to
  the client.
- **STRIDE per boundary**, one table each. Every mitigation names the file
  and the function that carries it, and the test that holds it. For example:
  tampering with a response is bounded by `http.ts` (size, time, strict
  parse) and held by the fuzz and matrix suites; information disclosure in
  outputs by `assertNoSecretShape` and the canary suites; elevation through
  scanned code by the static readers and the lint rules that ban
  `child_process`, `vm`, `eval` and dynamic import under `sources/code`.
- **Residual risks**, stated plainly: a credential with more than read access
  is the client's to prevent (`doctor` warns where it can see it); a
  compromised provider API can lie about the estate; the Okta token listing
  may show only the scanner's own tokens (#16); a secret-shaped object key is
  printed in a contract refusal path (#17, owner decision); DNS rebinding on
  the direct path if B4 finds it; no independent penetration test has been
  done.

A test checks that every `packages/…` path the document cites exists.

### G2. `docs/data-protection.md`

What personal data the scanner reads (owner names and e-mail addresses on
applications and service principals, user ids on tokens, names in an
operator's inventory, names in code comments are not read), per source and
per field; what it writes and where (report, results, CSV, HTML, logs:
which fields carry a person); what it never reads (credential values, mail,
files, message content, run inputs and outputs); retention
(`retainRuns`); transfers (none unless the tenant output is configured);
and the roles (the client is the controller; who runs the scanner is a
processor).

Then a DPIA template the client fills in: purpose, lawful basis, data
categories (pre-filled from the table), recipients, retention, security
measures (pre-filled with references to the threat model), risks and
residual risks, consultation, sign-off.

## H. Cleanups

### H1. Tool-evidence sources in results (#13)

- `packages/report/src/results/types.ts` and `schema.ts`: an optional
  `toolEvidenceSources: ('code' | 'mcp')[]` per agent in `scanent-results/1`.
  Optional, so a file written before this still reads.
- `score.ts` fills it from the contract's `toolEvidenceSourcesOf`.
- `diff/diff.ts`: an `UNPINNED_WRITE_TOOL` finding is closed only when every
  listed source, in both runs, is present and `COMPLETE`. When the member is
  absent (an older file), fall back to today's rule from `discoveredVia`
  and mark the result as decided on the older rule.
- Tests: the issue's case (an agent found through `code` with an `https://`
  tool, the new run listing only `code`: not closed); both members present;
  one side older; the schema accepts absence and refuses an unknown value.
- `docs/scanner.md` gains the member.

### H2. Comments and the contract specification (#10)

Scope decided here:

1. **`docs/contract.md`, written from the code.** The normative document for
   someone writing a consumer: the three schema ids and what each adds, every
   member with type and limit (from `harness-contract.ts`), the canonical
   JSON rule, the signature (what is signed, the key encoding, verification
   order: size, JSON, signature by a trusted key, strict schema of the id
   named), the reasons a report is refused, source kinds and incomplete
   reasons, the ladder (levels, criteria, how a level is derived, "unanswered
   counts as no"), the findings a consumer plans, and the transport. A test
   holds the limits and the enumerations in the document equal to the
   exported constants.
2. **Comments.** In `packages/contract/src` and `packages/scanner/src`
   (except `cli.ts`, which the other builder owns and cleans), replace each
   reference to an issue number, an owner-decision date or a document path of
   the originating repository with the reason it stood for, or with a
   reference to `docs/contract.md`. No code changes: the diff is comments
   only, and a test asserts the built JavaScript under `dist` is byte for
   byte what it was before (comments are stripped from neither, so compare
   with comments removed, using the TypeScript printer).
3. **A guard:** a test fails on `#\d{4}` and on the old document paths in
   those two source trees, so the references do not return.
4. **Not changed:** `SCANNER_NAME`, the MCP client name and the GitHub
   User-Agent. They are in the manifest hash and in what a provider sees, so
   changing them is an owner decision. Listed in the issue.

`docs/EXTRACTION.md` keeps its one statement of where the code came from.

## What proves each item

| Item | Proved by |
| --- | --- |
| A1 | `read-only-proof.test.ts`, with its mutation case and the two exhaustiveness checks |
| A2 | `network-and-permissions-doc.test.ts` (stale file, every path named) |
| B1, B2 | `fuzz-*.test.ts`, short in `npm test`, long under `SCANENT_LONG=1` |
| B3 | `hostile-repository.test.ts` |
| B4 | `ssrf.test.ts` |
| B5 | `source-secret-canary.test.ts` |
| C2 | `scale.test.ts` (bounded always, full under `SCANENT_LONG=1`) |
| C3 | `partial-failure-matrix.test.ts` |
| C4 | `html-scale.test.ts` |
| C5 | `schedule-soak.test.ts`; `scripts/soak.js` for the real-time run |
| D1 | `deploy-templates.test.ts` (workflow shape, `verify.sh` with a stub `cosign`); the first tagged release for the real thing |
| D2 | a test on the identity string |
| D3 | the gates themselves in CI; `check-licences` has a unit test over a fixture lockfile |
| D4 | the CI step; a unit test of the comparison |
| D5 | `deploy/smoke.sh` on the new base, plus `image.test.ts` |
| E1 | the `chart-install` job |
| E2 | step 11 of `deploy/smoke.sh` |
| F1 | `support-bundle.test.ts` |
| F2 | the log-fields test |
| F3 | `compat.test.ts` |
| G1 | the cited-paths test |
| H1 | cases in `diff.test.ts` and `score.test.ts` |
| H2 | the constants test on `docs/contract.md`, the comment guard, the comments-only check |

Coverage stays at or above 80% on all four metrics; it is 92 / 87 / 90 / 93
today. New source files (`support-bundle.ts`) come with their tests.

## What cannot be done here

In the build sandbox:

- **GitHub-hosted steps.** Keyless signing, attestations, CodeQL, Scorecard
  and the kind job run only on GitHub. They are written, checked for shape by
  tests, and first run when pushed. Signing and attestation first run on the
  first tag, which the owner pushes.
- **Helm and kind.** Helm is not installed; an `alpine/helm` image renders
  the chart. kind was not tried.
- **arm64.** Images are built for amd64 only here.
- **Podman.** Not installed.
- **A real corporate proxy.**

Without the owner:

- **Real estates.** Every source is tested against fakes. False positives
  and negatives per provider need pilots (roadmap 4.5).
- **The 72-hour soak.** The script and a short run are delivered; the long
  run needs a machine that stays up.
- **An external penetration test and code review** (roadmap 4.6).
- **Repository settings:** private vulnerability reporting, secret scanning,
  push protection, branch protection, and whether the image and the
  Scorecard result are public (#19).
- **Owner decisions already open:** the contract's secret-shaped key (#17),
  the scanner's name in the manifest (#10), Okta token visibility (#16).

## Two builders

No file is touched by both. Where both need something from a shared file,
one owns it and the other is told what to expect.

**Builder 1: A, B, C, H.**

- New tests and helpers under `packages/scanner/tests/` named above for A, B
  and C, and `packages/report/tests/html-scale.test.ts`.
- `scripts/render-network-and-permissions.js`, `scripts/soak.js`,
  `docs/network-and-permissions.md`, `docs/contract.md`.
- `package.json`: the scripts `docs:network`, `test:long` and `soak`. Only
  this builder edits `package.json` and `jest.config.js`.
- Source, for fixes the tests find and for C4, H1 and H2: everything under
  `packages/contract/src`, `packages/report/src`, and `packages/scanner/src`
  except `cli.ts` and `support-bundle.ts`.
- `docs/scanner.md`, and the existing tests of the files it changes
  (`diff.test.ts`, `score.test.ts`, `html.test.ts`, `cidr.test.ts`, the
  source suites).

**Builder 2: D, E, F, G.**

- `.github/workflows/*` (including a manual `long-tests.yml` that runs
  `npm run test:long`, a script Builder 1 adds), `.github/dependabot.yml`.
- `deploy/**`, with `packages/scanner/tests/deploy-templates.test.ts` and
  `image.test.ts`.
- `scripts/check-licences.js`, `scripts/check-reproducible-build.js`, run as
  `node scripts/…` from the workflows, so `package.json` is not touched.
- `packages/scanner/src/support-bundle.ts` and `cli.ts` (the new command, and
  the comment cleanup of H2 for that one file), with
  `support-bundle.test.ts`, `compat.test.ts`, the fixtures under
  `tests/fixtures/compat/`, the log-fields test and the cited-paths test.
- `SECURITY.md`, `README.md`, `docs/verify-a-release.md`,
  `docs/operations.md`, `docs/release-checklist.md`, `docs/threat-model.md`,
  `docs/data-protection.md`, `docs/deployment.md`, `docs/quick-start.md`.

Three points where one waits on the other:

1. Builder 2's compatibility fixtures are made from a checkout of `190f3fb`,
   so they do not depend on Builder 1's change to the results schema, and
   they are the test that the change is additive.
2. The support bundle is added to Builder 1's canary run by Builder 2, in
   `support-bundle.test.ts`, not by editing Builder 1's file.
3. The threat model cites tests Builder 1 writes. It names them as this note
   does; the cited-paths test is run after both have landed.

## What was run: D, E, F and G

Recorded after the second builder's half, on 2026-11-12, in the build sandbox
(Docker 29.8, Node 22, amd64).

**Run for real.**

| What | Result |
|---|---|
| The image on the distroless base | Built. 257 MB on disk (61.6 MB compressed), from 285 MB (68.6 MB) on Alpine |
| `deploy/smoke.sh`, all eleven steps, on that image | Passed, including step 11: an MCP server through `compose.yaml` with `compose.egress.yaml`, allowed and then refused, and no direct route from the scanner's network |
| The same smoke test on the earlier Alpine image | Fails at step 1, naming `/bin/sh`, `/bin/busybox` and `/sbin/apk`: the check detects what it is for |
| A scan as an arbitrary user (`--user 12345:23456`) into a `0700` directory | The run is `0750`, its files `0640`, all owned by that user |
| Trivy, critical and high, fixed only, on the distroless image | No finding |
| `scripts/check-licences.js` | 7 production packages, all allowed |
| `scripts/check-reproducible-build.js` | 216 files, the same from two builds in two directories, two time zones and two clocks |
| The air-gapped bundle from a real amd64 image and a real arm64 image (cross-built without emulation, never run), with a CycloneDX SBOM of each | Built; `verify.sh` passes; one changed byte, one added file and one emptied SBOM each fail; `load.sh` with no local image loads the amd64 archive, and the smoke test passes on what it loaded |
| The chart, rendered by Helm 3.19 (the `alpine/helm` image): the test suite with `REQUIRE_HELM=1`, `helm lint --strict` with each value set, and the exact values `deploy/kind-test.sh` installs with | Passed |
| Compatibility fixtures | Made by a build of `190f3fb` |

**Not run.** Each is written, reviewed against the action's or the tool's own
documented inputs, and held for shape by tests.

- Keyless signing, the SBOM attestation, the provenance attestation and
  `cosign verify`: they need GitHub's identity token. `verify.sh` was run
  against a stand-in `cosign`, never a real one, so `cosign verify-blob
  --offline` with a Sigstore bundle is unproved, on a connected machine and on
  one with no network.
- The SBOMs in the run above were made by Trivy, which was at hand. The release
  makes them with Syft, through `anchore/sbom-action`. That step, and the Grype
  gate, were not run.
- `deploy/kind-test.sh` and the `chart-install` job: kind could not be
  installed in the sandbox. Whether kind's own network plugin enforces the
  default NetworkPolicy is the script's step 5, and is unproved until the job
  runs. The script fails, and says why, if it does not.
- The `image-podman` job: Podman is not installed. Step 7 was run with Docker's
  `--user` only, and as root, which is the sandbox's user.
- CodeQL, Scorecard, the `npm audit` gate and `long-tests.yml` as workflows.
  `npm run test:long` itself was run by the first builder.
- The arm64 image was built and bundled, never started.

**Decisions.**

- Distroless is adopted (#11). The three things that broke are closed: the
  smoke test reads everything through the image's own `node`, `PATH` puts
  `node` where the Compose overlay and the chart expect it, and the user is
  `1000:1000` by number.
- Pruning `typescript` to its parser was not attempted. It is at most 20 MB,
  and it would make the image's dependency differ from the published package
  the SBOM names.
- `verify.sh` on a signed bundle with no `cosign` fails unless `--no-signature`
  is given. On an unsigned bundle it passes and says so, and
  `--require-signature` makes that a failure.
- A support bundle leaves out the text of every doctor check unless
  identifiers are included, because free text cannot be shown to be free of
  names. A run records neither its exit code nor its duration, so the bundle
  names both as not recorded.
- A results file or an inventory of another schema is refused with the schema
  it names and the one this version reads. Only an id of the same family is
  repeated; any other text in that member is not.

## What the review changed

Four reviews of the above (an attacker's, the proofs' quality, the supply
chain, and the documents against the code) found the following. Each is fixed
with a test that fails without the fix, unless it says otherwise. Where a
decision above was reversed, it says so.

**Reversed.**

- `verify.sh` on an unsigned bundle passed with a notice. It now fails, and
  `--unsigned` accepts a bundle someone built themselves. The signature of a
  released bundle could otherwise be removed, the list rewritten, and the
  documented `./load.sh` would load the result. `--require-signature` is kept
  and means the same as no flag. `--offline` is no longer passed to `cosign`
  (cosign 3 deprecates it), and what `cosign` says on a failure is shown.
- A model or MCP endpoint written in code was reported as its URL without the
  query. It is now reported as its origin: a key in a path segment was signed
  into the report. An MCP server in code is still matched to a server the
  `mcp` source read by the whole URL, which is kept in memory for that and not
  reported. Reports of code that names an endpoint with a path differ from
  before in that one member; the contract is unchanged.
- The AWS IPv6 metadata address was left to the operator's allowlist. It is
  now never allowlistable, with two more metadata addresses that sit inside
  ranges an operator may list whole.
- The `bundle` job of the release held the signing identity on every run. It
  holds none; a `sign-bundle` job, for a pushed tag only, signs.

**Fixed.**

- The Python reader re-read the same tokens when a conditional turned out not
  to be one, doubling the work at every level of a lambda nested in a
  conditional. A file of 828 bytes stopped the scanner for good, and the time
  box could not stop it, because the read is synchronous. A conditional that
  failed is remembered; the condition and the `else` branch no longer recurse
  for a chain; and the reader counts its own steps and refuses a file past a
  multiple of its length.
- `NO_PROXY` entries separated by spaces were read as one entry, while Node
  reads them as several. A test now asks a second Node process which hosts its
  own `fetch` sends to the proxy, and holds `isProxied` to the answer.
- IPv6 forms that carry or stand for a non-public destination (v4-translated,
  local-use NAT64, site-local, Teredo, multicast) and four IPv4 ranges that
  are not the public internet passed as public.
- An inventory, a configuration or a `diff` input nested deeper than the stack
  ended the command with the engine's message. Each is now the typed refusal
  of its kind.
- A support bundle wrote an MCP server's label inside the token variable name
  `init` derives from it.
- A tag published without the tests, lint, the dependency gates or the
  reproducible-build check, from any commit. The release now runs them first,
  and refuses a tagged commit that is not on main.
- Provenance was attested for the manifest only. It is now attested for each
  architecture's image and for the bundle's archive, and each attestation is
  attached to the release as a file.
- A file named `SHA256SUMS` in a subdirectory of a bundle passed as not added.

**Proofs that were weaker than their names.**

- The canary suites watched the outputs a run is handed. They now also watch
  the process's own stdout, stderr and console, and lint refuses a write to
  them outside `cli.ts`, `log.ts` and `outputs.ts`.
- Three size caps could be removed with every test passing: the per-source
  byte budget, the cap on an MCP answer delivered as an event stream, and the
  cap on a token exchange's answer. Each has a case, paired with the same
  answer just inside the bound.
- A token exchange was judged by method, origin and path. Its grant is now
  judged too. The grants are declared beside the surface and not inside it, so
  the manifest hash is unchanged; putting them inside is a version bump and is
  left to the owner.
- The hostile-answer property claimed a truthful report. It is renamed to what
  it holds, and now also holds that a refused or non-JSON answer is never read
  as complete.
- The check on an MCP session id had no test.
- `FUZZ_SEED=0` and a seed that was not a number silently became the fixed
  seed.

**Not run, added to the list above.** The release workflow's `gates` and
`sign-bundle` jobs, the per-image and bundle provenance attestations and the
step that keeps each as a file, and `sign-bundle.sh` with a real `cosign`.
`sign-bundle.sh` was run against a stand-in signer, and gives the same archive,
byte for byte, as `build-bundle.sh` given the same signer.
