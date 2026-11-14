# Controls

Each control, where the code enforces it, and which test proves it. Every
path in the two right-hand columns is a file in this repository, and a name in
brackets after a file is a function or constant in that file. The test
`packages/scanner/tests/security-pack.test.ts` fails when either stops being
true.

This table is a summary by control. The [threat model](../threat-model.md)
has the same material arranged by trust boundary and threat, with the
residual risks. Where a control has a known limit, the last column of the
table below names the residual risk by its number there.

"Proven by" means a test that fails if the control is removed. Tests run
against imitations of each provider's API, written from the providers'
documentation, not against real services: see
[Assurance status](assurance-status.md).

## Read-only

| Control | Enforced in | Proven by | Limit |
|---|---|---|---|
| A source's general HTTP client can only issue GET: it has one verb and no method parameter. The other wires a source is handed each have one fixed purpose: the token exchange, the MCP listing and the one register read (each a POST with a fixed body), and the OpenShell gateway wire, which refuses every call and sends nothing | `packages/scanner/src/http.ts` (`ReadOnlyHttp`, `createSourceWire`), `packages/scanner/src/source.ts` (`SourceContext`) | `packages/scanner/tests/read-only-proof.test.ts` | Risk 1: what a credential can do is set where it is issued |
| Every request the scanner can make is declared in one file. The check is made by the tests, not at run time: they run every source and every preflight against a recorder and fail on a request that is not declared, and on a declared request that nothing makes. Two parts of the declaration are outside that check: the five OpenShell gateway calls are declared and nothing makes them (the wire refuses, and the test fails if one is ever recorded), and the egress proof's probes are not HTTP requests and are held by `packages/scanner/tests/egress-proxy.test.ts`. At run time the wire sends a GET only to the origin the source was built with | `packages/scanner/src/scanner-surface.ts` (`SCANNER_SURFACE`, `isDeclaredRequest`), `packages/scanner/src/http.ts` (`isOnOrigin`, `createSourceWire`) | `packages/scanner/tests/read-only-proof.test.ts`, `packages/scanner/tests/network-and-permissions-doc.test.ts`, `packages/scanner/tests/egress-proxy.test.ts` | |
| The hash of that declaration is in every signed report, so a reader can tell which surface produced it | `packages/scanner/src/scanner-surface.ts` (`scannerManifestHash`) | `packages/scanner/tests/scanner-report.test.ts`, `packages/scanner/tests/read-only-proof.test.ts` | Since 0.13.0 the grant of each token exchange is inside the hashed surface |
| The only requests the scanner makes that are not GET: token exchanges, the MCP listing messages, one register read, one post of each report (the agent report and, when its key is configured, the integrations report, each to its own route on the tenant), and, when `egress` is configured, the egress proof's three probes (two CONNECTs to the proxy and one direct TCP dial, each opened and closed with nothing sent through). Five OpenShell gateway calls (gRPC, POST) are declared as well and cannot be reached: no transport for them is built in | `packages/scanner/src/scanner-surface.ts` (`isDeclaredTokenExchange`, `isDeclaredMcpMessage`, `isDeclaredRegisterMessage`, `isDeclaredGatewayCall`), `packages/scanner/src/post.ts` (`postReport`), `packages/scanner/src/egress-proof.ts` (`proveEgress`) | `packages/scanner/tests/read-only-proof.test.ts`, `packages/scanner/tests/post-report.test.ts`, `packages/scanner/tests/egress-proxy.test.ts`, `packages/scanner/tests/openshell-source.test.ts` | |
| An MCP server is sent `initialize`, the initialized notification and `tools/list`. No tool is called | `packages/scanner/src/http.ts` (`MCP_MESSAGES`) | `packages/scanner/tests/mcp-source.test.ts`, step 11 of `deploy/smoke.sh` | |
| Scanned code is read as text and never run | `packages/scanner/src/sources/langchain.ts` (`scanLangChainCode`), `packages/scanner/src/sources/code/python.ts`, `packages/scanner/src/sources/code/javascript.ts`; lint rules in `eslint.config.mjs` refuse subprocess, VM, worker and module-loader imports, `eval`, `Function`, `require` and dynamic import under the code source | `packages/scanner/tests/fuzz-code-readers.test.ts` (a planted side effect is not observed), `packages/scanner/tests/hostile-repository.test.ts`, `packages/scanner/tests/read-only-proof.test.ts` (the tree is byte for byte what it was). The lint rules are held by the lint step of CI itself; no test plants a violation under the code source | |
| The preflight (`doctor`) makes only requests the scan makes, and writes nothing | `packages/scanner/src/source.ts` (`HarnessSource`), `packages/scanner/src/doctor/run.ts` | `packages/scanner/tests/read-only-proof.test.ts`, `packages/scanner/tests/doctor.test.ts` | |

## No secret values

| Control | Enforced in | Proven by | Limit |
|---|---|---|---|
| No request whose purpose is to return a secret's value is declared (Key Vault secret values, Okta's client-secret endpoint, GitHub secret values, key material) | `packages/scanner/src/scanner-surface.ts` (`SCANNER_SURFACE`) | `packages/scanner/tests/read-only-proof.test.ts`, `packages/scanner/tests/source-secret-canary.test.ts`, `packages/scanner/tests/okta-source.test.ts` | Risk 10: LangSmith's deployments listing carries secret values; it is read only with `readDeployments: true`, off by default. Two listings carry more than is kept: Graph returns a hint of each password with the members selected, and Okta's applications listing is asked for whole. Whether Okta puts a client secret in that listing for a Read-only Administrator is not confirmed against a live organisation; a test holds that one planted there is dropped |
| A report in which any string has a secret's shape is not signed | `packages/scanner/src/report.ts` (`signReport`), `packages/contract/src/harness-contract-rules.ts` (`looksLikeSecret`) | `packages/scanner/tests/source-secret-canary.test.ts`, `packages/scanner/tests/scanner-report.test.ts` | Risk 4: a shape check finds known shapes only, in a member's name as in its value |
| Every output file is checked for a secret's shape before the first byte is written; one hit refuses the whole run | `packages/scanner/src/file-output.ts` (`assertNoSecretShape`, `renderRunFiles`) | `packages/scanner/tests/output-secret-canary.test.ts` | |
| The log holds kinds and counts; a secret-shaped field is written `[redacted]` | `packages/scanner/src/log.ts` (`jsonLineLog`) | `packages/scanner/tests/scanner-log.test.ts`, `packages/scanner/tests/output-secret-canary.test.ts` | |
| Only three files may write to the process's stdout and stderr | `eslint.config.mjs` | `packages/scanner/tests/no-stray-output-lint.test.ts`, `packages/scanner/tests/source-secret-canary.test.ts` | |
| A secret-shaped string in the configuration refuses the file, and no message repeats a value from it | `packages/scanner/src/config.ts` (`firstSecretShaped`), `packages/scanner/src/cli.ts` (`loadConfig`) | `packages/scanner/tests/cli-hardening.test.ts`, `packages/scanner/tests/fuzz-inputs.test.ts` | |
| `init` asks for names only, refuses an answer shaped like a secret, and writes its files `0600` in a `0700` directory | `packages/scanner/src/init/write.ts` (`writeInit`), `packages/scanner/src/init/secret-shapes.ts` | `packages/scanner/tests/init-write.test.ts`, `packages/scanner/tests/init-prompts.test.ts` | |
| A secret file must be a regular file of at most 64 KiB that only its owner can write; a variable and its `_FILE` both set is refused | `packages/scanner/src/secrets.ts` (`readSecretFile`, `MAX_SECRET_FILE_BYTES`) | `packages/scanner/tests/secrets.test.ts` | Risk 12: the file's own mode is checked, not its directory or its owner |
| A URL written in code is reported as its origin only, never its path, query or user information | `packages/scanner/src/sources/code/recognize.ts` (`endpointOf`) | `packages/scanner/tests/langchain-code-source.test.ts`, `packages/scanner/tests/source-secret-canary.test.ts` | |
| A support bundle carries no credential value and replaces every name by a per-bundle token unless told not to | `packages/scanner/src/support-bundle.ts` (`buildSupportBundle`, `renderSupportBundle`) | `packages/scanner/tests/support-bundle.test.ts` | With `--doctor` it uses each credential exactly as `doctor` does |

## Request forgery and where requests go

| Control | Enforced in | Proven by | Limit |
|---|---|---|---|
| A host the configuration names is refused when it, or any address it resolves to, is loopback, link-local, cloud metadata, or private without an allowlist. Checked when the configuration is read and again before every request | `packages/scanner/src/customer-host.ts` (`customerOriginProblem`, `assertResolvesReachable`, `isNeverAllowlistable`, `addressReachable`) | `packages/scanner/tests/ssrf.test.ts`, `packages/contract/tests/cidr.test.ts` | Risk 5: on the direct path the check and the connection resolve the name separately (DNS rebinding). Risk 13: with another proxy, that proxy resolves |
| A redirect is refused, never followed | `packages/scanner/src/http.ts` (`createSourceWire`) | `packages/scanner/tests/ssrf.test.ts`, `packages/scanner/tests/read-only-proof.test.ts` | |
| A next-page link is followed only on the same origin and the same path | `packages/scanner/src/source.ts` (`readPages`), `packages/scanner/src/http.ts` (`isOnOrigin`) | `packages/scanner/tests/fuzz-responses.test.ts`, `packages/scanner/tests/ssrf.test.ts` | |
| The bundled egress proxy accepts CONNECT only, port 443 only, exact host names from its allowlist, no IP literal; it resolves the name itself and dials the address it checked | `packages/scanner/src/egress-proxy.ts` (`decideConnect`, `createEgressProxy`) | `packages/scanner/tests/egress-proxy.test.ts`, `packages/scanner/tests/egress-proxy-failures.test.ts`, `packages/scanner/tests/ssrf.test.ts`, step 11 of `deploy/smoke.sh` | Risk 14: an idle limit of two minutes and 256 connections bound what a peer can hold, and a peer that can reach the port can still use them all |
| With `egress` and a tenant configured, each scan proves the confinement before any source is read, and reports the result | `packages/scanner/src/egress-proof.ts` (`proveEgress`), `packages/scanner/src/scan.ts` (`runScan`) | `packages/scanner/tests/inflect-register-source.test.ts` (the scan runs the proof and reports its result), `packages/scanner/tests/egress-proxy.test.ts` (the probes themselves) | With no tenant configured the proof does not run |
| The scanner refuses to start with certificate verification switched off | `packages/scanner/src/cli.ts` (`TLS_OFF`) | `packages/scanner/tests/proxy-and-tls.test.ts` | |
| Which hosts bypass a proxy is decided by the rules of the Node that runs, so the scanner's own view of "proxied" matches what Node does | `packages/scanner/src/proxy-env.ts` (`isProxied`, `noProxyRulesFor`) | `packages/scanner/tests/proxy-env.test.ts` | |

## Time and size caps

| Control | Enforced in | Proven by | Limit |
|---|---|---|---|
| 4 MiB per response, 64 MiB per source, 1,000 pages per listing, no retry | `packages/scanner/src/http.ts` (`MAX_RESPONSE_BYTES`, `MAX_SOURCE_BYTES`), `packages/scanner/src/source.ts` (`MAX_PAGES_PER_SOURCE`) | `packages/scanner/tests/partial-failure-matrix.test.ts` and `packages/scanner/tests/scale.test.ts` for the two byte caps; `packages/scanner/tests/fuzz-responses.test.ts` for the page cap | The page-cap test fails when the cap is removed. It reads the constant, so it does not hold the figure 1,000 |
| One deadline per scan, set from `timeBoxSeconds` (10 to 3,600); a source past it is `INCOMPLETE` | `packages/scanner/src/config.ts` (`timeBoxSeconds`), `packages/scanner/src/scan.ts` (`runScan`) | `packages/scanner/tests/partial-failure-matrix.test.ts`, `packages/scanner/tests/scanner-config-and-schedule.test.ts` | |
| Code: 1 MiB per parsed file, 20,000 files, 128 MiB in total; a file over 1 MiB is searched for the name of a framework or of a model provider's SDK and never parsed, and one over 16 MiB is not opened; links and pipes are refused, not followed or opened | `packages/scanner/src/sources/code/files.ts` (`MAX_FILE_BYTES`, `MAX_MARKER_SCAN_BYTES`, `MAX_FILES`, `MAX_TOTAL_BYTES`, `readCodeFiles`), `packages/scanner/src/sources/langchain.ts` (`readRegularFileCapped`) | `packages/scanner/tests/hostile-repository.test.ts`, `packages/scanner/tests/code-files.test.ts` | Risk 6: a directory swapped for a link between its listing and the read |
| A Python file that costs more to read than a fixed multiple of its length is refused | `packages/scanner/src/sources/code/python.ts` (`STEPS_PER_TOKEN`, `workBudgetFor`) | `packages/scanner/tests/fuzz-code-readers.test.ts` | |
| A report over 5 MiB is refused before it is signed; a report of more than 5,000 agents is cut and says so | `packages/scanner/src/report.ts` (`signReport`, `buildReportBody`), `packages/contract/src/harness-contract.ts` (`MAX_REPORT_BYTES`, `MAX_AGENTS`) | `packages/scanner/tests/scale.test.ts`, `packages/contract/tests/harness-contract.test.ts` | Risk 9 |
| A bound that is reached is reported, never silent: the source is `INCOMPLETE` with a reason, its agents get no level, and nothing about them is reported as resolved | `packages/scanner/src/source.ts` (`SourceReadError`), `packages/contract/src/harness-matrix-model.ts` (`harnessJudgementOf`), `packages/report/src/diff/diff.ts` (`diffResults`) | `packages/scanner/tests/partial-failure-matrix.test.ts`, `packages/report/tests/score.test.ts`, `packages/report/tests/diff.test.ts` | |
| Operator inputs are size-capped and strictly decoded (configuration, inventory, answers file, `diff` inputs) | `packages/scanner/src/config.ts` (`parseScannerConfig`), `packages/scanner/src/inventory-file.ts` (`loadInventoryFile`), `packages/scanner/src/diff-command.ts` (`loadDiffSide`) | `packages/scanner/tests/fuzz-inputs.test.ts`, `packages/scanner/tests/inventory-file.test.ts`, `packages/scanner/tests/diff-command.test.ts` | |

## Output escaping

| Control | Enforced in | Proven by | Limit |
|---|---|---|---|
| `summary.html` escapes every value; markup can only come from the template | `packages/report/src/render/escape.ts` (`escapeHtml`, `html`), `packages/report/src/render/html.ts` (`renderSummaryHtml`) | `packages/report/tests/html.test.ts` | |
| The page loads nothing from the network: its one inline script and one style block run by their SHA-256 hashes, and its CSP allows nothing else | `packages/report/src/render/html.ts` (`renderSummaryHtml`) | `packages/report/tests/html.test.ts` | |
| A CSV cell that starts with a formula character is neutralised | `packages/report/src/render/csv.ts` (`csvCell`) | `packages/report/tests/csv.test.ts` | |
| Text printed to a terminal has control and bidirectional characters written as visible escapes, never as the characters themselves | `packages/report/src/render/escape.ts` (`terminalLine`, `isBidiControl`) | `packages/report/tests/diff.test.ts`, `packages/scanner/tests/diff-command.test.ts` | |
| Run directories are `0750` and files `0640`; a run is written to a temporary directory and renamed into place, and is never replaced | `packages/scanner/src/file-output.ts` (`RUN_DIR_MODE`, `RUN_FILE_MODE`, `writeRun`) | `packages/scanner/tests/file-output.test.ts`, steps 6 and 7 of `deploy/smoke.sh` | Risk 11: every output but the signed report is unsigned |

## Signing

| Control | Enforced in | Proven by | Limit |
|---|---|---|---|
| The report is signed with Ed25519 over the SHA-256 of the body's canonical JSON | `packages/scanner/src/report.ts` (`signReport`), `packages/contract/src/canonical-json.ts`, `packages/contract/src/harness-contract.ts` (`harnessSignedMessage`) | `packages/scanner/tests/scanner-report.test.ts`, `packages/contract/tests/harness-contract.test.ts` | Risk 15: no key revocation, and a replayed old report is the consumer's to refuse |
| Verification order is fixed: size, JSON, signature by a key the verifier already trusts, then the strict schema of the id the report names | `packages/contract/src/harness-contract.ts` (`verifyAndParseHarnessReport`) | `packages/contract/tests/harness-contract.test.ts`, `packages/scanner/tests/fuzz-inputs.test.ts` | |
| The signing key is created `0600` in a new file; an existing file is never replaced | `packages/scanner/src/keygen.ts` (`generateSigningKey`, `SIGNING_KEY_MODE`) | `packages/scanner/tests/keygen.test.ts` | Risk 7: anyone who can read the scanner's files or memory has the key |
| The report lists every source with its status and reason; it carries no level and no completeness flag, which a reader derives | `packages/scanner/src/report.ts` (`buildReportBody`) | `packages/scanner/tests/scanner-report.test.ts`, `packages/report/tests/score.test.ts` | Risk 2: a provider that returns a well-formed, false inventory |
| Files written by an earlier commit of the code are still read by this one | `packages/scanner/tests/fixtures/compat/README.md` | `packages/scanner/tests/compat.test.ts` | One set of files exists. It was made from commit `190f3fb`, a commit of the earlier unreleased version, 0.12.0. Its results file, signed report, doctor report, configurations and answers file are still read. Its two inventory files are `scanent-inventory/1` and are refused, with a message saying what changed. No released version exists to compare with |

## Container hardening

| Control | Enforced in | Proven by | Limit |
|---|---|---|---|
| The image is a distroless Node base pinned by digest, runs as uid 1000, and holds no shell and no package manager | `deploy/Dockerfile` | `packages/scanner/tests/image.test.ts`, step 1 of `deploy/smoke.sh` | |
| The image holds compiled JavaScript only, installed from the lockfile with no install script | `deploy/Dockerfile` | `packages/scanner/tests/image.test.ts`, step 1 of `deploy/smoke.sh` | |
| It runs with a read-only root filesystem, every capability dropped and no privilege gain; the output directory is the one writable mount | `deploy/compose.yaml`, `deploy/helm/scanent/templates/_helpers.tpl`, `deploy/helm/scanent/templates/cronjob.yaml` | `deploy/smoke.sh` (every step runs that way), `packages/scanner/tests/deploy-templates.test.ts`, `deploy/kind-test.sh` | |
| The chart creates no Secret, Role or Ingress, reads no credential into the environment, and installs a NetworkPolicy | `deploy/helm/scanent/templates/networkpolicy.yaml`, `deploy/helm/scanent/values.schema.json` | `packages/scanner/tests/deploy-templates.test.ts`, `deploy/kind-test.sh` | A NetworkPolicy matches addresses, not names: exact hosts need the egress proxy or the Cilium policy |
| The egress overlay puts the scanner on a network with no route out except the proxy | `deploy/compose.egress.yaml` | `packages/scanner/tests/deploy-templates.test.ts`, step 11 of `deploy/smoke.sh` | |

`deploy/smoke.sh` and `deploy/kind-test.sh` run in CI against the image the
job has just built (the `image`, `image-podman` and `chart-install` jobs of
`.github/workflows/ci.yml`). They are scripts, not unit tests, and need a
container runtime.

## Supply chain

| Control | Enforced in | Proven by | Limit |
|---|---|---|---|
| Dependencies are installed from the lockfile's integrity hashes | `deploy/Dockerfile`, `.github/workflows/ci.yml` | `packages/scanner/tests/image.test.ts` | |
| Every GitHub Action is pinned to a full commit SHA | `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `.github/workflows/codeql.yml`, `.github/workflows/scorecard.yml`, `.github/workflows/long-tests.yml` | `packages/scanner/tests/image.test.ts` | |
| Production dependencies must carry a licence on an allowlist | `scripts/check-licences.js` (`checkLicences`, `ALLOWED`) | `packages/scanner/tests/supply-chain.test.ts`, `packages/scanner/tests/security-pack.test.ts` | |
| `npm audit` on production dependencies (moderate and above); Trivy and Grype on the image (high and above) | `.github/workflows/ci.yml` | The gates themselves, which run on every push and pull request | A gate reports known vulnerabilities only |
| Static analysis (CodeQL) and OpenSSF Scorecard | `.github/workflows/codeql.yml`, `.github/workflows/scorecard.yml` | The workflows themselves | |
| The compiled JavaScript is reproducible: two builds of one commit give the same files | `scripts/check-reproducible-build.js` | `packages/scanner/tests/supply-chain.test.ts`; CI runs the script | The image digest is not reproducible |
| Releases: keyless signature by digest, a CycloneDX SBOM per image as an attestation, build provenance, a signed checksum list for the air-gapped bundle | `.github/workflows/release.yml`, `deploy/airgap/verify.sh`, `deploy/airgap/sign-bundle.sh` | `packages/scanner/tests/deploy-templates.test.ts` holds how the workflow and scripts are written | Run for 0.13.2 (2026-11-13) and verified as a client would; see Assurance status. Risk 8 |
| The published contract package holds the compiled contract, its manifest, `README.md`, `LICENSE` and `NOTICE`, and nothing else: no source map, no test, no source, no path of the build machine. It is published as the tarball that was checked, with build provenance | `packages/contract/package.json`, `scripts/check-contract-package.js` (`checkTarball`), `.github/workflows/release.yml` | `packages/scanner/tests/contract-package.test.ts` runs `npm pack` and the check on every change | Published for 0.13.2 (2026-11-13); installing it needs a GitHub Packages token |
| A tag is held to what main is held to before anything is built or signed | `.github/workflows/release.yml` | `packages/scanner/tests/deploy-templates.test.ts` | Never run on GitHub. Branch and tag protection are repository settings and are not on today: see [Assurance status](assurance-status.md) |
| Dependency and base-image updates are proposed weekly | `.github/dependabot.yml` | | |
