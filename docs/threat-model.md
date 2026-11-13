# Threat model

What scanent protects, from whom, how, and what it does not protect. Written
for a security team deciding whether to let it into an estate.

Every mitigation names the file and the function that carries it and the test
that holds it. A test in this repository (`packages/scanner/tests/docs-cited-paths.test.ts`)
fails when a path or a function named here no longer exists.

- [What the scanner is](#what-the-scanner-is)
- [Assets](#assets)
- [Trust boundaries](#trust-boundaries)
- [Threats and mitigations, by boundary](#threats-and-mitigations-by-boundary)
- [Residual risks](#residual-risks)
- [What has not been done](#what-has-not-been-done)

## What the scanner is

One process, started by a schedule. It reads the estate's agent sources with
read-only credentials, builds one report, signs it, and writes it to a
directory, to stdout, or to a tenant you name. It listens on no port, accepts
no inbound connection, runs no code it reads, and keeps no state between runs
except the files it wrote.

## Assets

| Asset | Why it matters |
|---|---|
| **The read credentials** the scanner is given (a Graph client secret, an Okta token, a GitHub token, a Google key, MCP read tokens, a tenant's ingest key) | Each reads part of the estate's identity inventory. Leaked, it does that for someone else |
| **The signing key** (Ed25519, PKCS#8) | Whoever holds it can sign a report the tenant will accept as this scanner's |
| **The inventory as read**: agent and principal ids, credential ids and ages, tool names, owner ids | It maps which non-human identities exist and which are weak |
| **The outputs**: the signed report, `results.json`, the CSV files, `summary.html` | The same, at rest, plus the findings |
| **The network position**: a process inside the estate that may reach identity providers and internal MCP servers | A foothold, if the process could be steered |
| **The release**: the image, the chart, the bundle | What every client runs |

## Trust boundaries

```
 operator ──(configuration, inventory, answers file, environment)──▶ ┌─────────┐
                                                                     │         │──▶ provider APIs (Graph, Okta, GitHub, Google, LangSmith)
 release pipeline ──(image, chart, bundle)──▶ client ──(runs)──────▶ │ scanner │──▶ hosts the estate names (MCP servers, self-hosted LangSmith)
                                                                     │         │──▶ the file system under a code root
                                                                     │         │──▶ egress proxy ──▶ outside
                                                                     │         │──▶ output directory
                                                                     └─────────┘──▶ a tenant's ingest (optional)
```

| # | Boundary | What crosses it | Who is trusted |
|---|---|---|---|
| 1 | Operator to scanner | The configuration, the inventory, an answers file, environment variables, secret files | The operator, fully. Their files are still parsed strictly, because a typo must not become a leak |
| 2 | Scanner to a provider API | Requests with a credential; JSON responses | The provider's identity (TLS). Not the content of its answers |
| 3 | Scanner to a host the estate names | The same, to a host nobody can list in advance | Neither the name nor what it resolves to |
| 4 | Scanner to a code root | Directory listings and file contents | Nothing in the tree |
| 5 | Scanner to the egress proxy, proxy to the outside | CONNECT requests; tunnels | The proxy is scanent's own code. Its clients are not trusted |
| 6 | Scanner to the output directory | The run's files | The directory's owner |
| 7 | Scanner to a tenant | The signed report | The tenant decides what to accept. The scanner trusts its answer only as a status |
| 8 | Release pipeline to client | The image, the chart, the bundle | Established by signature, not assumed |

## Threats and mitigations, by boundary

STRIDE: **S**poofing, **T**ampering, **R**epudiation, **I**nformation
disclosure, **D**enial of service, **E**levation of privilege.

### 1. Operator to scanner

| | Threat | Mitigation | Held by |
|---|---|---|---|
| T | A configuration with an unknown or misspelt member is silently half-applied | Every object of the schema is strict; an unknown key refuses the file. `packages/scanner/src/config.ts` (`parseScannerConfig`) | `packages/scanner/tests/scanner-config-and-schedule.test.ts`, `packages/scanner/tests/fuzz-inputs.test.ts` |
| I | A credential pasted into the configuration file ends up in a log or an error | A secret-shaped string anywhere in the file refuses it, and no message repeats a value of the file. `packages/scanner/src/config.ts` (`firstSecretShaped`), `packages/scanner/src/cli.ts` (`loadConfig`) | `packages/scanner/tests/cli-hardening.test.ts`, `packages/scanner/tests/fuzz-inputs.test.ts` |
| I | A credential is read from a file another local user can replace | A secret file must be a regular file, at most 64 KiB, writable by its owner alone; a variable and its `_FILE` both set is refused. The check is of the file's own mode and no more: see [Residual risks](#residual-risks), 12. `packages/scanner/src/secrets.ts` (`readSecretFile`) | `packages/scanner/tests/secrets.test.ts` |
| I | The wizard is given a secret, or writes one where others can read it | `init` asks for names only and writes its files `0600` in a `0700` directory; a signing key is never replaced. `packages/scanner/src/init/write.ts` (`writeInit`), `packages/scanner/src/keygen.ts` (`generateSigningKey`) | `packages/scanner/tests/init-write.test.ts`, `packages/scanner/tests/keygen.test.ts` |
| I | Certificate verification is switched off by a variable left in a shell profile | `scan` and `schedule` refuse to start with `NODE_TLS_REJECT_UNAUTHORIZED=0`. `packages/scanner/src/cli.ts` (`TLS_OFF`) | `packages/scanner/tests/proxy-and-tls.test.ts` |
| D | A huge or malformed inventory or CSV | Size caps and a strict decoder; a refusal names a row and a field, never a value. `packages/scanner/src/inventory-file.ts` (`loadInventoryFile`) | `packages/scanner/tests/inventory-file.test.ts`, `packages/scanner/tests/fuzz-inputs.test.ts` |
| E | An inventory makes an agent look better than it is | Everything it supplies is labelled declared, never observed, and a level resting on a declaration is kept apart from the observed one. `packages/report/src/results/inventory.ts` (`declaredVerdicts`) | `packages/report/tests/inventory.test.ts`, `packages/report/tests/score.test.ts` |

### 2. Scanner to a provider API

| | Threat | Mitigation | Held by |
|---|---|---|---|
| S | A request with a credential goes to the wrong host | Each fixed host is a constant of its source; every request is checked against the declared surface, and a redirect is refused, never followed. `packages/scanner/src/scanner-surface.ts` (`isDeclaredRequest`), `packages/scanner/src/http.ts` (`createSourceWire`) | `packages/scanner/tests/read-only-proof.test.ts`, `packages/scanner/tests/ssrf.test.ts` |
| T | The scanner changes something in the estate | It has no code path that does. Every request is a GET, except the token exchanges, the MCP listing messages, the one register read and the one post to a tenant, all declared in one file whose hash is in every signed report. `packages/scanner/src/scanner-surface.ts` (`SCANNER_SURFACE`, `scannerManifestHash`) | `packages/scanner/tests/read-only-proof.test.ts`, `packages/scanner/tests/network-and-permissions-doc.test.ts` |
| T | A response steers the next request to another path or host (a next-page link to a secret's own URL) | A next link is followed only on the same origin and the same path. `packages/scanner/src/source.ts` (`readPages`), `packages/scanner/src/http.ts` (`isOnOrigin`) | `packages/scanner/tests/fuzz-responses.test.ts`, `packages/scanner/tests/ssrf.test.ts` |
| T | A malformed or hostile response is taken as a clean, empty estate | A response that is not the listing's shape is `PAGINATION_TORN` or `UNPARSEABLE`, and the source is `INCOMPLETE`. Zero agents is a finding (`EMPTY_SCAN`), never a clean result | `packages/scanner/tests/fuzz-responses.test.ts`, `packages/scanner/tests/partial-failure-matrix.test.ts` |
| R | A report cannot be tied to the scanner that made it, or a source is said to have been read when it was not | The report is signed with the scanner's key over canonical JSON, carries the manifest hash, and lists every source with its status and reason. `packages/scanner/src/report.ts` (`signReport`), `packages/contract/src/harness-contract.ts` (`verifyAndParseHarnessReport`) | `packages/scanner/tests/scanner-report.test.ts`, `packages/contract/tests/harness-contract.test.ts` |
| I | A secret value is read from a provider and reported | No path whose purpose is to return a secret's value is requested (Key Vault secret values, Okta's client-secret endpoint, GitHub secret values, key material). Two listings carry more than is kept and drop it with the page: Graph returns a hint of each password, and Okta's apps listing is asked for whole (whether it carries a client secret for a Read-only Administrator is not confirmed against a live organisation). One listing carries secret values and is off by default: LangSmith's deployments listing, read only when the configuration sets `readDeployments: true`, carries each deployment's secrets, names and values. The scanner keeps a deployment's id and tracing project from it and drops the rest with the page; see [Residual risks](#residual-risks), 10. A report member with a secret's shape refuses the whole report. `packages/scanner/src/report.ts` (`signReport`), `packages/contract/src/harness-contract-rules.ts` (`looksLikeSecret`), `packages/scanner/src/sources/langsmith.ts` | `packages/scanner/tests/source-secret-canary.test.ts`, `packages/scanner/tests/read-only-proof.test.ts`, `packages/scanner/tests/langsmith-source.test.ts` |
| I | A credential, or a response body, is printed by a source to the process's own output, past the log and the outputs that are watched | Only three files may write to the console or to the process's stdout and stderr; lint refuses it everywhere else, and the canary suite watches the process itself during every run. `eslint.config.mjs`, `packages/scanner/src/log.ts` (`jsonLineLog`) | `packages/scanner/tests/no-stray-output-lint.test.ts`, `packages/scanner/tests/source-secret-canary.test.ts` |
| I | A credential appears in a log line or an error | The log holds kinds and counts; a secret-shaped field is written `[redacted]`. `packages/scanner/src/log.ts` (`jsonLineLog`) | `packages/scanner/tests/scanner-log.test.ts`, `packages/scanner/tests/output-secret-canary.test.ts` |
| D | A slow, huge or endless response holds the scan | 4 MiB per response, 64 MiB and one deadline per source, a page cap, no retry. Past a bound the source is `INCOMPLETE` and the others are unaffected. `packages/scanner/src/http.ts` (`MAX_RESPONSE_BYTES`, `MAX_SOURCE_BYTES`), `packages/scanner/src/source.ts` (`MAX_PAGES_PER_SOURCE`) | `packages/scanner/tests/partial-failure-matrix.test.ts`, `packages/scanner/tests/scale.test.ts` |
| D | Rate limiting, an outage or an expired credential makes a finding disappear | A source that was not read in full closes nothing: its agents get no level, and `diff` reports nothing about them as resolved. `packages/report/src/diff/diff.ts` (`diffResults`) | `packages/scanner/tests/partial-failure-matrix.test.ts`, `packages/report/tests/diff.test.ts` |

### 3. Scanner to a host the estate names

| | Threat | Mitigation | Held by |
|---|---|---|---|
| S, E | A configured URL, or the name behind it, points at a loopback, link-local, private or cloud-metadata address (server-side request forgery) | Checked when the configuration is read and again before every request: every address the name resolves to must be reachable under the rules. The spellings covered are the ones in the test's tables, and no others are claimed: a URL host in decimal, octal, hex or short form, and with a trailing dot; an IPv4 address inside an IPv6 one as v4-mapped, v4-compatible, v4-translated, NAT64 (the well-known and the local-use prefix) and 6to4. Refused without an allowlist: the private, carrier-grade NAT and unique-local ranges, and the ranges that are not the public internet (192.0.0.0/24, benchmarking 198.18.0.0/15, multicast, 240.0.0.0/4, site-local, Teredo). Refused inside any allowlist: loopback, "this host", link-local (169.254.169.254 among it), and the metadata addresses that sit outside link-local: `fd00:ec2::254`, `100.100.100.200`, `192.0.0.192`. Another provider's metadata address that is neither link-local nor on that list is the operator's to keep out of the allowlist. `packages/scanner/src/customer-host.ts` (`customerOriginProblem`, `assertResolvesReachable`, `isNeverAllowlistable`, `addressReachable`) | `packages/scanner/tests/ssrf.test.ts`, `packages/contract/tests/cidr.test.ts` |
| S | The name resolves to a public address at the check and a private one at the connection (DNS rebinding) | The check runs before each request, so a rebind between two requests stops the read. Behind scanent's own proxy the proxy resolves once and dials the address it checked. On the direct path the gap between check and connection remains: see [Residual risks](#residual-risks) | `packages/scanner/tests/ssrf.test.ts`, `packages/scanner/tests/egress-proxy.test.ts` |
| T | An MCP server is asked to do something | Three messages only: `initialize`, the initialized notification, `tools/list`. No tool is ever called. `packages/scanner/src/http.ts` (`MCP_MESSAGES`), `packages/scanner/src/scanner-surface.ts` (`isDeclaredMcpMessage`) | `packages/scanner/tests/mcp-source.test.ts`, `packages/scanner/tests/read-only-proof.test.ts`, step 11 of `deploy/smoke.sh` |
| I | An MCP server's tool descriptions or instructions carry text meant for a model, or a secret | Tool names and hashes are kept; descriptions and instructions are not reported. A secret-shaped name refuses the report | `packages/scanner/tests/mcp-source.test.ts`, `packages/scanner/tests/source-secret-canary.test.ts` |

### 4. Scanner to a code root

| | Threat | Mitigation | Held by |
|---|---|---|---|
| E | Scanned code is executed | The readers are static: a tokenizer for Python, the TypeScript parser for JavaScript and TypeScript. Nothing is imported, evaluated or spawned, and lint rules ban `child_process`, `vm`, `eval`, `Function` and dynamic import under the code source. `packages/scanner/src/sources/langchain.ts` (`scanLangChainCode`), `eslint.config.mjs` | `packages/scanner/tests/report-purity-lint.test.ts`, `packages/scanner/tests/fuzz-code-readers.test.ts` |
| I | A symbolic link leads the read out of the root (to a key, to `/etc`) | Two checks in two files. The walk stats each entry without following and refuses a link: `packages/scanner/src/sources/code/files.ts` (`readCodeFiles`). The read then opens the file without following a link and without blocking, checks that what it opened is a regular file, and reads to a cap: `packages/scanner/src/sources/langchain.ts` (`readRegularFileCapped`) | `packages/scanner/tests/hostile-repository.test.ts`, `packages/scanner/tests/code-files.test.ts` |
| D | A pipe, a sparse file, deep nesting, millions of files, or input that makes a parser recurse or loop | 1 MiB per file, 20,000 files, 128 MiB in total, the source's deadline; a file that cannot be read is `UNPARSEABLE` and the rest is kept. A file is parsed in one synchronous step that the deadline cannot interrupt, so the Python reader also counts its own work: a file that costs more than a fixed multiple of its length is refused. `packages/scanner/src/sources/code/files.ts` (`MAX_FILE_BYTES`, `MAX_FILES`, `MAX_TOTAL_BYTES`), `packages/scanner/src/sources/code/python.ts` (`STEPS_PER_TOKEN`, `workBudgetFor`) | `packages/scanner/tests/hostile-repository.test.ts`, `packages/scanner/tests/fuzz-code-readers.test.ts` |
| I | A secret written in code is reported | The name of the variable a key is read from is kept, never a value; a model or MCP endpoint written as a URL is reported as its origin (scheme, host, port), never its path, query or user information, because a key is often a path segment; a secret-shaped member refuses the report. `packages/scanner/src/sources/code/recognize.ts` (`endpointOf`, `codeLocator`) | `packages/scanner/tests/langchain-code-source.test.ts`, `packages/scanner/tests/source-secret-canary.test.ts` |

### 5. The egress proxy

| | Threat | Mitigation | Held by |
|---|---|---|---|
| E | The scanner, or anything else on its network, reaches a host that is not on the list | CONNECT only, port 443 only, exact host names from `EGRESS_ALLOW`, no IP literal; an empty list refuses everything. `packages/scanner/src/egress-proxy.ts` (`decideConnect`) | `packages/scanner/tests/egress-proxy.test.ts`, `packages/scanner/tests/ssrf.test.ts`, step 11 of `deploy/smoke.sh` |
| S | An allowed name resolves to a private or metadata address | The proxy resolves the name itself, applies the same address rules, and connects to the address it checked. `packages/scanner/src/egress-proxy.ts` (`createEgressProxy`) | `packages/scanner/tests/egress-proxy.test.ts`, `packages/scanner/tests/ssrf.test.ts` |
| D | A client crashes or stalls the proxy (a reset at the wrong moment, a slow client, a header flood) | Every socket has an error handler; a refused client is closed; a slow client holds its own socket and no other. A connection that carries nothing for two minutes is closed, and at most 256 are held at once (`EGRESS_IDLE_TIMEOUT_MS`, `EGRESS_MAX_CONNECTIONS`): see [Residual risks](#residual-risks), 14. `packages/scanner/src/egress-proxy.ts` (`createEgressProxy`) | `packages/scanner/tests/egress-proxy-failures.test.ts`, `packages/scanner/tests/egress-proxy.test.ts` (3a), `packages/scanner/tests/ssrf.test.ts` |
| R | The confinement is assumed and not there | With `egress` configured, every scan proves it (the proxy allows the tenant's host, refuses a canary, and there is no direct route) and reports the result as a criterion on the scanner's own agent. `packages/scanner/src/egress-proof.ts` (`proveEgress`) | `packages/scanner/tests/scanner-report.test.ts`, `packages/scanner/tests/read-only-proof.test.ts` |

A Kubernetes NetworkPolicy alone matches addresses, not names: "TCP 443 to
public addresses" is not "exactly these hosts". The proxy, or a Cilium policy
by name, is what gives exact hosts (`deploy/helm/scanent/README.md`).

### 6. The output directory

| | Threat | Mitigation | Held by |
|---|---|---|---|
| T | A run is half-written and read as whole, or damaged after it was written | A run is written to a temporary directory and renamed into place; a run is never replaced; `manifest.json` carries each file's SHA-256; a `runs` that is a link is refused. The manifest detects damage. It is not signed, so it does not detect a change by someone who can write the directory: see [Residual risks](#residual-risks), 11. `packages/scanner/src/file-output.ts` (`writeRun`) | `packages/scanner/tests/file-output.test.ts`, step 6 of `deploy/smoke.sh` |
| I | Another local user reads the results | Run directories `0750`, files `0640`, owned by the user the scanner runs as. `packages/scanner/src/file-output.ts` (`RUN_DIR_MODE`, `RUN_FILE_MODE`) | `packages/scanner/tests/file-output.test.ts`, step 7 of `deploy/smoke.sh` |
| I | A secret reaches a results file, the HTML page or a CSV | Every file is checked for a secret's shape, as data and as text, before the first byte is written; one hit refuses the whole run. `packages/scanner/src/file-output.ts` (`assertNoSecretShape`, `renderRunFiles`) | `packages/scanner/tests/output-secret-canary.test.ts` |
| T, E | A value from the estate becomes markup or a formula when the page or the CSV is opened | The page escapes every value and loads nothing from the network; CSV cells that start with a formula character are neutralised. `packages/report/src/render/html.ts` (`renderSummaryHtml`), `packages/report/src/render/csv.ts` (`csvCell`) | `packages/report/tests/html.test.ts`, `packages/report/tests/csv.test.ts` |
| I | A support bundle carries a credential or the estate's names | Without `--doctor` it resolves no credential and opens no secret file. With `--doctor` it runs the preflight, which resolves every credential and uses it exactly as `scanent doctor` does; no value is written to the bundle either way. It replaces every name by a per-bundle token unless told not to, the label inside a derived MCP token variable name included, and is refused whole on a secret's shape. `packages/scanner/src/support-bundle.ts` (`buildSupportBundle`, `renderSupportBundle`) | `packages/scanner/tests/support-bundle.test.ts` |

### 7. Scanner to a tenant

| | Threat | Mitigation | Held by |
|---|---|---|---|
| S | Someone else posts a report as this scanner | The tenant accepts a report only when it verifies under a key registered there for this scanner. The order is fixed: size, JSON, signature by a trusted key, then the strict schema of the id the report names. `packages/contract/src/harness-contract.ts` (`verifyAndParseHarnessReport`) | `packages/contract/tests/harness-contract.test.ts`, `packages/scanner/tests/fuzz-inputs.test.ts` |
| T | The report is altered on the way | The signature covers the canonical JSON of the whole body. `packages/contract/src/harness-contract.ts` (`harnessSignedMessage`) | `packages/contract/tests/harness-contract.test.ts` |
| I | The ingest key is sent somewhere else, or the tenant's answer is logged | The key goes to the configured origin's ingest path and nowhere else; only the status and a refusal code are kept from the answer. `packages/scanner/src/post.ts` (`postReport`) | `packages/scanner/tests/post-report.test.ts`, `packages/scanner/tests/read-only-proof.test.ts` |
| D | A report too large for the tenant is signed and then refused | A report over 5 MiB is refused locally before it is signed, and nothing is written or posted. `packages/scanner/src/report.ts` (`signReport`) | `packages/scanner/tests/scale.test.ts` |

A run that names no tenant sends nothing anywhere. That is the default of
every example configuration.

### 8. Release pipeline to client

| | Threat | Mitigation | Held by |
|---|---|---|---|
| S, T | A client runs an image or a bundle that the release did not produce | Images are signed by digest, keyless, by the release workflow at the tag; the bundle's checksum list is signed the same way, and `verify.sh` and `load.sh` refuse a bundle whose signature is missing unless told the bundle is one you built. `.github/workflows/release.yml`, `deploy/airgap/verify.sh`, `docs/verify-a-release.md` | `packages/scanner/tests/deploy-templates.test.ts`; the first tagged release for the signing itself |
| S, T | A tag is pushed on a commit that is not on main, or that fails the tests | The release workflow first holds the tagged commit to what a commit on main is held to (the dependency gates, lint, type-check, the tests under the coverage gate, the reproducible build), and refuses a tag whose commit main does not hold. Nothing is built or signed before that passes. `.github/workflows/release.yml` | `packages/scanner/tests/deploy-templates.test.ts`; never run on GitHub |
| T | A dependency or a base image is replaced | The lockfile's integrity hashes decide what is installed, with no install script; both base images are pinned by digest; every action is pinned by commit. `deploy/Dockerfile` | `packages/scanner/tests/image.test.ts` |
| T | A vulnerable dependency or base ships | Written as gates: Trivy and Grype on the image for fixed high and critical findings; `npm audit` on production dependencies; a licence allowlist; CodeQL. Each has run in CI on `main`; CodeQL's findings have not been reviewed (see [What has not been done](#what-has-not-been-done)). `.github/workflows/ci.yml`, `scripts/check-licences.js` | The gates themselves, once they run; `packages/scanner/tests/supply-chain.test.ts` holds how they are written |
| R | Nobody can say what is in the image | A CycloneDX SBOM per image, attached as an attestation, in the release and in the bundle; build provenance for the pushed manifest, for each architecture's image and for the bundle's archive | `packages/scanner/tests/deploy-templates.test.ts` |
| E | The image gives an attacker tools | No shell, no package manager, uid 1000, and it runs with a read-only root, no capability and no privilege gain. `deploy/Dockerfile`, `deploy/compose.yaml` | `deploy/smoke.sh` (step 1), `packages/scanner/tests/image.test.ts` |
| T | A version is replaced after release | A version already in the registry is never pushed again; no `latest` tag exists. `.github/workflows/release.yml` | `packages/scanner/tests/deploy-templates.test.ts` |

## Residual risks

Stated plainly. None of these is closed by the code.

1. **A credential with more than read access.** The scanner asks for read-only
   grants and never writes, but what a credential can do is decided where it is
   issued. A leaked over-privileged credential is as bad as its privileges.
   `doctor` warns where the provider lets it see the grant (a GitHub classic
   token's scopes, for one); for most providers it cannot. Follow
   `docs/access.md` and review the grant yourself.
2. **A provider that lies.** A compromised or faulty provider API can return a
   well-formed, false inventory. The scanner cannot tell. It reports what it
   was told, per source, and signs that.
3. **Okta API tokens may be only partly visible.** The token listing may show
   only the tokens the scanner's own administrator can see. Tokens it cannot
   see are not reported, and the source still reads as complete.
4. **A secret-shaped object key is refused, by shape only.** A report, an
   inventory or a comparison input is refused when a member, or a member's
   name, has a secret's shape. The refusal names the member's path, with
   `<key>` where such a name would be, so it does not print what it refuses.
   (Until 0.13.0 the name was printed to the operator's terminal.) The check
   knows the shapes listed in the contract and no others: a name or a value
   that is a secret of no known shape passes.
5. **DNS rebinding on the direct path.** Without scanent's proxy, the address
   check and the connection resolve the name separately. A resolver that
   answers differently inside that gap can send one request, with that host's
   read token, to an address the check would have refused. Use the bundled
   egress proxy (`deploy/compose.egress.yaml`, or `egressProxy.enabled` in the
   chart) where a configured host's DNS is not under your control: the proxy
   connects to the address it checked.
6. **A directory replaced by a link during a read.** A file swapped for a link
   is caught; a directory swapped for a link between its listing and the read
   of its entries is still listed. Mount code roots read-only, from a source
   the scanned teams cannot write to during the scan.
7. **The machine itself.** Anyone who can read the scanner's environment, its
   secret files or its process memory has its credentials and its signing key.
   Nothing here defends against root on the host or a cluster administrator.
8. **The release identity.** A signature proves the release workflow made the
   bytes. An attacker who can change that workflow, or push a tag, in this
   repository could make a signed release. Branch protection and who may push
   tags are repository settings (`docs/release-checklist.md`).
9. **The report's size.** Two caps, which behave differently. A report over
   5 MiB is refused locally: nothing is signed, written or posted. A report
   of more than 5,000 agents is cut: it carries the first 5,000 by id, it is
   signed, and every source that lost an agent is `INCOMPLETE` with
   `BYTE_CAP`, so the agents past the cap are not in the report and the report
   says it is not complete. Scan a larger estate in parts (`docs/scanner.md`,
   "Limits and scale").
10. **Deployment secrets pass through memory when `readDeployments` is on.**
    LangSmith's deployments listing returns each deployment's secrets with
    their values. With `readDeployments: true` the scanner receives that
    response, keeps a deployment's id and tracing project, and drops the rest;
    nothing of it is written, logged or reported. The values are still in the
    process's memory for the length of the read, and in sight of any proxy
    that inspects TLS on the path. The option is off unless the configuration
    sets it. Leave it off unless you need deployments in the report.
11. **Every output but the report is unsigned.** `report.signed.json` carries
    the scanner's signature. `results.json`, `summary.html`, the CSV files and
    `manifest.json` do not: the manifest lists each file's SHA-256 and is
    itself an ordinary file. Anyone who can write the output directory can
    change a file and the manifest together. Restrict who can write that
    directory, and where a result matters, re-derive it from the signed
    report (`scanent diff` reads one) rather than trust the files beside it.
12. **A secret file is checked by its own mode only.** The scanner refuses a
    secret file that its group or every user can write. It does not check the
    directory the file is in, or who owns either, and it follows a symbolic
    link to the file. A file another user can replace through its directory
    passes. Keep secret files in a directory only the scanner's user can
    write, as Docker and Kubernetes secrets are mounted.
13. **A proxy or a certificate authority you add sees every credential.** With
    `HTTPS_PROXY` set, the scanner's own address check (boundary 3) binds this
    machine's resolver, not the proxy's: a proxy that resolves a name
    differently connects where it likes. The bundled egress proxy is the one
    proxy that checks the address it dials. A certificate authority added with
    `NODE_EXTRA_CA_CERTS`, or a proxy that inspects TLS, reads every request,
    read credentials included. Do not route credentialed sources through a
    proxy or a certificate authority you would not give those credentials to.
14. **The egress proxy bounds what a peer can hold, and no more.** It closes
    a connection that carries nothing for two minutes and holds at most 256
    at once; one over is dropped. Anything that can reach its port can still
    fill those 256 and keep them busy, and the scanner's own reads would then
    be refused. It listens for the scanner alone: keep its port reachable
    from the scanner's network only, as the Compose overlay and the chart do.
    The idle limit also ends a read whose server sends nothing for two
    minutes; that source is reported incomplete.
15. **A leaked signing key, and an old report sent again.** The scanner has no
    way to revoke its own key. If the signing key leaks, remove its public key
    from wherever reports are accepted (the tenant's register of scanner
    keys), generate a new one with `scanent keygen`, and register that. A
    signed report carries the time it describes and a scan id, and nothing
    stops a copy of an old one being presented again: refusing a stale or
    repeated report is the consumer's job, not the scanner's.

## What has not been done

- No independent penetration test and no external code review.
- One pilot, on the maker's own real estate (Entra ID, GitHub Actions, Google
  Cloud, an Inflect register and source code; 2026-11-12). None at a client,
  and Okta, Azure Key Vault, LangSmith and MCP servers are still tested only
  against fakes written from the providers' documentation. False positives and
  false negatives per provider are not measured.
- The 72-hour soak has not been run; a 75-minute one has. The 72-hour one is required before 1.0.
- Keyless signing and the attestations run only on GitHub's runners, at a
  tag. They are written and reviewed. No release exists, so nothing has been
  signed and no client-side verification command has been run against a real
  signature. The release workflow has never run for a tag: its on-main
  check and its signing, publishing and release jobs have never run. It has
  been run by hand once to the end, which signs and publishes nothing: its
  gates, the build and smoke test on both architectures, the Syft SBOM step
  and the bundle.
- The long-test workflow has run twice on GitHub, by hand.
- CI first ran on GitHub in its present form on 2026-11-12, which is one day
  of history: lint, type-check, build and the tests on Node 22 and Node 24, `npm audit`, the licence
  allowlist, the Trivy and Grype scans, the cluster test, the rootless Podman
  job, CodeQL and Scorecard. Under rootless Podman the smoke test runs
  without its last step, the egress overlay. CodeQL's and Scorecard's
  findings have not been reviewed.
- The arm64 image has been built and bundled, never started.
- The repository settings the release checklist requires (private
  vulnerability reporting, secret scanning, branch and tag protection) were
  not on when last read, on 2026-11-12.

`docs/security-pack/assurance-status.md` says the same at more length, with
what has been done beside it.
