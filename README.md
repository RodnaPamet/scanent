# scanent — Agent Estate Scanner

scanent (second name: Agent Estate Scanner, command `scanent`, alias `aes`)
runs inside an organisation's own estate and takes an inventory of the AI
agents and agent-shaped principals there: service principals, service
accounts, API tokens, CI workflows, MCP servers, tracing projects and agent
definitions in code. For each one it reports the credentials it holds (by
reference), the tools it can call, the model endpoints it uses, and verdicts
against a six-rung harness ladder (H0 to H5). The result is one signed JSON
report.

**Status: Phase 1 extraction.** This repository is the scanner carved out of
the Inflect Compliance repository, with its behaviour unchanged. See
[docs/EXTRACTION.md](docs/EXTRACTION.md) for exactly what was moved and what
was not. A container image is built and tested in CI; no image or package is
published yet. The only output is the signed report (posted to an Inflect
tenant, or printed with `--dry-run`). Local, human-readable report outputs are
planned for Phase 2.

## Read-only by design

- A source holds an HTTP client whose only verb is GET. The one POST a source
  can cause is the token exchange with the identity provider, behind its own
  interface. MCP servers are sent `initialize` and `tools/list`, never
  `tools/call`; the one exception is the read of the scanner's own tenant's
  register.
- A secret's value is never requested. Credentials are reported by reference
  (`env://NAME`, `azure-kv://…`, `github-secret://…`), and the scanner refuses
  to sign a report in which any string has a secret's shape.
- Code is parsed, never run: the `code` source imports, evaluates and spawns
  nothing.
- Every request the scanner can make is declared in one file
  (`packages/scanner/src/scanner-surface.ts`). The hash of that declaration is
  in every report, and the tests hold every request the fakes see to it.
- A source that could not be read in full is in the report as `INCOMPLETE`
  with its reason. It is never left out and never reported as complete.

[docs/scanner.md](docs/scanner.md) describes each source in detail.

## Sources

"Implemented" means the reader is in this repository and its tests pass
against fakes of the product's API.

| Kind | Product | Status |
|---|---|---|
| `entra-sp` | Microsoft Entra service principals and managed identities | Implemented |
| `okta-app` | Okta service apps and API tokens | Implemented |
| `vault` | Azure Key Vault secrets and certificates (metadata only) | Implemented |
| `gcp-sa` | Google Cloud IAM service accounts and their keys | Implemented |
| `cicd` | GitHub Actions workflows and repository secrets (names only) | Implemented |
| `runtime` | LangSmith tracing projects and deployments | Implemented |
| `code` | LangChain, LangGraph and Claude Agent SDK agent definitions in Python, JavaScript and TypeScript | Implemented |
| `mcp` | MCP servers' tool listings | Implemented |
| `inflect-register` | An Inflect tenant's agent register | Implemented; needs an Inflect tenant |
| `runtime` | NVIDIA OpenShell gateway | **Not available.** A reader exists in the source tree, but no configuration selects it |

## Packages

| Package | What it is |
|---|---|
| `packages/contract` (`@scanent/contract`) | The report contract: strict schemas, the harness ladder, the findings planner, canonical JSON and signature verification |
| `packages/scanner` (`@scanent/scanner`) | The scanner and its command line |
| `packages/report` (`@scanent/report`) | Local results: scores a signed scan against the ladder with no tenant, from the report and an optional operator inventory. Pure functions; the output files arrive later in Phase 2 |

## Quick start, from source

Needs Node.js 22 or later, and `openssl` for the throwaway key.

```bash
npm ci
npm run build

# A throwaway signing key.
export SCANNER_SIGNING_KEY="$(openssl genpkey -algorithm ed25519)"

# A configuration that reads the example estate. A code root is an absolute path.
sed "s#__REPO__#$(pwd)#" examples/code-only/config.template.json > /tmp/scanent-example.json

# The public half of the key, then one scan printed instead of posted.
node packages/scanner/dist/cli.js public-key --config /tmp/scanent-example.json
node packages/scanner/dist/cli.js scan --dry-run --config /tmp/scanent-example.json
```

`npm ci` also links the two commands, so after the build the same thing is
`npx scanent` or `npx aes`:

```bash
npx scanent scan --dry-run --config /tmp/scanent-example.json
npx aes public-key --config /tmp/scanent-example.json
```

`--dry-run` prints the signed report on stdout and posts nothing; the log is
JSON lines on stderr. The `code` source reads local files only, so this example
makes no network request. The `inflect` block is required by the configuration
schema even for a dry run; without `--dry-run` the scanner posts the report
there.

## Quick start, container

Needs Docker (or another runtime that builds a Dockerfile) and `openssl`.

```bash
docker build -f deploy/Dockerfile -t scanent .

export SCANNER_SIGNING_KEY="$(openssl genpkey -algorithm ed25519)"

# The example estate is mounted at /estate, so the configuration names that path.
mkdir -p /tmp/scanent-config
sed "s#__REPO__/examples/code-only/estate#/estate#" \
  examples/code-only/config.template.json > /tmp/scanent-config/config.json

docker run --rm \
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  -e SCANNER_SIGNING_KEY \
  -v /tmp/scanent-config:/etc/scanent:ro \
  -v "$(pwd)/examples/code-only/estate:/estate:ro" \
  scanent scan --dry-run --config /etc/scanent/config.json
```

The image runs as a non-root user, writes no file and needs no capability, so
`--read-only --cap-drop ALL --security-opt no-new-privileges` is how it is
meant to run everywhere. `--network none` suits this example only, because the
`code` source reads local files; a source that reads an API needs a network.
The mounted files must be readable by uid 1000.

With no arguments the image runs `schedule --config /etc/scanent/config.json`:
one scan at once, then one every `schedule.everyHours`, each posted to the
`inflect` block's tenant. See [docs/scanner.md](docs/scanner.md), "Container".

Behind a TLS-inspecting proxy, give the build that proxy's certificate
authority as the optional `ca` build secret; it is used by the two `npm ci`
steps only and reaches no layer:

```bash
docker build --secret id=ca,src=/path/to/ca.pem -f deploy/Dockerfile -t scanent .
```

`deploy/smoke.sh scanent` runs the image's smoke test against the image you
built.

## Development

```bash
npm run lint        # eslint: typescript-eslint recommended, plus the scanner's import boundaries
npm run typecheck   # sources and tests, nothing emitted
npm run build       # tsc, each package to its dist/
npm test            # jest
```

CI (`.github/workflows/ci.yml`) runs those four on Node.js 22 and 24 on every
pull request and push to `main`, and in a second job builds the image,
smoke-tests it and scans it with Trivy.

## Licence

scanent is licensed under the **Business Source License 1.1** (BUSL-1.1); the
licensor is Inflect Ltd. See [LICENSE](LICENSE). BUSL-1.1 is a source-available
licence. **It is not an open-source licence**: production use is subject to the
licence's Additional Use Grant, and each version converts to the Apache License
2.0 on its Change Date.

[NOTICE](NOTICE) carries the third-party attribution: the receipt format the
contract verifies, and the run-time dependencies the image redistributes. The
image holds both files in `/app`.
