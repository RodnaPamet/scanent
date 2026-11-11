# scanent — Agent Estate Scanner

scanent (second name: Agent Estate Scanner, command `scanent`, alias `aes`)
runs inside an organisation's own estate and takes an inventory of the AI
agents and agent-shaped principals there: service principals, service
accounts, API tokens, CI workflows, MCP servers, tracing projects and agent
definitions in code. For each one it reports the credentials it holds (by
reference), the tools it can call, the model endpoints it uses, and verdicts
against a six-rung harness ladder (H0 to H5). The result is one signed JSON
report.

**Status: Phase 2, standalone results.** This repository is the scanner carved
out of the Inflect Compliance repository (see
[docs/EXTRACTION.md](docs/EXTRACTION.md) for what was moved and what was not),
and it now works with no Inflect tenant at all: one command scans an estate
and writes a page you can open, two spreadsheets, the results as JSON and the
signed report. See [See your results locally](#see-your-results-locally). A
container image is built and tested in CI; no image or package is published
yet.

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
| `packages/report` (`@scanent/report`) | Local results: scores a signed scan against the ladder with no tenant, from the report and an optional operator inventory; renders `results.json`, the two CSV files and `summary.html`; compares two runs. Pure functions |

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
makes no network request. Without `--dry-run` the scanner posts the report to
the tenant the configuration's `inflect` block names.

## See your results locally

No Inflect tenant is needed. `--out <dir>` writes each run's results under a
directory, and the example below uses a configuration with no `inflect` block
at all.

```bash
export SCANNER_SIGNING_KEY="$(openssl genpkey -algorithm ed25519)"
sed "s#__REPO__#$(pwd)#" examples/code-only/config.local.template.json > /tmp/scanent-local.json

npx scanent scan --config /tmp/scanent-local.json --out /tmp/scanent-out
```

The same with the container. The output directory is the one writable mount;
the root filesystem stays read-only. The container writes as uid 1000, so the
directory is opened up for it here (on a host where you can, `chown 1000` it
instead):

```bash
mkdir -p /tmp/scanent-config /tmp/scanent-out && chmod 0777 /tmp/scanent-out
sed "s#__REPO__/examples/code-only#/example#" \
  examples/code-only/config.local.template.json > /tmp/scanent-config/config.json

docker run --rm \
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  -e SCANNER_SIGNING_KEY \
  -v /tmp/scanent-config:/etc/scanent:ro \
  -v "$(pwd)/examples/code-only:/example:ro" \
  -v /tmp/scanent-out:/out \
  scanent scan --config /etc/scanent/config.json --out /out
```

Each run is one new directory, written whole or not at all, and nothing that
exists is ever overwritten except the `latest.json` pointer:

```
/tmp/scanent-out/
  latest.json                  which run is the newest
  runs/<scanId>/
    summary.html               open this one
    agents.csv                 one row per agent, one column per criterion
    findings.csv               one row per finding
    results.json               everything above, as data (schema scanent-results/1)
    report.signed.json         the signed report, byte for byte what would be posted
    manifest.json              the names, sizes and SHA-256 of the other five
```

`summary.html` is one self-contained file: no script, no image, no font and no
request to anywhere, so it can be opened from disk, attached to a ticket or
printed. What it says, in the order it says it:

- **Completeness first.** Which sources were read in full. An agent whose
  sources were not is shown as "Not judged", with the reason, and is given no
  level anywhere. Nothing is shown as gone or resolved on a partial read.
- **What this run could not have evidenced.** Many criteria are read only from
  an Inflect tenant's register, and some by no reader yet. The page names
  each, so "nothing in this run could have seen it" is not mistaken for "a
  source saw it fail". Without a register no agent can be shown above H1.
- **The estate**: agents per level, shortfalls, shadow agents, orphan
  credentials, and every agent against every criterion.
- **An empty scan is a finding**, never a clean result.

To show who owns an agent without a register, give the configuration an
inventory (`"inventory": { "path": ... }`, a JSON or CSV file; the example
uses `examples/code-only/inventory.example.json`). Everything it supplies is
labelled "declared by the operator" in every file, counts for the H1 criteria
only, and never enters the signed report.

Compare two runs:

```bash
npx scanent diff /tmp/scanent-out/runs/<older>/results.json /tmp/scanent-out/runs/<newer>/results.json
```

`diff` takes `results.json` files or signed reports. It calls an agent "gone",
or a finding "closed", only when the source that would have listed it was read
in full by the newer run; otherwise it says "not seen" and why. It exits 0 for
no difference, 1 for a difference, 2 for an error, and 3 when it found no
difference but could not compare everything.

No sample output is committed, because a run's files carry its time, a random
scan id and a signature from the key it was run with. The commands above
produce one in a few seconds.

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

The image runs as a non-root user, writes nothing outside a mounted output
directory and needs no capability, so
`--read-only --cap-drop ALL --security-opt no-new-privileges` is how it is
meant to run everywhere. `--network none` suits this example only, because the
`code` source reads local files; a source that reads an API needs a network.
The mounted files must be readable by uid 1000.

With no arguments the image runs `schedule --config /etc/scanent/config.json`:
one scan at once, then one every `schedule.everyHours`, each delivered to the
configuration's outputs (by default, posted to the `inflect` block's tenant). See [docs/scanner.md](docs/scanner.md), "Container".

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
