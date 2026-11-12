# scanent — Agent Estate Scanner

scanent (second name: Agent Estate Scanner, command `scanent`, alias `aes`)
runs inside an organisation's own estate and takes an inventory of the AI
agents and agent-shaped principals there: service principals, service
accounts, API tokens, CI workflows, MCP servers, tracing projects and agent
definitions in code. For each one it reports the credentials it holds (by
reference), the tools it can call, the model endpoints it uses, and verdicts
against a six-rung harness ladder (H0 to H5). The result is one signed JSON
report.

**Status: Phase 4, hardening (in progress).** This repository is the
scanner carved out of the Inflect Compliance repository (see
[docs/EXTRACTION.md](docs/EXTRACTION.md) for what was moved and what was not).
It works with no Inflect tenant at all: `scanent init` writes a configuration
and a signing key, `scanent doctor` checks that the estate can be read, and
`scanent scan` writes a page you can open, two spreadsheets, the results as
JSON and the signed report. See [Quick start](#quick-start-from-source) and
[See your results locally](#see-your-results-locally). A container image is
built and tested in CI; no image or package is published yet.

**For the organisation being scanned:** [docs/guide/README.md](docs/guide/README.md)
is a guide in plain language for an IT or security lead who is not a
developer: what the scanner is and is not, what it reads and the access to
grant, how to run a first scan, how to read the report, what to do about each
finding, and the questions a security team asks.

**For a security team:** [docs/network-and-permissions.md](docs/network-and-permissions.md)
lists every request the scanner can make and every grant it asks for,
[docs/threat-model.md](docs/threat-model.md) what it defends against and what
it does not, [docs/data-protection.md](docs/data-protection.md) the personal
data it touches (with a DPIA template), and
[docs/verify-a-release.md](docs/verify-a-release.md) how to check a release's
signature, SBOM and provenance. Report a vulnerability as
[SECURITY.md](SECURITY.md) says.

The [security intake pack](docs/security-pack/README.md) is the index for a
reviewer: architecture, a table of each control with the code that enforces it
and the test that proves it, and a blunt page on what has and has not been
done to test the scanner. No pilot on a real estate, no external penetration
test and no signed release exist yet.

**For whoever arranges a scan:** the [engagement kit](docs/engagement/README.md)
has a scoping checklist, a ready-to-send read-only access request for each
source, a data-handling statement, a run-book and how to make a sample report
from made-up data. [docs/roadmap.md](docs/roadmap.md) lists what is not in this
version.

**For whoever operates it:** [docs/operations.md](docs/operations.md) has the
log's events and fields, the exit codes, and `scanent support-bundle`.

**Running it at your own site:** [docs/quick-start.md](docs/quick-start.md),
"Run it at your site in 15 minutes", needs a container runtime and nothing
else. [docs/deployment.md](docs/deployment.md) covers Docker, Podman, Compose,
Kubernetes (a Helm chart) and a site with no internet (an air-gapped bundle).

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

Needs Node.js 22 or later, and nothing else.

```bash
npm ci
npm run build

# 1. Set up. Asks which sources you have, then writes ./scanent/config.json,
#    ./scanent/scanent.env (the NAMES of the credentials to fill in) and a
#    signing key, and prints the read-only access each source needs.
npx scanent init

# 2. Put each credential in scanent.env, then load it. The shell reads this file here, and
#    the shell rewrites $, #, ; and spaces: put each value you add in single quotes
#    (OKTA_API_TOKEN='...'), and take the quotes out again before giving the same file to
#    `docker --env-file`, which takes a value as written. A NAME_FILE=/path line needs neither.
set -a; . ./scanent/scanent.env; set +a

# 3. Check: the configuration, the key, each credential, each host, each read.
npx scanent doctor --config ./scanent/config.json

# 4. Scan. The results are written under the directory you chose.
npx scanent scan --config ./scanent/config.json
```

`init` never asks for a secret value, and refuses an answer that looks like
one. `doctor` reads only: it writes and posts nothing, and it says "not
observable" where it cannot check something rather than passing it. Both are
described in [docs/scanner.md](docs/scanner.md#setting-up-an-estate), and the
access each source needs is in [docs/access.md](docs/access.md).

To try it on the example estate in this repository, with no credential and no
network, give `init` its answers as a file:

```bash
cat > /tmp/scanent-answers.json <<ANSWERS
{
  "answers": "scanent-init-answers/1",
  "estate": "example-code",
  "outputDir": "$HOME/scanent-out",
  "inventoryPath": "$(pwd)/examples/code-only/inventory.example.json",
  "sources": [
    { "kind": "code", "roots": [{ "label": "example", "path": "$(pwd)/examples/code-only/estate" }] }
  ]
}
ANSWERS
npx scanent init --dir /tmp/scanent-example --answers /tmp/scanent-answers.json
set -a; . /tmp/scanent-example/scanent.env; set +a
npx scanent doctor --config /tmp/scanent-example/config.json
npx scanent scan --config /tmp/scanent-example/config.json
```

`doctor` exits 3 here, with one warning: the example estate is writable by
you, and it advises mounting agent code read-only. The scan runs all the same.

`npx scanent` and `npx aes` are the same program, and so is
`node packages/scanner/dist/cli.js`. `npx scanent help` lists every command.

### Without `init`

A configuration can also be written by hand, and the signing key made with
`openssl` and passed in the environment:

```bash
export SCANNER_SIGNING_KEY="$(openssl genpkey -algorithm ed25519)"

# A configuration that reads the example estate. A code root is an absolute path.
sed "s#__REPO__#$(pwd)#" examples/code-only/config.template.json > /tmp/scanent-example.json

# The public half of the key, then one scan printed instead of posted.
npx scanent public-key --config /tmp/scanent-example.json
npx scanent scan --dry-run --config /tmp/scanent-example.json
```

`--dry-run` prints the signed report on stdout and posts nothing; the log is
JSON lines on stderr. The `code` source reads local files only, so this example
makes no network request. Without `--dry-run` the scanner posts the report to
the tenant the configuration's `inflect` block names.

For any credential the configuration names, `<NAME>_FILE` may name a file
holding the value instead of the variable holding it
(`SCANNER_SIGNING_KEY_FILE=/path/to/key.pem`). Behind a proxy, set
`HTTPS_PROXY` and `NODE_USE_ENV_PROXY=1`; to trust a private certificate
authority, set `NODE_EXTRA_CA_CERTS` to its PEM file. See
[docs/scanner.md](docs/scanner.md#secrets-from-files).

## See your results locally

No Inflect tenant is needed. `--out <dir>` writes each run's results under a
directory, and the example below uses a configuration with no `inflect` block
at all.

```bash
export SCANNER_SIGNING_KEY="$(openssl genpkey -algorithm ed25519)"
sed "s#__REPO__#$(pwd)#" examples/code-only/config.local.template.json > /tmp/scanent-local.json

npx scanent scan --config /tmp/scanent-local.json --out "$HOME/scanent-out"
```

The same with the container. The output directory is the one writable mount;
the root filesystem stays read-only. The results are evidence, so the directory
is private to you (`0700`, not a world-writable one under `/tmp`), and the
container runs as you (`--user`), so it can write there and you can read what
it wrote:

```bash
mkdir -p /tmp/scanent-config && mkdir -m 0700 -p "$HOME/scanent-out"
sed "s#__REPO__/examples/code-only#/example#" \
  examples/code-only/config.local.template.json > /tmp/scanent-config/config.json

docker run --rm --user "$(id -u):$(id -g)" \
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  -e SCANNER_SIGNING_KEY \
  -v /tmp/scanent-config:/etc/scanent:ro \
  -v "$(pwd)/examples/code-only:/example:ro" \
  -v "$HOME/scanent-out:/out" \
  scanent scan --config /etc/scanent/config.json --out /out
```

Without `--user` the image runs as uid 1000, and the run's directories (`0750`)
and files (`0640`) are readable by uid 1000 and root only: give it a directory
owned by uid 1000 (`chown 1000`), never one that every user can write. Rootless
Docker and Podman map users differently; there, run it as the user that maps to
you (Podman: `--userns=keep-id --user "$(id -u):$(id -g)"`).

Each run is one new directory, written whole or not at all, and nothing that
exists is ever overwritten except the `latest.json` pointer:

```
<output directory>/
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
npx scanent diff "$HOME/scanent-out"/runs/<older>/results.json "$HOME/scanent-out"/runs/<newer>/results.json
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

To run the image at a site, follow [docs/quick-start.md](docs/quick-start.md):
`init`, `doctor` and `scan` from the image, as yourself, with no `openssl` and
no checkout. What follows builds the image from this checkout and scans the
example estate with it. It needs Docker (or another runtime that builds a
Dockerfile) and `openssl`.

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
The mounted files must be readable by the user the container runs as (uid 1000
unless `--user` says otherwise).

`init`, `keygen`, `doctor` and `hosts` are in the image too. A credential can
be given as a mounted file: set `<NAME>_FILE` to its path in the container.
The image sets `NODE_USE_ENV_PROXY=1`, so `HTTPS_PROXY` and `NO_PROXY` take
effect when they are set.

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

`deploy/` also holds a Compose file and its egress overlay, a Helm chart
(`deploy/helm/scanent`), the air-gapped bundle's scripts (`deploy/airgap`) and
example configurations (`deploy/examples`).

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
