# Support and maintenance

How to report a problem, who fixes what, how a new source is added, how the
report and results formats are versioned, and what a release contains.

## What exists today, and what does not

- The repository states **no support contract, no service level and no
  release cadence**. Those are commercial terms and come from the licensor,
  Inflect Ltd. (see [SBOM and licences](sbom-and-licences.md#commercial-terms)).
- **No release has been published.** The process below is written and tested
  for its shape. It has not run. See [Assurance status](assurance-status.md).
- The security policy's response times are a statement of intent from a small
  project, and the policy says so.

## Reporting a vulnerability

Follow [SECURITY.md](../../SECURITY.md). In short:

- Report privately through GitHub's private vulnerability reporting for the
  repository (the Security tab, then "Report a vulnerability"). Do not open a
  public issue, pull request or discussion.
- Do not include a real credential, a real report or a real estate's data. A
  synthetic example is enough.
- The policy commits to an acknowledgement within 5 working days, an
  assessment within 15 working days, and a fix in a new release with an
  advisory, aiming for disclosure no more than 90 days from the report.

**As read from GitHub's API on 2026-11-12, private vulnerability reporting is
not yet enabled on the repository**, so that route does not work today.
Switching it on is the first item of `docs/release-checklist.md`. Until it is
on, a reporter has no private channel through GitHub; an engagement team
should route a suspected vulnerability through its own contact at the
licensor.

## Reporting a defect that is not a vulnerability

Open an issue in the repository. Attach the output of
`scanent support-bundle` if it helps: it describes a deployment without its
credentials and with its names replaced by tokens
([Operating scanent](../operations.md#asking-for-help-the-support-bundle)).
Read it before you send it.

## Who fixes what

| Problem | Who |
|---|---|
| A defect in the scanner, the report contract, the local results, the image, the chart, the Compose files or the air-gapped bundle | The maintainers of this repository |
| A vulnerability in a dependency or in the base image | The maintainers, by updating it. Dependabot proposes npm, base-image and GitHub Actions updates weekly (`.github/dependabot.yml`), and CI runs its vulnerability gates weekly as well as on every change, because a new advisory can fail code that passed last week |
| A provider's API behaving differently from its documentation | Report it here so the source can be corrected. The provider's behaviour itself is the provider's |
| A finding about an agent or a credential in your estate | You. The scanner reports; it changes nothing |
| The read-only grants, the credentials, the signing key, the output directory, the schedule | Whoever operates the deployment |
| An MCP server, an identity provider or another system the scanner reads | Its owner |

Supported versions, from the security policy: the latest released version
receives security fixes. Before version 1.0 there are no maintenance
branches; a fix is a new release.

## How a new source is added

A source is one reader of one kind of inventory. The interface is
`HarnessSource` in `packages/scanner/src/source.ts`:

```ts
export interface HarnessSource {
    readonly kind: SourceKind;
    readonly product: string;
    read(ctx: SourceContext): Promise<SourceRead>;
    preflight(ctx: SourceContext): Promise<readonly ProbeStep[]>;
}
```

- `read` returns what it saw of each principal (`Observation`) and how far it
  got (`COMPLETE`, or `INCOMPLETE` with one of the contract's reasons). It
  never throws for a read that went wrong.
- `preflight` is what `scanent doctor` runs. It is a required member, so a
  source cannot ship without one, and it may make only requests `read` makes.
- `SourceContext` is everything a source is given: a clock and a deadline, a
  GET-only HTTP client, the token exchange, the MCP listing wire, the
  register read and the OpenShell gateway wire. The last four each have one
  fixed purpose. The token exchange, the MCP listing and the register read
  are POSTs with a fixed body; the OpenShell wire refuses every call, because
  no transport for it is built in. There is no way to pass an HTTP method.

What a source cannot do, by construction: issue a request of its own
choosing that is not a GET (the MCP and register sources read their
inventory through their fixed-purpose wires, which are POSTs); decide that an
agent is registered (only the register
source's claim reaches the report); carry a credential value.

### The checklist

Each step names the file, and what fails if the step is skipped. The steps
are taken from the code as it stands; most are enforced by the type checker
or by a test, so a half-added source does not build.

| # | Step | File | What holds it |
|---|---|---|---|
| 1 | Write the reader: `read` and `preflight`, the fixed origin and the read paths as exported constants | A new file under `packages/scanner/src/sources` | The `HarnessSource` type |
| 2 | Declare every request it makes | `packages/scanner/src/scanner-surface.ts` (`SCANNER_SURFACE`) | `packages/scanner/tests/read-only-proof.test.ts` fails on an undeclared request and on a declared request that nothing makes (the OpenShell gateway calls and the egress proof's probes are the two declared exceptions it does not exercise) |
| 3 | Raise the scanner's version: the declared surface changed, so the manifest hash in every report changes | `packages/scanner/src/scanner-surface.ts` (`SCANNER_VERSION`) | The comment on the constant records each change; the release workflow refuses a tag that does not name it |
| 4 | Add its configuration schema, strict, with credentials by variable name only | `packages/scanner/src/config.ts` (`parseScannerConfig`) | `packages/scanner/tests/scanner-config-and-schedule.test.ts`, `packages/scanner/tests/fuzz-inputs.test.ts` |
| 5 | Build it from the configuration | `packages/scanner/src/scan.ts` (`buildSources`) | `packages/scanner/tests/read-only-proof.test.ts` requires a row for every kind of the configuration schema |
| 6 | List the hosts it reaches | `packages/scanner/src/hosts.ts` | `packages/scanner/tests/hosts.test.ts` |
| 7 | Write its access entry: the read-only grant, where it is created, what it reads, what must not be granted | `packages/scanner/src/init/access-guide.ts` (`ACCESS_GUIDE`, `GUIDE_ORDER`) | The table is typed over every source kind; then `npm run docs:access` regenerates `docs/access.md` |
| 8 | Give `init` its default credential name and question | `packages/scanner/src/init/plan.ts`, `packages/scanner/src/init/prompts.ts` | `packages/scanner/tests/init-plan.test.ts`, `packages/scanner/tests/init-prompts.test.ts` |
| 9 | Describe each request and what is deliberately not requested, for the security page | `packages/scanner/src/surface-doc.ts` | `packages/scanner/tests/network-and-permissions-doc.test.ts`; then `npm run docs:network` regenerates `docs/network-and-permissions.md` |
| 10 | Say which criteria it can report, and which it can report as met | `packages/scanner/src/criterion-readers.ts` (`CRITERION_READERS`) | `packages/scanner/tests/criterion-readers.test.ts` reads each source's code and runs it |
| 11 | Write an imitation of the provider's API and the source's own tests, including each way a read can stop | `packages/scanner/tests/helpers/agent-harness-source-fakes.ts`, a new test file | The coverage gate |
| 12 | Add it to the one imitation estate the hardening suites run: the read-only proof, the secret canaries, response fuzzing, the partial-failure matrix and the scale tests all take their sources from it | `packages/scanner/tests/helpers/estate-world.ts` (`ESTATE_SOURCES`) | `packages/scanner/tests/read-only-proof.test.ts` fails when its rows are not exactly the source kinds of the configuration schema |
| 13 | State what personal data it reads | `docs/data-protection.md` | `packages/scanner/tests/docs-cited-paths.test.ts` requires a row for every source kind |
| 14 | Add an example configuration | `deploy/examples` | `packages/scanner/tests/deploy-templates.test.ts`; `npm run docs:examples` |

A source for a **new kind** (not a new product under an existing kind) also
changes the report contract, because the kinds are a closed list on the wire:

| # | Step | File | What holds it |
|---|---|---|---|
| 15 | Add a new contract id with its own strict schema beside the others. Never widen an existing one | `packages/contract/src/harness-contract-rules.ts`, `packages/contract/src/harness-contract.ts` | `packages/contract/tests/harness-contract.test.ts`, `packages/contract/tests/contract-doc.test.ts` |
| 16 | Classify the kind: does it bear identities and credentials? | `packages/contract/src/harness-findings.ts` (`IDENTITY_BEARING_SOURCE`) | A record over every kind: it does not compile until the kind is classified |
| 17 | Classify the kind: does it report verdicts about other sources' agents? | `packages/report/src/results/judgement.ts` (`CROSS_AGENT_VERDICT_SOURCE`) | The same |
| 18 | Describe the new id | `docs/contract.md` | `packages/contract/tests/contract-doc.test.ts` |
| 19 | Any consumer of the report must accept the new id before a scanner writes it | The consumer | |

A new source must hold the properties in [Controls](controls.md): reads only,
no secret value requested, every bound reported, nothing dropped in silence.
A source that needs a request that is not a read, or that returns secret
values, is a design question to raise before any code.

## Versioning

| Thing | Identifier today | How it changes |
|---|---|---|
| The scanner | `SCANNER_VERSION`, 0.13.1 | Raised with any change to what the scanner reads or reports. It is in every report, beside the hash of the declared request surface |
| The report contract | `inflect-agent-harness/3` is written; `/2` is accepted by the verifier; `/1` is retired and refused | A new id is a new strict schema beside the others, never a looser schema that reads either. An unknown member anywhere is a refusal. [The report contract](../contract.md) is the normative description, and a test holds it to the code |
| The ladder | `LADDER_VERSION`, a hash over the levels, criteria and bars | It is not in the report. Results derived from a report carry it, and two sets of results compare level for level only when they carry the same one |
| The results file | `scanent-results/1` | One schema id exists. An optional member has been added to it once without a new id; `packages/scanner/tests/compat.test.ts` proves that files written by the earlier, unreleased 0.12.0 are still read |
| The inventory file | `scanent-inventory/2` | `/1` is retired and refused, and the refusal says what changed: `/2` took the axis names, their values and the risk tiers of Inflect's agent register. No version was released with `/1`, so nothing converts a `/1` file |
| The `init` answers file | `scanent-init-answers/1` | One id exists |
| The `doctor` report and the support bundle | `scanent-doctor/1`, `scanent-support/1` | One id each |

Compatibility is tested, not promised in words: each release is to add a
directory of what that version wrote under
`packages/scanner/tests/fixtures/compat`, and every such directory is read by
the current code on every test run. One directory exists today, named
0.12.0. It was made from a commit of that earlier, unreleased version
(`190f3fb`), not from a release.

A change that can stop a set-up that scanned before is listed in
`docs/scanner.md` under "Changes that can stop a setup that scanned before",
and `docs/release-checklist.md` requires it for every release.

The version numbers are below 1.0. No compatibility promise beyond the tests
above is made in this repository.

## What a release contains

Written in `.github/workflows/release.yml`, for a tag `v<version>`. **Never
run: no release exists.**

| Item | Where |
|---|---|
| The image for amd64 and arm64 under one manifest, `ghcr.io/rodnapamet/scanent:<version>`. Public: a pull needs no login. No `latest` tag; a published version is never pushed again | The container registry |
| A keyless signature on the manifest and on each architecture's image, by digest | With the image |
| A CycloneDX SBOM per architecture, as a signed attestation | With the image, and attached to the release |
| Build provenance for the manifest, each image and the bundle | Attestations, and attached to the release as files |
| The air-gapped bundle: one image archive per architecture, `load.sh`, `verify.sh`, the Compose files, the Helm chart, example configurations, the operating documents, the SBOMs, `LICENSE` and `NOTICE`, with a SHA-256 for every file | Attached to the release as `scanent-<version>-airgap.tar` |
| The bundle's SHA-256, its list of checksums, and the signature over that list | Attached to the release |
| The report contract as an npm package, `@rodnapamet/scanent-contract@<version>`: compiled code, type declarations, `LICENSE` and `NOTICE`, with build provenance for the tarball. A published version is never published again | GitHub Packages. An install needs a token ([the contract page](../contract.md#install-it)) |

Before anything is built, the workflow holds the tagged commit to what a
commit on `main` is held to, and refuses a tag whose commit is not on `main`.

Nobody tags a release by hand (owner decision, 2026-11-13). A change of
`SCANNER_VERSION` with its release notes is the release: once CI passes on
`main`, the auto-release workflow (`.github/workflows/auto-release.yml`) tags
that commit `v<version>` as GitHub Actions and starts the release workflow on
the tag. A person's manual run of the release workflow publishes and signs
nothing.

How a client checks each item is in [Verify a release](../verify-a-release.md).
What the maintainers do before and after a tag is in
`docs/release-checklist.md`.

The image is to be public (owner decision, 2026-11-12, issue 19). GitHub
creates a container package private, so after the first release somebody sets
the package's visibility to Public by hand, once; the release checklist has
the step, and the release workflow reports whether the image answered without
a login.
