# Assurance status

What has been done to test scanent, and what has not. Read on 2026-11-13, at
commit `8388ff0` of `main`. This page is meant to be blunt.

## The short version

**scanent is tested and hardened in development. It is not proven in
production.**

| | Status |
|---|---|
| Run against a real estate | **Once, on the maker's own estate** (Inflect's): Entra ID, GitHub Actions, Google Cloud, an Inflect register and one repository of source code. **Not at a client**, and not for Okta, Azure Key Vault, LangSmith or an MCP server |
| External penetration test | **Not done** |
| Independent code review | **Not done** |
| 72-hour soak | **Not done.** A 75-minute soak has been run. The 72-hour one is required before 1.0 (owner decision, 2026-11-12) |
| Signed release | **Not done.** No release, no tag, no published image or package exists. The release workflow has been run by hand, which signs and publishes nothing |
| Any security certification of the product | **None.** None is claimed |

Do not describe scanent to anyone as battle-tested, pilot-proven,
penetration-tested or certified. The open work is tracked in issue 21 of the
repository ("Hardening that needs people or time"), and the threat model
lists the same under ["What has not been done"](../threat-model.md#what-has-not-been-done).

## What has not been done

### One pilot, on the maker's own estate, and none at a client

On 2026-11-12 the scanner was run once against a real estate: Inflect's own,
by Inflect. No client's estate has been scanned.

| Source | What happened |
|---|---|
| Microsoft Entra ID (`entra-sp`) | Read in full: 55 rows, 4 principals |
| GitHub Actions (`cicd`) | Read in full: 27 rows, 22 principals |
| Google Cloud (`gcp-sa`) | Read in full: 10 rows, 9 principals |
| An Inflect register (`inflect-register`) | Read in full: 6 agents |
| Source code (`code`) | One repository of 7,539 source files. The first scan could not read it. After three defects were fixed (issue 24) it was read in full, and held no agent of the frameworks the scanner recognises |

What it showed:

- The four live sources were read through an egress proxy that admits six
  hosts, in 14 seconds, and `doctor` passed first (26 checks passed, none
  failed).
- The scanner this one was extracted from ran on the same estate seconds
  later. Both reported the same 40 principals, and no field of any principal
  differed between the two reports.
- The first scan of a real repository was reported incomplete, for three
  reasons no test had caught: a vendored file over the size limit, ordinary
  code counted as code that could not be resolved, and a reason given with no
  sentence and no place. Issue 24 has the detail; all three are fixed.
- Of the 40 principals, 34 are not in the register. They are CI workflows
  that hold a credential, service accounts and service principals, and the
  scanner cannot tell which of them run a model. At the time of the run each
  was reported as a shadow agent at HIGH, with a second HIGH finding for
  being below the agent bar: 73 high findings. Since then a principal that
  shows no sign of a model is reported as an unregistered automated
  identity, at MEDIUM, and is held to no bar (issue 25). The same report
  scored again gives 5 high findings and 34 medium ones.

What it does not show:

- **False positives and false negatives are not measured**, for any source.
  There is no independent inventory of that estate to count against.
  Agreement with the earlier scanner shows that the extraction changed
  nothing; both could miss the same thing.
- It was the maker's estate, read by the maker. It says nothing about a
  client's directory, its size, its proxy or its approval process.
- An agent built directly on a model provider's SDK was not recognised by the
  `code` source when that scan was made. That estate's own agents are built
  that way: they were found through its register, not in its code. The `code`
  source has since been taught to read a model call that is given tools on
  the Anthropic, OpenAI, Gemini and Bedrock SDKs. That recognition is tested
  against fixtures written from the SDKs' own type definitions and source,
  and against one later copy of that estate's repository (7,555 source
  files), where it found the one call the estate's agents run through and
  could not resolve the request that call is given, which another file
  builds. It has not been run against a client's code.
- Okta, Azure Key Vault, LangSmith and MCP servers were not part of it. Each
  is still tested only against an imitation of the provider's API, written
  from the provider's documentation.
- A provider whose real behaviour differs from its documentation would not be
  caught by any test here.
- One such difference is already suspected and unconfirmed. Okta's
  documentation says a Read-only Administrator sees only its own API tokens.
  If so, a scan misses other users' tokens and still reports the Okta source
  as complete (threat model, residual risk 3; issue 16).
- A second Okta question is also unconfirmed. The scanner asks for Okta's
  applications listing whole, with no field selection. Whether that listing
  carries an application's client secret for a Read-only Administrator has
  not been checked against a live organisation. A test holds that a secret
  planted in the listing is dropped and not reported
  (`packages/scanner/tests/okta-source.test.ts`); no test can show what a
  real Okta sends.
- The scale figures in `docs/scanner.md` ("Limits and scale") were measured
  with imitations in place of the network. They are the scanner's own cost,
  not a measurement on a real estate.
- Proxy support relies on Node's own handling of `HTTPS_PROXY`. The pilot
  ran through an egress proxy of the scanner's own kind. It has not been
  confirmed against a real corporate proxy (issue 18).

### No external penetration test, no independent review

An internal adversarial review was carried out during hardening. Issue 20
records that it raised 35 findings, that 34 were fixed, and the follow-ups
that remain open. That review was done by the same team that wrote the code.
It is not an independent test and must not be presented as one.

### No long soak

`scripts/soak.js` exists, and a bounded schedule test runs with the unit
tests. The 72-hour scheduled run has not been done. The owner decided on
2026-11-12 that it is required before 1.0, and that a 0.x release needs a
soak of at least one hour.

The longest run so far: a 75-minute soak was run on 2026-11-13 at commit `7437554`: 75 scans, one a minute, none failed and none started late (the latest by 64 ms), and resident memory was 110 MiB after the first scan and 110 MiB after the last. It soaks the `code` source and the file
output only, and reaches no network.

### One signed release, checked once, by its maker

0.13.2, released on 2026-11-13, is the only complete release, and only its
maker has checked it as a client would. It is the first complete release
(https://github.com/RodnaPamet/scanent/releases/tag/v0.13.2). Its tag was made
by `.github/workflows/auto-release.yml` and every job of the release workflow
passed. Two tags before it were cut from the same scanner code and stopped
part way, and a version is never released twice:

- `v0.13.0` published nothing: the image push failed (the registry refused
  layers mounted from another organisation's image). The images are now
  pushed with `skopeo` from the tested archives.
- `v0.13.1` pushed and signed its images, then failed to publish the
  contract package (npm read the tarball's path as a GitHub shorthand). It
  has no contract package and no GitHub release.

What was checked on 0.13.2 as a client would, from outside GitHub Actions,
on 2026-11-13, with `cosign` 3.1.4 and the commands of
[Verify a release](../verify-a-release.md):

- The image was read from the registry with no login, under `0.13.2` and
  `0.13`, and no `latest` tag exists.
- `cosign verify` passed, with the documented identity, for the tag and for
  the amd64 and arm64 images by digest; `cosign verify-attestation --type
  cyclonedx` returned an SBOM for each (1,307 and 1,306 components).
- The ten release files are attached; the bundle matched its SHA-256, and
  `cosign verify-blob` passed for its signed list of checksums.
- `gh attestation verify` passed for the bundle and the image manifest, and
  named `release.yml` at `refs/tags/v0.13.2`.
- Unpacked, `verify.sh` passed with networking off given a trusted root file,
  `load.sh` loaded both images, and the loaded image ran with
  `--network none`.
- The contract package's publish step reported
  `+ @rodnapamet/scanent-contract@0.13.2`. Installing it was not tried from
  outside: that needs a token with read access to GitHub Packages.

0.14.0 (2026-11-13) was checked the same way the same day: no-login pull and
no `latest` tag; tag and per-architecture signatures; an SBOM attestation for
each architecture (1,345 and 1,344 components); ten release files; the
bundle's checksum and signed list; `verify.sh` with networking off given a
trusted root file; and the bundle's provenance.

Before the first tag, the release workflow was run by hand, which signs and
publishes nothing: twice on
  2026-11-12, where the first run failed at the SBOM step and the second
  passed, and once on 2026-11-13 at commit `8388ff0`, which passed
  (https://github.com/RodnaPamet/scanent/actions/runs/43356838356). Such a run builds
  and smoke-tests the image on amd64 and on arm64, makes a Syft SBOM of each,
  builds the air-gapped bundle, loads it and scans with what it loaded, and
  packs the contract package. Before the first of them, the arm64 image had
  never been started and no SBOM had been made by the pipeline.

The image is public (owner decision, 2026-11-12, issue 19): the organisation
first had to allow public packages, then the package was made public by hand
after 0.13.1 created it.

### Repository settings that are not on

Read from GitHub's API on 2026-11-12:

- **Private vulnerability reporting is not enabled.** [SECURITY.md](../../SECURITY.md)
  directs reports to it. Until it is switched on, that route does not work.
- **Secret scanning and push protection are not enabled.**
- **The `main` branch is not protected**, and no ruleset exists. So nothing
  on GitHub's side restricts who can push to `main` or create a tag. The
  ruleset to be made on `v*` must let GitHub Actions create tags, because
  the release tag is made by a workflow.

`docs/release-checklist.md` requires all of these before the first release.
Residual risk 8 of the threat model (the release identity) rests on them.

### Other things that have never run, or have run by hand only

- The long-test workflow (`.github/workflows/long-tests.yml`: the fuzzing and
  scale tests with their large budgets) has run twice, by hand, on 2026-11-12
  and on 2026-11-13 at commit `8388ff0`, and passed both times
  (https://github.com/RodnaPamet/scanent/actions/runs/43356834306). Two runs
  with one seed are what that shows.
- Under rootless Podman, CI runs the image's smoke test without its last
  step (the egress overlay), because that step needs Compose.
- CodeQL and Scorecard have each run and finished. Their findings, if any,
  have not been reviewed for this page, and no Scorecard score is claimed.

## What has been done

All of the following is in the repository and can be re-run.

### On every push and pull request (CI)

On 2026-11-13 every job below passed on `main` at commit `8388ff0`:

| Job | What it does |
|---|---|
| Lint, type-check, build, test, on Node 22 and on Node 24 | Lint, type-check, build and the unit and property tests on both versions. On Node 24 the tests run under an 80% coverage gate, followed by the reproducible-build check. `npm audit` of production dependencies (moderate and above) and the licence allowlist are steps of the same job |
| Image | Builds the image; runs the 11-step smoke test (`deploy/smoke.sh`) against it under Docker; scans it with Trivy and with Grype |
| Image, under rootless Podman | Builds and runs the smoke test as a non-root user, without the egress-overlay step |
| Helm chart | Lints and renders the chart with each of its value sets |
| Helm chart, installed on kind | Installs the chart on a throwaway cluster, runs one scan, reads the result back, and probes the NetworkPolicy (`deploy/kind-test.sh`) |
| CodeQL | Static analysis of the TypeScript |
| Scorecard | OpenSSF Scorecard analysis |

The pipeline in this form first ran on GitHub on 2026-11-12. That first run
found two real defects, both fixed in `7836ef9`: the scanner's view of
which hosts bypass a proxy disagreed with Node 24, and the documented Podman
command worked only for a user whose id is 1000. That is one day of CI
history, not a track record.

### What the tests cover

Each is described, with the file that holds it, in [Controls](controls.md)
and the [threat model](../threat-model.md).

- **Read-only proof.** Every source and every preflight is run against a
  recorder; a request that is not declared, or a declared request that
  nothing makes, fails. Two parts of the declaration are outside that check:
  the five OpenShell gateway calls, which are declared and cannot be reached,
  and the egress proof's probes, which have a test of their own.
- **Secret canaries.** Secret-shaped values are planted in provider responses
  and in outputs; the tests fail if one reaches a report, a file or the
  process's output.
- **Request forgery.** Tables of address spellings, redirects and next-page
  links; DNS answers that change between check and use.
- **Fuzzing**, with a short budget in every run: provider responses, operator
  inputs, and the code readers.
- **A hostile repository.** Links, pipes, oversized files, deep nesting, files
  that change during the read.
- **Partial failure.** Rate limits, outages and expired credentials, per
  source: none makes a finding disappear.
- **Scale**, at 500 agents in every run.
- **Compatibility.** Files written by an earlier commit of the code
  (`190f3fb`, the earlier unreleased version 0.12.0) are read by the current
  code, with one exception: its two inventory files are
  `scanent-inventory/1`, which the current code refuses with a message
  saying what changed. No released version exists to compare with. A second
  directory, `0.13.0`, holds what the code of the first release wrote (commit
  `8388ff0`), so that the version after it is tested against it. A third,
  `0.15.0`, holds what the code tagged `v0.15.0` wrote (commit `dedb214`).
  0.14.0 has none: none was made at its release.
- **The deployment templates.** Compose, the chart, the air-gapped bundle's
  scripts (against stand-ins for the container runtime and `cosign`).
- **The documents.** Several pages are generated from the code or checked
  against it, this pack included.

### What a test here cannot show

- That a real provider answers as its documentation says.
- That the scanner finds every agent in a real estate, or reports none that
  is not there.
- That a determined attacker with time cannot find a way through. Tests show
  the presence of the defences they were written for.

## What to do with this

- **For a first engagement:** treat it as the pilot it is. Check results by
  hand against what the client knows, record every mismatch, and run with the
  narrowest read-only grants in [Access the scanner needs](../access.md).
  The [run-book](../engagement/run-book.md) has the steps.
- **For a security review:** the controls are real and testable, and
  [Controls](controls.md) names the test for each. The evidence that is
  missing is operational and independent, and this page lists it.
- **Before calling it production-ready:** the items under "What has not been
  done" need to be closed, and this page updated with the date and the
  evidence for each.
