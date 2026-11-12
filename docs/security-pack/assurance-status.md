# Assurance status

What has been done to test scanent, and what has not. Read on 2026-11-12, at
commit `7836ef9` of `main`. This page is meant to be blunt.

## The short version

**scanent is tested and hardened in development. It is not proven in
production.**

| | Status |
|---|---|
| Run against a real estate of any provider | **Not done** |
| External penetration test | **Not done** |
| Independent code review | **Not done** |
| 72-hour soak | **Not done** |
| Signed release | **Not done.** No release, no tag, no published image or package exists |
| Any security certification of the product | **None.** None is claimed |

Do not describe scanent to anyone as battle-tested, pilot-proven,
penetration-tested or certified. The open work is tracked in issue 21 of the
repository ("Hardening that needs people or time"), and the threat model
lists the same under ["What has not been done"](../threat-model.md#what-has-not-been-done).

## What has not been done

### No pilot on a real estate

Every source (Entra, Okta, Azure Key Vault, Google Cloud, GitHub Actions,
LangSmith, MCP) is tested against an imitation of the provider's API, written
from the provider's documentation. The only real input the scanner has read is
the small offline code example in `examples/code-only`.

What follows from that:

- **False positives and false negatives are not measured**, for any source.
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
- Proxy support relies on Node's own handling of `HTTPS_PROXY`. It has not
  been confirmed against a real corporate proxy (issue 18).

### No external penetration test, no independent review

An internal adversarial review was carried out during hardening. Issue 20
records that it raised 35 findings, that 34 were fixed, and the follow-ups
that remain open. That review was done by the same team that wrote the code.
It is not an independent test and must not be presented as one.

### No long soak

`scripts/soak.js` exists, and a bounded schedule test runs with the unit
tests. The 72-hour scheduled run has not been done. The threat model records
that a five-minute run was done; nothing longer.

### No signed release

No tag has been pushed and no release exists. So:

- Keyless signing, the SBOM attestations and the provenance attestations have
  never run.
- The release workflow (`.github/workflows/release.yml`) has never run, in
  any of its jobs, including its check that a tagged commit is on `main`.
- No command in [Verify a release](../verify-a-release.md) has been run
  against a real signature. `deploy/airgap/verify.sh` and
  `deploy/airgap/sign-bundle.sh` have been run against a stand-in for
  `cosign` only.
- The SBOM step (Syft) is in the release workflow only, so no SBOM has been
  produced by the pipeline.
- The arm64 image has never been started. CI builds and tests amd64 only.
- Nobody can obtain a verified binary today. The only way to run scanent is
  to build it from source.

The image is to be public (owner decision, 2026-11-12, issue 19): once a
release exists, pulling it will need no login. The contract package is to be
published to GitHub Packages by the same workflow (issue 7). Neither has
happened: no tag has been pushed.

### Repository settings that are not on

Read from GitHub's API on 2026-11-12:

- **Private vulnerability reporting is not enabled.** [SECURITY.md](../../SECURITY.md)
  directs reports to it. Until it is switched on, that route does not work.
- **Secret scanning and push protection are not enabled.**
- **The `main` branch is not protected**, and no ruleset exists. So nothing
  on GitHub's side restricts who can push to `main` or push a tag.

`docs/release-checklist.md` requires all of these before the first release.
Residual risk 8 of the threat model (the release identity) rests on them.

### Other things that have never run

- The long-test workflow (`.github/workflows/long-tests.yml`: the fuzzing and
  scale tests with their large budgets) has never run on GitHub. This page
  makes no claim that the large budgets have been run anywhere.
- Under rootless Podman, CI runs the image's smoke test without its last
  step (the egress overlay), because that step needs Compose.
- CodeQL and Scorecard have each run and finished. Their findings, if any,
  have not been reviewed for this page, and no Scorecard score is claimed.

## What has been done

All of the following is in the repository and can be re-run.

### On every push and pull request (CI)

On 2026-11-12 every job below passed on `main` at commit `7836ef9`:

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
  (`190f3fb`, the same unreleased version 0.12.0) are read by the current
  code. No released version exists to compare with.
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
