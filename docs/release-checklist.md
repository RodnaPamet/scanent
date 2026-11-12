# Release checklist

What is done before a tag is pushed, at the tag, and after it. A release is
made by pushing a tag `v<MAJOR>.<MINOR>.<PATCH>`; `.github/workflows/release.yml`
does the rest. Nothing here is automated away: each line is something a person
checks.

## Settings that must be on

Once, and again whenever the repository's settings change. Each is under the
repository's **Settings**.

- [ ] **Private vulnerability reporting** is enabled (Code security). `SECURITY.md`
      sends reporters there; with it off, the link leads nowhere.
- [ ] **Secret scanning** and **push protection** are enabled (Code security).
- [ ] **Dependabot alerts** and **security updates** are enabled.
      `.github/dependabot.yml` already proposes version updates.
- [ ] **Branch protection on `main`**: pull requests required, the CI jobs
      required (`checks` on both Node versions, `image`, `chart`,
      `chart-install`, CodeQL), no force push, no deletion.
- [ ] **Tag protection** (a ruleset on `v*`): only the people who release may
      create a version tag, and a tag cannot be moved or deleted. The signing
      identity of a release is "the release workflow at this tag", so whoever
      can push a tag can make a signed release.
- [ ] **Actions**: workflow permissions default to read-only; "Allow GitHub
      Actions to create and approve pull requests" is off.
- [ ] **The package** `ghcr.io/rodnapamet/scanent` has the visibility you
      intend, and inherits access from this repository.
- [ ] Decide whether the OpenSSF Scorecard result is published. It is not:
      `scorecard.yml` has `publish_results: false`. Publishing also needs
      `id-token: write` on that job.

## Before the tag

- [ ] The version is the same in three places:
      `SCANNER_VERSION` in `packages/scanner/src/scanner-surface.ts`,
      `version` and `appVersion` in `deploy/helm/scanent/Chart.yaml`, and the
      examples in `docs/quick-start.md`. The release workflow refuses a tag
      that does not name `SCANNER_VERSION`.
- [ ] The generated pages are current: `npm run build`, then
      `npm run docs:access`, `npm run docs:network` and `npm run docs:examples`
      change nothing (`git status` is clean).
- [ ] If the declared surface changed, the manifest hash changed with it, and
      the release notes say what the scanner can now request that it could not
      before.
- [ ] If a results file, an inventory, a doctor report or the configuration
      changed shape, `docs/scanner.md` says so under "Changes that can stop a
      setup that scanned before".
- [ ] **A compatibility fixture for the version being released** is added under
      `packages/scanner/tests/fixtures/compat/<version>/`, made the way
      `packages/scanner/tests/fixtures/compat/README.md` says, from the commit
      to be tagged. No earlier directory is removed while that version is
      supported.
- [ ] CI is green on the commit to be tagged, every job.
- [ ] The long tests were run on that commit: the **Long tests** workflow
      (`long-tests.yml`), by hand. Record the run's URL in the release notes.
- [ ] The soak was run where a machine can stay up:
      `npm run build && npm run soak -- --hours 72 --every-seconds 60`. Record
      where its output is kept, the number of runs, and that none failed or
      was missed. If it was not run for this release, the release notes say so.
- [ ] `npm audit --omit=dev` and the two image scans are clean today, not only
      when CI last ran.
- [ ] A manual run of the **Release** workflow (`workflow_dispatch`) on the
      commit passes. It builds, tests and bundles, and pushes and signs
      nothing.

## The tag

- [ ] `git tag -s v<version> -m "scanent <version>"` on the commit that passed,
      then `git push origin v<version>`.
- [ ] The **Release** workflow passes: `build` on both architectures,
      `bundle`, `publish`, `release`.

A version is never released twice. If the workflow fails after the images were
pushed, fix forward with a new patch version; do not delete and re-push.

## After the tag

Verify what was published, as a client would, with the commands of
`docs/verify-a-release.md`:

- [ ] `cosign verify` of `ghcr.io/rodnapamet/scanent:<version>` passes for the
      identity of that tag, and fails for another version's identity.
- [ ] `cosign verify-attestation --type cyclonedx` passes for each
      architecture's digest, and the SBOM lists `zod`, `js-yaml` and
      `typescript`.
- [ ] `gh attestation verify oci://ghcr.io/rodnapamet/scanent:<version> --repo RodnaPamet/scanent`
      passes.
- [ ] The release carries six files: the bundle, its `.sha256`, the two SBOMs,
      the bundle's `SHA256SUMS` and its `.sigstore.json`.
- [ ] `sha256sum -c` of the bundle passes, and `cosign verify-blob` of the
      checksum list passes.
- [ ] **On a machine with no network**: unpack the bundle,
      `./verify.sh --require-signature`, `./load.sh --require-signature`, then
      `deploy/smoke.sh ghcr.io/rodnapamet/scanent:<version>` from a checkout.
      Change one byte of one file and confirm `verify.sh` fails. Record whether
      `cosign` needed a trusted root supplied (`SCANENT_TRUSTED_ROOT`), and
      correct `docs/verify-a-release.md` if what it says did not hold.
- [ ] The image runs by its digest: `docker run --rm ghcr.io/rodnapamet/scanent@sha256:<digest> help`.
- [ ] No tag `latest` exists on the package.

## What has never been run

Listed here so that the first release does them deliberately. Strike a line
when it has happened once, and say in which release.

- Keyless signing, the SBOM attestations and the provenance attestation: they
  run only on GitHub's runners, at a tag.
- `verify.sh` against a real Sigstore bundle, with and without network.
- The `chart-install` job (kind) and the `image-podman` job: written and
  reviewed, first run when pushed.
- The arm64 image: built and tested only by the release workflow's arm64
  runner.
- The 72-hour soak.
- A pilot against a real estate of each provider.
