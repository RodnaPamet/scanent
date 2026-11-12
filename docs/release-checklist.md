# Release checklist

What is done before a tag is pushed, at the tag, and after it. A release is
made by pushing a tag `v<MAJOR>.<MINOR>.<PATCH>`; `.github/workflows/release.yml`
does the rest. Nothing here is automated away: each line is something a person
checks.

**No release has been made yet.** No tag has been pushed, so no image, bundle
or package is published, and neither package named below exists on GitHub.

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
- [ ] **The organisation lets its packages be public**: the organisation's
      Settings, **Packages**, "Package Creation", with **Public** enabled.
- [ ] **The image's package** `ghcr.io/rodnapamet/scanent` is **public**, and
      is linked to this repository. It does not exist before the first
      release: GitHub creates a package when it is first pushed, and creates
      it private. "After the tag" has the step that makes it public, once. At
      every later release, check that it still is.
- [ ] **The contract package** `@rodnapamet/scanent-contract` (GitHub
      Packages, npm) is linked to this repository, and each repository that
      installs it is listed in its settings under "Manage Actions access"
      with the Read role. It too is created private, at the first publish.
      Its visibility is yours to choose: an install needs a token whether it
      is public or private, and a package made public cannot be made private
      again.
- [ ] Decide whether the OpenSSF Scorecard result is published. It is not:
      `scorecard.yml` has `publish_results: false`. Publishing also needs
      `id-token: write` on that job.

## Before the tag

- [ ] The version is the same in four places:
      `SCANNER_VERSION` in `packages/scanner/src/scanner-surface.ts`,
      `version` and `appVersion` in `deploy/helm/scanent/Chart.yaml`, the
      examples in `docs/quick-start.md`, and the contract package:
      `version` in `packages/contract/package.json`, with the same version
      where `packages/report/package.json` and `packages/scanner/package.json`
      depend on it, and `package-lock.json` refreshed
      (`npm install --package-lock-only`). The release workflow refuses a tag
      that does not name `SCANNER_VERSION`, and a contract package of any
      other version.
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
      commit passes. It builds, tests, bundles and packs the contract
      package, and pushes, publishes and signs nothing.

## The tag

- [ ] `git tag -s v<version> -m "scanent <version>"` on the commit that passed,
      then `git push origin v<version>`.
- [ ] The **Release** workflow passes: `gates` (the tagged commit is on main
      and passes what main is held to), `build` on both architectures,
      `bundle`, `sign-bundle`, `publish`, `contract-package`,
      `publish-contract`, `release`.

A version is never released twice. If the workflow fails after the images were
pushed or the contract package was published, fix forward with a new patch
version; do not delete and re-push.

## After the tag

First, at the first release only:

- [ ] **Make the image public.** GitHub creates a package private, and the
      image is meant to be pulled with no login. On GitHub: the
      organisation's **Packages** tab, the package `scanent`, **Package
      settings**, then under "Danger Zone" **Change visibility**, and
      **Public**. It cannot be made private again. The `publish` job's last
      step says which it found: before this step it warns that the image did
      not answer without a login.
- [ ] Under the contract package's settings, "Manage Actions access", add
      each repository that installs it, with the Read role
      (`docs/EXTRACTION.md` says which and why).

Then verify what was published, as a client would, with the commands of
`docs/verify-a-release.md`:

- [ ] **With no login** (`docker logout ghcr.io` first):
      `docker pull ghcr.io/rodnapamet/scanent:<version>` succeeds.
- [ ] `cosign verify` of `ghcr.io/rodnapamet/scanent:<version>` passes for the
      identity of that tag, and fails for another version's identity.
- [ ] `cosign verify-attestation --type cyclonedx` passes for each
      architecture's digest, and the SBOM lists `zod`, `js-yaml` and
      `typescript`.
- [ ] `gh attestation verify oci://ghcr.io/rodnapamet/scanent:<version> --repo RodnaPamet/scanent`
      passes, and so does the same for each architecture's digest and
      `gh attestation verify scanent-<version>-airgap.tar --repo RodnaPamet/scanent`.
- [ ] The release carries ten files: the bundle, its `.sha256`, the two SBOMs,
      the bundle's `SHA256SUMS` and its `.sigstore.json`, and four
      `.provenance.jsonl` files (the manifest, each image, the bundle). Each
      provenance file holds one attestation, for its own subject; if a file
      holds more than one, correct `docs/verify-a-release.md`.
- [ ] `gh attestation verify --bundle <file>` passes for each of the four
      provenance files.
- [ ] `sha256sum -c` of the bundle passes, and `cosign verify-blob` of the
      checksum list passes.
- [ ] **On a machine with no network**: unpack the bundle, `./verify.sh`,
      `./load.sh` (with no flag, both require the signature), then
      `deploy/smoke.sh ghcr.io/rodnapamet/scanent:<version>` from a checkout.
      Change one byte of one file and confirm `verify.sh` fails. Remove
      `signatures/` and confirm `verify.sh` and `load.sh` fail. Record whether
      `cosign` needed a trusted root supplied (`SCANENT_TRUSTED_ROOT`), and
      correct `docs/verify-a-release.md` if what it says did not hold.
- [ ] The image runs by its digest: `docker run --rm ghcr.io/rodnapamet/scanent@sha256:<digest> help`.
- [ ] No tag `latest` exists on the package.
- [ ] The contract package is published. With a token that can read it
      (`docs/contract.md`):
      `npm view @rodnapamet/scanent-contract@<version> version` prints the
      version, and `npm pack @rodnapamet/scanent-contract@<version>` followed
      by `gh attestation verify rodnapamet-scanent-contract-<version>.tgz --repo RodnaPamet/scanent`
      passes. If the tarball the registry serves is not the one that was
      attested, correct `docs/verify-a-release.md`.
- [ ] An empty project with the two `.npmrc` lines of `docs/contract.md`
      installs the package and loads
      `@rodnapamet/scanent-contract/harness-contract`.

## What has never been run

Listed here so that the first release does them deliberately. Strike a line
when it has happened once, and say in which release.

- Keyless signing, the SBOM attestations and the provenance attestations
  (the manifest, each image, the bundle), and keeping each attestation as a
  file for the release: they run only on GitHub's runners, at a tag.
- `verify.sh` against a real Sigstore bundle and a real `cosign`, with and
  without network. It has been run against a stand-in `cosign` only.
- `sign-bundle.sh` with a real `cosign`: run against a stand-in only.
- The release workflow's `gates` job, and its check that the tagged commit is
  on main. The check's script has been run against a local repository.
- The release workflow as a workflow, by tag or by hand, and with it the Syft
  SBOM step. Of the image scans, Trivy and Grype have run in CI; no SBOM has
  been made by Syft.
- The contract package's two jobs, `contract-package` and
  `publish-contract`: `npm pack` and the check of the tarball on a runner, the
  provenance attestation of the tarball, and `npm publish` to GitHub
  Packages. The pack and the check have been run on a workstation only.
- An install of the contract package from GitHub Packages, with a person's
  token or a workflow's.
- A pull of the image with no login, and the `publish` job's step that tries
  one.
- The long-test workflow (`long-tests.yml`).
- The arm64 image: built and bundled on a workstation, never started. It is
  built and tested only by the release workflow's arm64 runner.
- The last step of the smoke test under rootless Podman: the `image-podman`
  job leaves the egress overlay out.

Run for the first time on 2026-11-12, on `main`: `ci.yml` in its current form
(the `checks` job on Node 22 and Node 24, with the `npm audit` and licence
gates; `image` with Trivy and Grype; `image-podman`; `chart`;
`chart-install` on kind), `codeql.yml` and `scorecard.yml`.

- The 72-hour soak.
- A pilot against a real estate of each provider.
