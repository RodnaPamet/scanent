# Verify a release

How to check that an image, a bundle or an SBOM of scanent is the one this
repository's release workflow produced, and what each check does and does not
prove.

> **Status: no release has been published yet.** There is no tag, no signed
> image and no signed bundle. None of the `cosign` or `gh` commands on this
> page has been run against a real signature, and where the page says what a
> command prints, that is what the tool's documentation says it prints. They
> run for the first time at the first tag; the release checklist
> (`docs/release-checklist.md`) has the steps and records what has never been
> run.

Nothing here needs a key from us. Signing is keyless: the release workflow
asks GitHub for a short-lived token that says which workflow of which
repository is running for which tag, Sigstore's certificate authority issues a
ten-minute certificate for that identity, and the signature is recorded in
Sigstore's public transparency log. You verify by naming the identity you
expect. There is no long-lived signing key to steal or rotate.

You need [`cosign`](https://docs.sigstore.dev/cosign/system_config/installation/)
3 or later. `gh` (the GitHub CLI) is needed only for the provenance check.

- [The identity](#the-identity)
- [The image](#the-image)
- [The SBOM](#the-sbom)
- [The build's provenance](#the-builds-provenance)
- [The air-gapped bundle](#the-air-gapped-bundle)
- [What these checks do not prove](#what-these-checks-do-not-prove)

## The identity

Every signature of a release is made by one workflow, at that release's tag.
For version `<version>` (for example `0.13.0`) the two values to give `cosign`
are:

```
--certificate-identity "https://github.com/RodnaPamet/scanent/.github/workflows/release.yml@refs/tags/v<version>"
--certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

Give the identity in full, with the version you expect. A pattern that accepts
any tag, or any workflow of the repository, accepts more than you mean to.

In the commands below:

```bash
VERSION=<version>
IDENTITY="https://github.com/RodnaPamet/scanent/.github/workflows/release.yml@refs/tags/v$VERSION"
ISSUER="https://token.actions.githubusercontent.com"
```

## The image

```bash
cosign verify "ghcr.io/rodnapamet/scanent:$VERSION" \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER"
```

A pass prints the signature's claims and exits 0. The line
`docker-manifest-digest` in them is the digest that was signed.

**Then run the image by that digest, not by the tag.** A signature is for a
digest. A tag can be moved to another image later; a digest cannot.

```bash
docker pull "ghcr.io/rodnapamet/scanent:$VERSION"
docker image inspect --format '{{index .RepoDigests 0}}' "ghcr.io/rodnapamet/scanent:$VERSION"
# ghcr.io/rodnapamet/scanent@sha256:…   use this in Compose, or as the chart's image.digest
```

The release signs three digests: the manifest that names both architectures
(what the tag points to), and each architecture's own image. Verifying the tag
checks the first. To check the image for one architecture, give its digest:

```bash
cosign verify "ghcr.io/rodnapamet/scanent@sha256:<the amd64 or arm64 digest>" \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
```

**It proves** that these exact bytes were pushed by this repository's release
workflow, run for the tag `v<version>`, and that the signing was logged
publicly at that time.

## The SBOM

Each architecture's image carries its software bill of materials as a signed
attestation: a CycloneDX document listing the operating-system packages and
the npm packages in the image.

```bash
cosign verify-attestation --type cyclonedx \
  "ghcr.io/rodnapamet/scanent@sha256:<the amd64 or arm64 digest>" \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" \
  | jq -r '.payload' | base64 -d | jq '.predicate' > scanent-sbom.cdx.json
```

The same two documents are attached to the GitHub release as
`scanent-<version>-linux-amd64.cdx.json` and `…-arm64.cdx.json`, and are in
the air-gapped bundle under `sbom/`.

**It proves** that this SBOM was made by the release workflow for that image.
It was made by reading the built image, so it lists what is in it, not what a
manifest says should be.

## The build's provenance

```bash
gh attestation verify "oci://ghcr.io/rodnapamet/scanent:$VERSION" --repo RodnaPamet/scanent
```

The release attests provenance for four things: the manifest the tag points
to (the command above), each architecture's image, and the air-gapped bundle's
archive. For one architecture's image, give its digest; for the bundle, the
file:

```bash
gh attestation verify "oci://ghcr.io/rodnapamet/scanent@sha256:<the amd64 or arm64 digest>" --repo RodnaPamet/scanent
gh attestation verify "scanent-$VERSION-airgap.tar" --repo RodnaPamet/scanent
```

Those commands fetch the attestation from GitHub. The same four attestations
are attached to the GitHub release as files, for a machine that cannot:
`scanent-<version>-image.provenance.jsonl`,
`scanent-<version>-linux-amd64.provenance.jsonl`, `…-linux-arm64.provenance.jsonl`
and `scanent-<version>-airgap.provenance.jsonl`. `gh attestation verify` takes
one with `--bundle <file>`; it still needs Sigstore's root of trust, as
`cosign` does (see "Without network at the site" below). The provenance files
are not inside the bundle: the bundle's own attestation cannot be.

**It proves** which repository, workflow, commit and run produced that digest
or that file (a SLSA provenance statement, signed the same keyless way).

## The air-gapped bundle

A release carries five files for the bundle:

| File | What it is |
|---|---|
| `scanent-<version>-airgap.tar` | The bundle |
| `scanent-<version>-airgap.tar.sha256` | The archive's SHA-256, for `sha256sum -c` |
| `scanent-<version>-airgap.SHA256SUMS` | The list of checksums of every file inside the bundle |
| `scanent-<version>-airgap.SHA256SUMS.sigstore.json` | The signature over that list |
| `scanent-<version>-airgap.provenance.jsonl` | The archive's build provenance (above) |

On a machine with network access, before the bundle is carried anywhere:

```bash
sha256sum -c "scanent-$VERSION-airgap.tar.sha256"

cosign verify-blob "scanent-$VERSION-airgap.SHA256SUMS" \
  --bundle "scanent-$VERSION-airgap.SHA256SUMS.sigstore.json" \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
```

At the site, after unpacking:

```bash
tar -xf "scanent-$VERSION-airgap.tar"
cd "scanent-$VERSION-airgap"
./verify.sh
```

With no flag, `verify.sh` requires the signature: a bundle that carries none
fails, and so does a signed one when `cosign` is not on the path. Taking the
signature out and rewriting the list is the first thing someone replacing a
bundle would do, so a missing signature is never accepted unless you say so.
(`--require-signature` is still accepted and means the same.)

`verify.sh` checks every file against `SHA256SUMS`, that no file is present
that the list does not name, that `sbom/` holds one CycloneDX document per
image, and, with `cosign` on the path, the signature over `SHA256SUMS` inside
the bundle (`signatures/SHA256SUMS.sigstore.json`) for the identity above. The
version in the identity is the one the bundle's own `VERSION` file names, and
that file is in the signed list.

| Situation | What `verify.sh` does |
|---|---|
| Signed, `cosign` present, the signature verifies | Passes, and prints the identity |
| Signed, `cosign` present, the signature does not verify | Fails, and shows what `cosign` said |
| Signed, no `cosign` on the path | Fails, and says the signature was not checked. `--no-signature` accepts the checksums alone, and says so |
| Not signed | Fails: nothing shows the bundle is the one the release made. `--unsigned` accepts a bundle you built yourself, on its checksums, and says there is no signature |
| `--unsigned`, and the bundle is signed after all | The signature is checked as with no flag |

`load.sh` runs `verify.sh` first, with the same flag, and loads nothing if it
fails.

**Without network at the site.** The signature file is a Sigstore bundle: it
carries the certificate and the transparency-log proof, so verifying it needs
no connection to Sigstore's log. `cosign` does need Sigstore's root of trust,
which it normally fetches and caches under the user's home directory
(`~/.sigstore`). On a machine that has never had network access, either:

- run `cosign initialize` on a connected machine you trust, and carry the
  cache directory it wrote to the same user's home on the site machine; or
- give `verify.sh` a trusted root file you obtained yourself:
  `SCANENT_TRUSTED_ROOT=/path/to/trusted_root.json ./verify.sh`.

Do not take the root of trust from the bundle or from the same download as the
bundle: whoever could replace one could replace the other.

Neither way has been exercised. `verify.sh` has been run against a stand-in
`cosign` only, never against a real Sigstore bundle, on a connected machine or
on one with no network: no release exists to verify. Both are steps of the
release checklist (`docs/release-checklist.md`) for the first tag.

**It proves** that the list of checksums was signed by the release workflow
for that tag, and so that every file in the bundle is the one that release
contained. The images in the bundle are the ones the release pushed: the same
archives, saved before the push.

## What these checks do not prove

- **That the code is free of defects or does what you need.** A signature says
  where the bytes came from. The tests, the scans in CI and your own review say
  what they do.
- **That the repository or its workflow was not compromised.** A release made
  by an attacker who controls the repository would carry a valid signature for
  the same identity. The provenance names the commit: compare it with the
  commit you reviewed.
- **That a later image is the same one.** Only the digest you verified is
  covered. Pin it.
- **That two builds of the same commit give the same image digest.** They do
  not: layer timestamps and installed-file metadata differ. The compiled
  JavaScript inside is reproducible, and CI checks that on every change
  (`node scripts/check-reproducible-build.js`).
- **Anything about a bundle or image you built yourself.** It is unsigned.
  `./verify.sh --unsigned` then checks the checksums only, and says so.
