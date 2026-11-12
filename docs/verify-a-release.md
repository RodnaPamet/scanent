# Verify a release

How to check that an image, a bundle or an SBOM of scanent is the one this
repository's release workflow produced, and what each check does and does not
prove.

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

**It proves** which repository, workflow, commit and run produced the image's
digest (a SLSA provenance statement, signed the same keyless way).

## The air-gapped bundle

A release carries four files for the bundle:

| File | What it is |
|---|---|
| `scanent-<version>-airgap.tar` | The bundle |
| `scanent-<version>-airgap.tar.sha256` | The archive's SHA-256, for `sha256sum -c` |
| `scanent-<version>-airgap.SHA256SUMS` | The list of checksums of every file inside the bundle |
| `scanent-<version>-airgap.SHA256SUMS.sigstore.json` | The signature over that list |

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
./verify.sh --require-signature
```

`verify.sh` checks every file against `SHA256SUMS`, that no file is present
that the list does not name, that `sbom/` holds one CycloneDX document per
image, and, with `cosign` on the path, the signature over `SHA256SUMS` inside
the bundle (`signatures/SHA256SUMS.sigstore.json`) for the identity above. The
version in the identity is the one the bundle's own `VERSION` file names, and
that file is in the signed list.

| Situation | What `verify.sh` does |
|---|---|
| Signed, `cosign` present, the signature verifies | Passes, and prints the identity |
| Signed, `cosign` present, the signature does not verify | Fails |
| Signed, no `cosign` on the path | Fails, and says the signature was not checked. `--no-signature` accepts the checksums alone, and says so |
| Not signed (a bundle you built yourself) | Passes on the checksums and says there is no signature. With `--require-signature` it fails |

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
  `SCANENT_TRUSTED_ROOT=/path/to/trusted_root.json ./verify.sh --require-signature`.

Do not take the root of trust from the bundle or from the same download as the
bundle: whoever could replace one could replace the other.

Verifying on a machine with no network is a step of the release checklist
(`docs/release-checklist.md`). Until a release has been through it, treat the
check on the connected machine, above, as the one that was exercised.

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
  `verify.sh` then checks the checksums only, and says so.
