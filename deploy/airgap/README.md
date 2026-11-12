# scanent, air-gapped bundle

Everything needed to run scanent at a site with no registry and no internet.

```bash
tar -xf scanent-<version>-airgap.tar
cd scanent-<version>-airgap
./load.sh
```

`load.sh` runs `verify.sh` first, loads the image for this machine's
architecture, and tags it `ghcr.io/rodnapamet/scanent:<version>` so the
Compose files and the chart find it locally. It needs `docker` (or set
`CONTAINER_RUNTIME=podman` or `nerdctl`) and no network.

A released bundle is signed. With `cosign` on the path the signature is
checked; without it `load.sh` stops and says so. See
"What the checks do and do not show" below.

## What is in it

| Path | What it is |
|---|---|
| `VERSION` | The scanent version |
| `LICENSE`, `NOTICE` | The licence travels with every copy |
| `images/scanent-<version>-linux-amd64.tar`, `…-arm64.tar` | One image archive per architecture |
| `images/IMAGES` | Which image reference each archive holds |
| `load.sh`, `verify.sh` | Load the image; check the bundle |
| `deploy/compose.yaml`, `deploy/compose.egress.yaml` | Run on a schedule with Compose |
| `deploy/helm/scanent-<version>.tgz` | The Helm chart |
| `examples/` | Example configurations |
| `docs/` | The quick start, the deployment guide, the command reference, the access each source needs, every request the scanner makes, operations, and how to verify a release |
| `sbom/` | A CycloneDX software bill of materials per image (`<arch>.cdx.json`), or a note that the bundle was built without one |
| `SHA256SUMS` | The checksum of every file above |
| `signatures/SHA256SUMS.sigstore.json` | In a released bundle: the release workflow's signature over `SHA256SUMS`. The one file the list does not name |

## What the checks do and do not show

`./verify.sh` shows the copy is complete and undamaged: every listed file
matches, no file is present that is not listed, and `sbom/` holds one SBOM per
image or the notice that there is none.

Where the bundle came from is shown by the signature. A released bundle
carries one over `SHA256SUMS`, made by the release workflow with no stored
key:

| You run | With | Result |
|---|---|---|
| `./verify.sh --require-signature` | `cosign` on the path | Passes only if the signature verifies for the release workflow at the tag of this bundle's version |
| `./verify.sh` | a signed bundle, no `cosign` | Fails: the signature is there and was not checked |
| `./verify.sh --no-signature` | a signed bundle | Checks the checksums and says the signature was not checked |
| `./verify.sh` | a bundle with no signature (one you built) | Checks the checksums and says there is no signature |

`load.sh` takes the same flag and passes it on.

Without the signature check, the checksums do not show where the bundle came
from: whoever can replace a file can replace the list. Then obtain it over a
channel you trust, and compare the archive's own SHA-256 with the one
published for the release: the GitHub release for the version carries
`scanent-<version>-airgap.tar` and `scanent-<version>-airgap.tar.sha256`
(`sha256sum -c scanent-<version>-airgap.tar.sha256`).

`docs/verify-a-release.md` in this bundle has the whole procedure, including
a machine that has never had network access.

## Other runtimes

- Podman: `CONTAINER_RUNTIME=podman ./load.sh`. Run with `--userns=keep-id` in
  place of `--user`.
- containerd, on each node of a cluster. The archive holds the image under its
  per-architecture name (the third column of `images/IMAGES`), and the chart
  asks for `ghcr.io/rodnapamet/scanent:<version>`, so import it and then give
  it that name, as `load.sh` does for the other runtimes:

  ```sh
  ref="$(awk -v a=<arch> '$1 == a { print $3 }' images/IMAGES)"
  ctr -n k8s.io images import images/scanent-<version>-linux-<arch>.tar
  ctr -n k8s.io images tag "$ref" ghcr.io/rodnapamet/scanent:<version>
  ```

  Then install the chart with `image.pullPolicy=Never`. Without the `tag` step
  the pod stays in `ErrImageNeverPull`.
- A registry inside your network: `docker load`, then tag and push to it, and
  set the chart's `image.repository`.

## Building one

```bash
deploy/airgap/build-bundle.sh <version> <amd64-image-ref> <arm64-image-ref> <out-dir>
```

Both images must already be in the local image store; the script pulls and
builds nothing. The release workflow runs it on every tag, with the SBOMs it
made from the two images (`SCANENT_SBOM_DIR`) and a command that signs the
list of checksums (`SCANENT_SIGN_CMD`). A bundle built without them holds no
SBOM and no signature, and `verify.sh` says so.
