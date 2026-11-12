# scanent, air-gapped bundle

Everything needed to run scanent at a site with no registry and no internet.

```bash
tar -xf scanent-<version>-airgap.tar
cd scanent-<version>-airgap
./load.sh
```

`load.sh` checks every file against `SHA256SUMS` first, loads the image for
this machine's architecture, and tags it `ghcr.io/rodnapamet/scanent:<version>`
so the Compose files and the chart find it locally. It needs `docker` (or set
`CONTAINER_RUNTIME=podman` or `nerdctl`) and no network.

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
| `docs/` | The quick start, the deployment guide, the command reference, and the access each source needs |
| `sbom/` | A software bill of materials per image, or a note that there is none |
| `SHA256SUMS` | The checksum of every file above |

## What the checksums do and do not show

`./verify.sh` shows the copy is complete and undamaged: every listed file
matches, and no file is present that is not listed.

It does not show where the bundle came from. Nothing in it is signed, and
whoever can replace a file can replace the list. Obtain it over a channel you
trust, and compare the archive's own SHA-256 with the one published for the
release.

## Other runtimes

- Podman: `CONTAINER_RUNTIME=podman ./load.sh`. Run with `--userns=keep-id` in
  place of `--user`.
- containerd: `ctr -n k8s.io images import images/scanent-<version>-linux-<arch>.tar`
  on each node, then install the chart with `image.pullPolicy=Never`.
- A registry inside your network: `docker load`, then tag and push to it, and
  set the chart's `image.repository`.

## Building one

```bash
deploy/airgap/build-bundle.sh <version> <amd64-image-ref> <arm64-image-ref> <out-dir>
```

Both images must already be in the local image store; the script pulls and
builds nothing. The release workflow runs it on every tag.
