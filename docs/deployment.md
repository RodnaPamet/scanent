# Deployment

Every way of running scanent at a site, and what each one is given. For a
first run, start with [quick-start.md](quick-start.md). The commands are in
[scanner.md](scanner.md); the access each source needs is in [access.md](access.md).

## What holds everywhere

- **Read-only.** scanent reads the estate and writes only its own results,
  under the output directory. `doctor` makes only requests a scan makes, and
  never writes to a system to find out whether it could.
- **No credential in a configuration, a values file or an image.** The
  configuration holds the NAMES of variables. A value comes from the
  environment, or from a file named by `NAME_FILE`.
- **The container.** A non-root user, a read-only root filesystem, every
  capability dropped, no privilege gain. The entrypoint is `node` and the
  command line's file, in exec form: no shell starts it.
- **A version, never `latest`.** The Compose file requires `SCANENT_VERSION`
  and the chart refuses the tag `latest`.

## One scan, with a container runtime

```bash
docker run --rm --user "$(id -u):$(id -g)" \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --env-file scanent/scanent.env \
  -v "$PWD/scanent:/etc/scanent:ro" \
  -v "$PWD/scanent-out:/out" \
  ghcr.io/rodnapamet/scanent:<version> scan --config /etc/scanent/config.json
```

- `./scanent` is the directory `scanent init` wrote. It is mounted read-only.
- `./scanent-out` is the one writable mount. Create it yourself, mode 0700,
  owned by the user the container runs as: the runs are evidence about your
  estate. Each run is a directory (0750) of six files (0640).
- `--user` makes the scanner you, so `init`'s files (0600) can be read and the
  runs are yours to open. Without it the image runs as uid 1000.
- A `code` source needs each root mounted read-only at the path the
  configuration names.

### Rootless Docker and Podman

- Rootless Docker: the same line. Inside the user namespace `--user` maps to a
  sub-uid, so files written to a bind mount are owned by a sub-uid on the host.
  Leave `--user` out to run as the namespace's uid 1000, or use Podman's
  `keep-id`.
- Podman: `--userns=keep-id` in place of `--user`. On SELinux hosts add `:Z`
  (or `:ro,Z`) to each volume.

## On a schedule, with Compose

[deploy/compose.yaml](../deploy/compose.yaml) runs the image's default
command, `schedule`: one scan at start, then one every `schedule.everyHours`.

| Variable | Meaning |
|---|---|
| `SCANENT_VERSION` | Required. The image tag |
| `SCANENT_DIR` | The directory `init` wrote. Default `./scanent` |
| `SCANENT_OUT` | Where runs are written. Default `./scanent-out` |
| `SCANENT_UID`, `SCANENT_GID` | The user the scanner runs as. Default 1000:1000 |

The service has no published port, no added capability, no host network and
no Docker socket. It restarts unless stopped. The signing key is a Compose
file secret, which is a bind mount of the file: it keeps its owner and mode,
so it must be readable by `SCANENT_UID`.

`schedule` reads credentials, and files named by `_FILE`, once at start. After
rotating one, restart the service.

### The egress overlay

[deploy/compose.egress.yaml](../deploy/compose.egress.yaml) puts the scanner
on a network with no route out and adds one more container: the CONNECT-only
proxy that ships in the same image. It forwards a tunnel to a host in
`EGRESS_ALLOW`, on port 443, and refuses any other host, any other port and
any plain HTTP request. An empty list refuses everything.

```bash
export EGRESS_ALLOW="$(docker run --rm -v "$PWD/scanent:/etc/scanent:ro" --user "$(id -u):$(id -g)" \
  ghcr.io/rodnapamet/scanent:<version> hosts --config /etc/scanent/config.json --format egress-allow)"
SCANENT_VERSION=<version> docker compose -f compose.yaml -f compose.egress.yaml up -d
```

With an `egress` block in the configuration, each scan also proves the
restriction before it reports it ([scanner.md](scanner.md), "The egress proxy").

## Kubernetes, with Helm

[deploy/helm/scanent](../deploy/helm/scanent/) installs a CronJob. Its
[README](../deploy/helm/scanent/README.md) documents the values.

- The CronJob runs `scan`, one at a time, and a failed Job is not retried.
  With `strict: true` a Job fails when a source was incomplete or no agent was
  found.
- The pod: uid and gid 1000, `runAsNonRoot`, the `RuntimeDefault` seccomp
  profile, a read-only root filesystem, no privilege escalation, every
  capability dropped, no service account token.
- Credentials: an existing Secret, mounted as files and named by `_FILE`. The
  chart creates no Secret and its values schema refuses a key it does not
  know, so a values file cannot carry a credential.
- Output: a PersistentVolumeClaim, kept when the release is removed.

### The NetworkPolicy, and its limit

The default policy allows nothing in, and out only DNS and TCP 443 to public
addresses.

It does not limit the scanner to exactly the hosts it reads. A NetworkPolicy
matches addresses and ports, not names, and those hosts are names whose
addresses belong to large providers and change. For exact hosts the chart
offers a `CiliumNetworkPolicy` (`networkPolicy.flavor: cilium`) or the bundled
egress proxy (`egressProxy.enabled: true`), both given the list
`scanent hosts` prints.

A policy does nothing on a cluster whose network plugin does not enforce it.
The chart's README has a one-command check.

## A site with no internet

`scanent-<version>-airgap.tar` holds one image archive per architecture
(amd64 and arm64), `load.sh`, `verify.sh`, the Compose files, the chart, the
examples and these documents, with a SHA-256 for every file.

```bash
tar -xf scanent-<version>-airgap.tar && cd scanent-<version>-airgap
./load.sh          # verifies, loads this machine's image, prints the next command
```

- `verify.sh` fails when a file is changed, missing or added.
- **Nothing in the bundle is signed.** The checksums detect a damaged copy,
  not a replaced one: whoever can replace a file can replace the list. Obtain
  the bundle over a channel you trust, and compare the archive's SHA-256 with
  the one the release states.
- The bundle holds no SBOM unless the release was built with one; `sbom/` says
  which.
- For a cluster, push the loaded image to a registry inside your network and
  set the chart's `image.repository`, or import the archive on each node.

[deploy/airgap/README.md](../deploy/airgap/README.md) lists the contents.

## Secrets from files

For each credential NAME the configuration gives, `NAME_FILE` may name a file
holding the value instead. Setting both is refused: one of the two would be
silently ignored.

| Platform | How the file gets there |
|---|---|
| `docker run` | A file under the read-only configuration mount, or `--mount type=bind,…,readonly` |
| Compose | A `secrets:` entry, mounted at `/run/secrets/<name>` |
| Kubernetes | A Secret's key, mounted by the chart at `/run/secrets/scanent/<key>` |

The file must be a regular file of at most 64 KiB, and must not be writable
by others. One trailing line break is removed.

## Proxy and certificate authority

| Variable | Meaning |
|---|---|
| `HTTPS_PROXY` | The forward proxy every request goes through |
| `NO_PROXY` | Hosts reached directly. A bare name exempts that name only; `.example.com` exempts its subdomains |
| `NODE_EXTRA_CA_CERTS` | A PEM file of certificate authorities, added to the public ones |

The image sets `NODE_USE_ENV_PROXY=1`, which is what makes Node honour the
first two. From source, set it yourself; `doctor` fails the `proxy` check when
a proxy is set without it.

There is no switch that turns certificate verification off. `scan` and
`schedule` refuse to start with `NODE_TLS_REJECT_UNAUTHORIZED=0`.

A host on your own network that the scanner names (a self-hosted LangSmith, an
MCP server) belongs in `NO_PROXY`: the scanner checks the address it resolves
before each request, and through a proxy that check is about this machine's
resolver, not the proxy's. `doctor` warns about each such host.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Done. `scan`: every output delivered. `doctor`: ready |
| 1 | Failed: an output was not delivered, or an error with no class of its own |
| 2 | Usage: wrong arguments. Nothing was read or written |
| 3 | Incomplete. `scan --strict`: delivered, but a source was incomplete or no agent was found. `doctor`: warnings or blocked checks |
| 4 | The configuration, an answers file, the inventory or a secret file was refused |
| 5 | `doctor`: a credential is missing or refused |
| 6 | `doctor`: a host could not be resolved or reached |

A scheduler can act on them: retry on 6, page on 5, fail a pipeline on 3 with
`--strict`.

## Releases

A tag `v<version>` builds the image on an amd64 and an arm64 runner, runs the
smoke test and the vulnerability gate on each, and pushes
`ghcr.io/rodnapamet/scanent:<version>` as one manifest over both. The same
workflow builds the air-gapped bundle and checks it by unpacking, verifying
and loading it. No image has been published yet.

Images are not signed, and carry no SBOM or provenance attestation yet.
