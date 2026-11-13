# Run it at your site in 15 minutes

Six steps, each one command, from nothing to a page you can open. Once you
have the image you need a container runtime (Docker or Podman) and nothing
else: no Node and no `openssl`.

Nothing here writes to your systems. scanent reads, and what it may request is
declared in one file whose hash is in every report. No step asks you to type a
credential into scanent: credentials go in a file you keep, or in your secret
store.

The commands use Docker. [Podman](#podman), [Compose](#on-a-schedule-with-compose),
[Kubernetes](#on-kubernetes-with-helm) and [a site with no internet](#a-site-with-no-internet)
follow.

## 0. Get the image

```bash
export IMAGE=ghcr.io/rodnapamet/scanent:0.13.2
docker pull "$IMAGE"
```

The image is public: the pull needs no account and no login.
[Verify a release](verify-a-release.md) checks its signature before you run
it. A site with no internet loads the image from the air-gapped bundle
(`./load.sh`, see [below](#a-site-with-no-internet)).

To build it from a checkout instead, `docker build -f deploy/Dockerfile -t
"$IMAGE" .` in a clone of this repository; behind a proxy that inspects TLS
add `--secret id=ca,src=/path/to/ca.pem` (the
[README](../README.md#quick-start-container) says what it is used for).

Every command below runs the container the same way. Put it in a shell
function once:

```bash
scanent() {
  docker run --rm --user "$(id -u):$(id -g)" \
    --read-only --cap-drop ALL --security-opt no-new-privileges "$@"
}
```

That is: as you rather than root, with a read-only root filesystem, every
capability dropped and no way to gain privileges.

## 1. Set up

```bash
mkdir -p scanent scanent-out && chmod 0700 scanent scanent-out
scanent -it --network none -v "$PWD/scanent:/etc/scanent" "$IMAGE" init --dir /etc/scanent
```

`init` asks for the estate's name and which sources you have, and for each
source its identifiers: a directory id, an organisation URL, repositories. It
never asks for a secret, and it refuses an answer that looks like one. Accept
`/out` as the output directory. It makes no network request, which is why this
one command runs with `--network none`.

It writes three files into `./scanent`, each readable only by you:

| File | What it holds |
|---|---|
| `config.json` | The configuration: what to read, and the NAMES of the credentials |
| `scanent.env` | Those names, each with nothing after the `=` |
| `signing-key.pem` | The key your reports are signed with |

Expected last lines:

```
scanent.env names the signing key by its path, /etc/scanent/signing-key.pem.
Run doctor and scan where that path is the same: in a container, mount this directory at the path given to --dir.
```

Without a terminal, give the answers as a file instead:
`init --dir /etc/scanent --answers /etc/scanent/answers.json`.
[deploy/examples/](../deploy/examples/) holds four.

## 2. Create the access, and fill in `scanent.env`

`init` printed, for each source you chose, the read-only access to create:
the role or scope, where to create it, what it lets the scanner read and what
must not be granted. [access.md](access.md) has the same tables.

Create each one, then put its value after the `=` in `scanent/scanent.env`. A
value is taken as written, without quotes. A credential with line breaks (a
Google key file) goes in a file under `./scanent`, named by the `_FILE` line:

```
GCP_SCANNER_KEY_FILE=/etc/scanent/gcp-key.json
```

An estate of agent code only has nothing to fill in.

## 3. Check

```bash
scanent --env-file scanent/scanent.env \
  -v "$PWD/scanent:/etc/scanent:ro" -v "$PWD/scanent-out:/out" \
  "$IMAGE" doctor --config /etc/scanent/config.json
```

`doctor` checks the configuration, the signing key, each credential, each
host, and that each source can be read, with the smallest read each API
allows. It writes and posts nothing. Every line says what was found, and a
failed line says what to fix.

Expected last line, when the estate is ready:

```
8 passed, 0 warnings, 0 failed, 10 not checked (1 not observable, 9 not applicable). Ready. 10 checks were not checked; each says why above.
```

The numbers are your own. "Not checked" is never counted as passed: a check
`doctor` cannot make from a read says so, and says what to confirm by hand.
The exit code is 0 when ready, 3 for warnings, 4 for the configuration, 5 for
a credential and 6 for the network.

A `code` source reads directories. Mount each one read-only at the path you
gave `init`, here and in the next step: `-v /srv/agents:/estate:ro`.

## 4. Scan

```bash
scanent --env-file scanent/scanent.env \
  -v "$PWD/scanent:/etc/scanent:ro" -v "$PWD/scanent-out:/out" \
  "$IMAGE" scan --config /etc/scanent/config.json
```

Expected last line:

```
{"ts":"…","level":"info","msg":"results written","scan":"<estate>-<time>-<id>","dir":"runs/<estate>-<time>-<id>","files":6,"removedRuns":0}
```

## 5. Open the results

```bash
cat scanent-out/latest.json
```

names the newest run. Open `scanent-out/runs/<scan id>/summary.html` in a
browser: it is one file and loads nothing from the network. Beside it are
`report.pdf`, the same results as a document, `agents.csv` and `findings.csv`
for a spreadsheet, `results.json`, the signed report and a manifest of
checksums. The files are yours (mode 0640, in a
directory 0750), because the scanner ran as you.

A source that could not be read in full is shown as incomplete with its
reason. It is never left out and never shown as complete.

## 6. On a schedule

Copy [deploy/compose.yaml](../deploy/compose.yaml) beside the `scanent`
directory, then:

```bash
export SCANENT_VERSION=0.13.2 SCANENT_UID="$(id -u)" SCANENT_GID="$(id -g)"
docker compose up -d
docker compose logs --tail 20 scanent
```

The three variables are exported because every `docker compose` command reads
the file again and needs them; a `.env` file beside `compose.yaml` holding the
same three lines does the same.

A `code` source reads directories, and the Compose file mounts none: add each
root under the service's `volumes:` first (uncomment the example line,
`- /srv/agents:/estate:ro`), at the path you gave `init`. Without it the source
is read as `INCOMPLETE` and the run holds no agent.

It scans now and then every `schedule.everyHours` of the configuration, and
writes each run under `./scanent-out`. In the log, look for one `source read`
line per source with `"status":"COMPLETE"` (a `source incomplete` line names
its reason), and then the same `results written` line as step 4. A
`results written` line alone does not mean the estate was read.

That is the whole first run. The rest of this page is the same six steps on
other platforms.

## Podman

Add `--userns=keep-id` beside `--user "$(id -u):$(id -g)"`, and replace
`docker` with `podman`:

```bash
scanent() {
  podman run --rm --userns=keep-id --user "$(id -u):$(id -g)" \
    --read-only --cap-drop ALL --security-opt no-new-privileges "$@"
}
```

`--userns=keep-id` gives your user the same number inside the container, and
`--user` runs the scanner as it, so the files in `./scanent` are readable and
the runs are yours. Both are needed: with `--userns=keep-id` alone the scanner
runs as the image's own user (number 1000), which is you only if your user
number is 1000. On a host with SELinux add
`:Z` to each volume (`-v "$PWD/scanent:/etc/scanent:ro,Z"`). The Compose file
works with `podman compose`.

## On a schedule with Compose

Step 6 above. What the Compose file gives the service, and nothing else: your
user, a read-only root filesystem, no capability, no published port, no host
network, no Docker socket. The signing key reaches it as a mounted file.

To make the scanner's only way out a proxy that forwards to an exact list of
hosts, add the overlay [deploy/compose.egress.yaml](../deploy/compose.egress.yaml):

```bash
export SCANENT_VERSION=0.13.2 SCANENT_UID="$(id -u)" SCANENT_GID="$(id -g)"
export EGRESS_ALLOW="$(scanent -v "$PWD/scanent:/etc/scanent:ro" "$IMAGE" \
  hosts --config /etc/scanent/config.json --format egress-allow)"
docker compose -f compose.yaml -f compose.egress.yaml up -d
```

A host you name yourself (an MCP server, a self-hosted LangSmith) is in that
list too. On the overlay's network the proxy resolves it and checks its
address; if it is on your own network, also
`export EGRESS_PRIVATE_CIDR_ALLOWLIST=<its range>`.

`hosts` is offline: it prints the hosts the configuration reaches, each on
port 443. Give the same list to whoever opens your firewall.

## On Kubernetes with Helm

```bash
# 1. The configuration and the key, as in steps 1 and 2 (any machine with the image).
# 2. The credentials, as files, in a Secret you create. The chart creates none.
kubectl create namespace scanent
kubectl create secret generic scanent-credentials --namespace scanent \
  --from-file=signing-key.pem=scanent/signing-key.pem
#   …and one --from-file per credential the configuration names.

# 3. A values file: the configuration (config.json, as YAML) and the Secret's keys.
cat > values.yaml <<'YAML'
config:
  # the contents of scanent/config.json
secrets:
  existingSecret: scanent-credentials
  files:
    - { env: SCANNER_SIGNING_KEY, key: signing-key.pem }
YAML

# 4. Install, then run one scan now.
helm install scanent deploy/helm/scanent --namespace scanent -f values.yaml
kubectl create job --namespace scanent --from=cronjob/scanent scanent-manual
kubectl logs --namespace scanent job/scanent-manual
```

Expected last line of the log: the `results written` line of step 4. The runs
are on the claim `scanent-out`.

The pod runs as a non-root user with a read-only root filesystem, no
capability and no service account token. Each credential reaches it as a file.

The chart installs a NetworkPolicy: nothing may connect in, and out only DNS
and TCP 443 to public addresses. It cannot limit the scanner to exactly its
hosts, because a NetworkPolicy matches addresses and not names; for that, the
chart has a Cilium policy and a bundled egress proxy, both fed by
`scanent hosts`. The chart's [README](../deploy/helm/scanent/README.md) says
what each gives and how to check that your cluster enforces it.

To run `doctor` in the cluster, create a Job from the same pod template with
`doctor` in place of `scan`, or run it from a workstation that has the same
network path.

## A site with no internet

On a machine with internet, take `scanent-<version>-airgap.tar` from the
release and carry it across. Then:

```bash
tar -xf scanent-0.13.2-airgap.tar
cd scanent-0.13.2-airgap
./load.sh
```

Expected last lines: `loaded: ghcr.io/rodnapamet/scanent:0.13.2  (linux/amd64)`
and the `init` command of step 1.

`load.sh` first checks every file against `SHA256SUMS`, then loads the image
for this machine's architecture (amd64 or arm64) with no registry. The bundle
also carries the Compose files, the chart, the examples and these documents,
so steps 1 to 6 run as written, with `IMAGE` set to the reference it printed.
A code-only estate then needs no network at all; other sources need a route to
their own hosts and nothing else.

The checksums show the copy is complete and undamaged. Where it came from is
shown by the signature a released bundle carries, and `load.sh` requires it:
with [`cosign`](verify-a-release.md) on the path it is verified, and a bundle
whose signature is missing or does not verify loads nothing. Without `cosign`,
`load.sh` stops and says the signature was not checked;
`./load.sh --no-signature` accepts the checksums alone. A bundle you built
yourself carries no signature: `./load.sh --unsigned`.

## Behind a proxy, or a proxy that inspects TLS

Add to each `docker run` (or to the Compose file's `environment`, or the
chart's `proxy` and `extraCa` values):

```bash
-e HTTPS_PROXY=http://proxy.internal.example:3128 \
-e NO_PROXY=mcp.internal.example \
-e NODE_EXTRA_CA_CERTS=/etc/scanent/ca.pem
```

The certificate authority file is added to the public ones. Nothing turns
certificate verification off, and scanent refuses to run with
`NODE_TLS_REJECT_UNAUTHORIZED=0`. `doctor` reports the proxy in effect, by host
and port only.

## When something is not ready

| `doctor` says | Do |
|---|---|
| `FAIL credential.present` | Fill in that name in `scanent.env`, or its `_FILE` |
| `FAIL host.resolves` or `reachable` | Open the host it names, on port 443; behind a proxy, set `HTTPS_PROXY` |
| `FAIL authenticated` | The credential was refused: check it is the one the access table describes, and not expired |
| `FAIL read.permitted` | The credential works but lacks the read-only role or scope the line names |
| `WARN write.absent` | The credential can write. Replace it with one that cannot |
| `the TLS certificate was not trusted` | Mount your certificate authority and set `NODE_EXTRA_CA_CERTS` |

[scanner.md](scanner.md) is the reference for every command, and
[deployment.md](deployment.md) for every way of running it.
