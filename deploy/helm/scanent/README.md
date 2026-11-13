# scanent Helm chart

Runs scanent as a Kubernetes CronJob. Each run reads the estate read-only and
writes its files under `/out/runs/<scanId>/` on a volume.

```bash
helm install scanent deploy/helm/scanent \
  --namespace scanent --create-namespace -f my-values.yaml
```

The quick start for a cluster is in [docs/quick-start.md](../../../docs/quick-start.md).

## What the chart installs

| Object | Purpose |
|---|---|
| CronJob | `scan --config /etc/scanent/config.json --out /out`, on `schedule`. One at a time, never retried |
| ConfigMap | `config.json`, rendered from `config` (not created with `existingConfigMap`) |
| PersistentVolumeClaim | The runs (`output.type: pvc`). Kept when the release is removed |
| ServiceAccount | No token is mounted and no Role is bound: the scanner never calls the Kubernetes API |
| NetworkPolicy or CiliumNetworkPolicy | See "Network" below |
| Deployment, Service, NetworkPolicy | The egress proxy, only with `egressProxy.enabled` |

It installs no Secret, no Role, no Ingress and no Service for the scanner.

## How the pod runs

- The image's own entrypoint, with arguments only. No `command`, so no shell.
- User and group 1000, `runAsNonRoot`, `fsGroup: 1000`, the `RuntimeDefault`
  seccomp profile.
- A read-only root filesystem, no privilege escalation, every capability
  dropped, not privileged.
- No service account token.
- The only writable path is `/out`.

## Configuration

Put the scanner configuration under `config` in a values file. It is the same
JSON `scanent init` writes, as YAML:

```yaml
config:
  estate: acme-prod
  scanner: { agentId: scanent-acme-prod, signingKeyEnv: SCANNER_SIGNING_KEY }
  outputs: [{ kind: file, dir: /out, retainRuns: 90 }]
  schedule: { everyHours: 24 }
  sources:
    - { kind: cicd, product: github-actions, repositories: [acme/payments-api], tokenEnv: GITHUB_READ_TOKEN }
secrets:
  existingSecret: scanent-credentials
  files:
    - { env: SCANNER_SIGNING_KEY, key: signing-key.pem }
    - { env: GITHUB_READ_TOKEN, key: github-read-token }
```

`schedule.everyHours` is required by the configuration and is not used by a
CronJob. Set it to the period of the chart's `schedule`: a reader of a report
takes it as how often the estate is scanned.

To keep the configuration in a ConfigMap you manage, set `existingConfigMap`
instead. It must hold the key `config.json`, and `inventory.json` when the
configuration names `/etc/scanent/inventory.json`.

A `code` source reads directories. List each claim holding code under
`codeRoots`; it is mounted read-only at the path the configuration's root names.

## Credentials

The chart creates no Secret, and no value of the chart can hold a credential:
`values.schema.json` refuses a key it does not know, so a values file cannot
add one. Create the Secret yourself, from files:

```bash
kubectl create secret generic scanent-credentials --namespace scanent \
  --from-file=signing-key.pem=./scanent/signing-key.pem \
  --from-file=github-read-token=./github-read-token
```

Each entry of `secrets.files` mounts one key as a file under
`/run/secrets/scanent` (mode 0440, readable through `fsGroup`) and sets
`<env>_FILE` to its path. No credential is passed as an environment value, and
none is read with `secretKeyRef`.

`scanent keygen --out signing-key.pem` makes the signing key.

A token kept in a file must not end with more than one line break.

`proxy.httpsProxy` takes no user name or password. A proxy that needs one is a
credential this chart does not hold.

## Output

| `output.type` | What it is |
|---|---|
| `pvc` (default) | The chart creates a `ReadWriteOnce` claim of `output.size`. It carries `helm.sh/resource-policy: keep` |
| `existingClaim` | The claim named in `output.existingClaim` |
| `emptyDir` | Nothing is kept after the pod ends. Refused unless `config` also delivers each run to `inflect` or `stdout`. Refused with `existingConfigMap`, where the chart cannot read the outputs |

There is no object-store output.

## Network

`scanent hosts --config config.json` prints the hosts a configuration reaches,
each on port 443. For the `everything` example they are:

<!-- hosts:begin -->
| Source | Hosts |
|---|---|
| `entra-sp` | `graph.microsoft.com`, `login.microsoftonline.com` |
| `vault` | `acme-agents.vault.azure.net`, `login.microsoftonline.com` |
| `okta-app` | `acme.okta.com` |
| `cicd` | `api.github.com` |
| `gcp-sa` | `iam.googleapis.com`, `oauth2.googleapis.com` |
| `runtime` | `eu.api.smith.langchain.com` |
| `mcp` | `mcp.acme.example` |
| `code` | none |
| `entra-integrations` | `graph.microsoft.com`, `login.microsoftonline.com` |
<!-- hosts:end -->

### `networkPolicy.flavor: kubernetes` (default)

One NetworkPolicy for the scanner pod:

- no ingress rule: nothing may connect in;
- egress to the cluster's DNS (`networkPolicy.dns`), UDP and TCP on
  `networkPolicy.dns.port` (53 by default); see [DNS](#dns) when your cluster's
  DNS is not the kube-dns pods on port 53;
- egress on TCP 443 to public addresses: `0.0.0.0/0` except `10.0.0.0/8`,
  `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10` and `169.254.0.0/16`, and
  `::/0` except `fc00::/7` and `fe80::/10`;
- each `networkPolicy.extraEgress` entry, for a host on a private address;
- with `networkPolicy.proxy.cidr` set, the 443 rule is replaced by that one
  address and port.

**What this gives:** no inbound connection, no port but 443, no
cluster-internal address and no metadata address.

**What it does not give:** it does not stop a connection to a public address
that is not one of the scanner's hosts. A NetworkPolicy matches addresses and
ports, not names, and the hosts above are names whose addresses belong to large
providers and change. The chart does not pretend otherwise.

### Exact hosts

Two ways, both fed by `scanent hosts`:

- `networkPolicy.flavor: cilium` installs a `CiliumNetworkPolicy` instead: DNS
  lookups for the names in `egress.fqdns` only, and TCP 443 to those names
  only. It needs Cilium. It is refused when `egress.fqdns` is empty, because
  that would deny every host.
- `egressProxy.enabled: true` runs the CONNECT-only proxy that ships in the
  image, with `egress.fqdns` as its allowlist. The scanner pod may then reach
  DNS and the proxy and nothing else; the proxy pod may reach TCP 443 on public
  addresses, and forwards only to a listed host. This works on any network
  plugin that enforces NetworkPolicy. The proxy resolves each name itself,
  refuses a loopback, link-local or metadata address, and connects to the
  address it checked. A host on a private address is refused unless its range
  is in `egressProxy.privateCidrs` (which also opens TCP 443 to that range for
  the proxy pod); or keep it off the proxy with `proxy.noProxy` and an
  `extraEgress` entry.

The two cannot be combined.

`networkPolicy.flavor: none` installs no policy.

### DNS

Both flavors let the pods reach DNS and nothing else on that port. The default
is the `kube-dns` / CoreDNS pods in `kube-system` on port 53. Where the cluster
differs, every lookup is dropped and every source reads as unreachable, so set
the values to match:

| Cluster | Values |
|---|---|
| NodeLocal DNSCache | `networkPolicy.dns.cidrs: [169.254.20.10/32]` (the address in the pods' `/etc/resolv.conf`). It is a node address, which a pod selector cannot match |
| OpenShift | `networkPolicy.dns.namespace: openshift-dns`, `networkPolicy.dns.podLabels: {dns.operator.openshift.io/daemonset-dns: default}`, `networkPolicy.dns.port: 5353` |

`kubectl exec` into any pod and read `/etc/resolv.conf` to see which address
the pods ask. These two were written from the products' documentation and were
not run on such a cluster.

### Is the policy enforced?

A cluster whose network plugin does not enforce NetworkPolicy accepts the
object and does nothing with it. To check, start a pod with the scanner's
labels and try a port the policy does not allow:

```bash
kubectl run np-check --namespace scanent --rm -it --restart=Never \
  --labels app.kubernetes.io/name=scanent,app.kubernetes.io/instance=scanent,app.kubernetes.io/component=scanner \
  --image busybox:1.36 -- wget -T 5 -qO- http://example.com
```

It should time out. If it prints a page, the policy is not enforced.

## Values

`values.yaml` documents each value. The ones most installs set:

| Value | Default | Meaning |
|---|---|---|
| `image.tag` | the chart's `appVersion` | The image version. `latest` is refused |
| `image.digest` | empty | `sha256:…`; used instead of the tag |
| `schedule` | `17 2 * * *` | Cron schedule |
| `strict` | `false` | Pass `--strict`: the Job fails when a source was incomplete or no agent was found |
| `config` / `existingConfigMap` | none | One of them is required |
| `secrets.existingSecret`, `secrets.files` | the signing key | The Secret, and which keys are which credentials |
| `codeRoots` | none | Claims holding code, mounted read-only |
| `output.type` | `pvc` | Where runs are kept |
| `proxy.httpsProxy`, `proxy.noProxy` | empty | A forward proxy |
| `extraCa.existingConfigMap`, `extraCa.key` | empty, `ca.pem` | A private certificate authority, added to the public ones |
| `networkPolicy.flavor` | `kubernetes` | `none`, `kubernetes` or `cilium` |
| `egress.fqdns` | none | The exact hosts, for `cilium` and the egress proxy |
| `egressProxy.enabled` | `false` | Run the bundled egress proxy |
| `egressProxy.privateCidrs` | none | Private ranges the bundled proxy may connect to |
| `networkPolicy.dns.port`, `networkPolicy.dns.cidrs` | `53`, none | Where DNS answers, when it is not the kube-dns pods on 53 |

`ci/` holds the value sets the tests render.

## An image from a bundle

On a cluster with no registry access, load the image from the air-gapped bundle
into a registry the cluster can reach and set `image.repository`, or import it
on each node (`ctr -n k8s.io images import`, then `ctr -n k8s.io images tag`
to the name the chart asks for: the bundle's README has the two commands), then
install the chart archive
the bundle carries. See [docs/deployment.md](../../../docs/deployment.md).
