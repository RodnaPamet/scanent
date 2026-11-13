# Operating scanent

What a running scanner tells you, and how to read it: the log, the exit codes,
the files of a run, and what to send when you ask for help.

- [The log](#the-log)
- [Exit codes](#exit-codes)
- [The files of a run](#the-files-of-a-run)
- [Is it working?](#is-it-working)
- [Asking for help: the support bundle](#asking-for-help-the-support-bundle)

## The log

The scanner and the egress proxy write one JSON object per line to **stderr**.
Stdout carries only what a command prints as its result (a signed report, a
public key, a doctor report, a support bundle).

Every line has three members, then the event's own:

| Member | Type | What it is |
|---|---|---|
| `ts` | string | When the line was written, ISO 8601, UTC |
| `level` | string | `info`, `warn` or `error` |
| `msg` | string | The event. One of the fixed texts below, never built from data |

A line never holds a credential, a request or response body, or a finding's
text. A string field that has the shape of a secret is written as
`[redacted]` instead of its value.

The estate's own names do appear: a scan id starts with the estate's label,
`host` is a host your configuration names, and `server` is an MCP server's
label. Treat the log as you treat the configuration.

### Events of `scan` and `schedule`

| `msg` | Level | Fields | When |
|---|---|---|---|
| `egress proven` | info | none | The configuration has `egress`, and the scan showed that the proxy allows the tenant's host, refuses the canary host, and that there is no direct route |
| `egress not proven` | warn | `failed` (string: which of the three checks failed) | The same proof failed. The scan continues and reports the criterion as not met |
| `customer host checked by the egress proxy` | info | `host` (string) | A host your configuration names is reached through scanent's own proxy, which checks the address it dials. Once per host |
| `customer host reached through a proxy` | warn | `host` (string), `note` (string) | The same, through a proxy that is not scanent's: the address check was made with this machine's resolver, not the proxy's. Once per host |
| `source read` | info | `source` (string: the source kind), `status` (string: `COMPLETE`), `rows` (number), `principals` (number: agents and identities found), `toolCalls` (number) | A source was read in full |
| `source incomplete` | warn | the fields of `source read` with `status` `INCOMPLETE`, `reason` (string: the contract's reason, such as `AUTH_FAILED`, `RATE_LIMITED`, `TIME_BOX`, `UNREACHABLE`), and `detail` (string or null: why, in the scanner's own fixed words) | A source was not read in full. Its agents are reported without a level |
| `not read` | warn | `source` (string: the source kind), `where` (string: the place, for the `code` source `code://<root label>/<path>#L<line>`), `reason` (string: the contract's reason for this place) | One place a source did not read. At most 25 for each source of a scan |
| `not read: more places than are listed` | warn | `source` (string), `unlisted` (number) | The source did not read more places than the `not read` lines name |
| `mcp server read` | info | `server` (string: the label), `tools` (number), `manifestHash` (string: `sha256:` of the listing, the value to pin) | One MCP server's listing was read in full |
| `report signed` | info | `scan` (string: the scan id), `agents` (number), `sources` (number) | The report was built and signed |
| `results written` | info | `scan` (string), `dir` (string: `runs/<scanId>`, relative to the output directory), `files` (number), `removedRuns` (number: runs removed by `retainRuns`) | The file output wrote a run |
| `report ingested` | info | `scan` (string), `complete` (boolean: whether the tenant reads it as a complete scan), `agents` (number) | The tenant accepted the report |
| `report refused` | error | `scan` (string), `status` (number: the HTTP status), `refusal` (string or null: the tenant's refusal code, when it gave one) | The tenant answered and did not accept the report. A tenant that could not be reached at all is `output failed` |
| `output failed` | error | `output` (string: `file`, `stdout` or `inflect`), `scan` (string), `error` (string: a fixed description or an error code) | One output could not be delivered. The others are still tried |
| `scheduled scan failed; the schedule continues` | error | `error` (string) | A scan of `schedule` threw. The next one runs at its time |
| `scanner stopped` | error | `error` (string) | The command ended on an error. The exit code says which kind |

### Events of the egress proxy

| `msg` | Level | Fields | When |
|---|---|---|---|
| `egress proxy listening` | info | `port` (number), `hosts` (string: the allowed hosts, comma-separated) | The proxy started |
| `egress allowlist is empty: every tunnel will be refused` | warn | none | `EGRESS_ALLOW` named no host |
| `egress allowed` | info | `host` (string), `port` (number) | A tunnel was opened to an allowed host |
| `egress refused` | warn | `reason` (string: `NOT_CONNECT`, `MALFORMED_TARGET`, `IP_LITERAL`, `PORT_NOT_ALLOWED`, `HOST_NOT_ALLOWED`, `HOST_DID_NOT_RESOLVE`, `ADDRESS_NOT_ALLOWED`, `TOO_MANY_CONNECTIONS`), and `host` (string) or, for `NOT_CONNECT`, `method` (string); `TOO_MANY_CONNECTIONS` has neither | A request was refused. Nothing was forwarded. `TOO_MANY_CONNECTIONS`: 256 connections were open, and the one that arrived was dropped before it was read |
| `egress closed` | warn | `reason` (string: `IDLE`, `UPSTREAM_DID_NOT_CONNECT`), `host` (string) | The proxy ended a connection that carried nothing for two minutes. `IDLE`: an open tunnel. `UPSTREAM_DID_NOT_CONNECT`: the host was allowed and no connection to it was made in that time; the client was answered 502 |
| `egress upstream failed` | warn | `host` (string) | The host was allowed and the connection to it failed |

A refused tunnel is the proxy doing its work. A steady stream of
`egress refused` with `HOST_NOT_ALLOWED` after a configuration change means
`EGRESS_ALLOW` was not updated: `scanent hosts --format egress-allow` prints
the value.

### What to alert on

| Signal | Meaning |
|---|---|
| No `report signed` line for longer than `schedule.everyHours` plus the time a scan takes | The schedule has stopped, or a scan is hanging past its time box |
| `source incomplete` with the same `reason` on consecutive scans | A credential expired (`AUTH_FAILED`), a limit is too low (`RATE_LIMITED`), or a host is gone (`UNREACHABLE`) |
| `report refused` or `output failed` | Results are not reaching where they should |
| `egress not proven` | The confinement the deployment relies on is not in place |
| Exit code 1, 4, 5 or 6 from a `scan` run by a scheduler | See the table below |

## Exit codes

| Code | Name | Meaning |
|---|---|---|
| 0 | `OK` | The command did what it was asked |
| 1 | `FAILED` | An output was not delivered, the tenant refused the report, the signing key is missing, or an error with no class of its own. `diff`: a difference |
| 2 | `USAGE` | Wrong arguments, an unknown flag, nowhere to deliver, a refused overwrite. Nothing was read or written |
| 3 | `INCOMPLETE` | Nothing failed, and not everything could be established. `scan --strict`: a source was incomplete, or no agent was found. `diff`: not everything could be compared. `doctor`: warnings or blocked checks |
| 4 | `CONFIG` | The configuration, the answers file, the inventory or a secret file was refused, or `NODE_TLS_REJECT_UNAUTHORIZED=0` is set |
| 5 | `CREDENTIAL` | `doctor`: a credential is missing or refused |
| 6 | `NETWORK` | `doctor`: a host could not be resolved or reached |
| 130 | `SIGINT` | Interrupted |
| 143 | `SIGTERM` | Terminated. `docker stop` and a pod's end give this |

`scan` without `--strict` exits 0 when the report was delivered, even if a
source was incomplete: the report itself says which. Use `--strict` where a
scheduler should mark such a run.

## The files of a run

With a file output, each scan writes one directory and replaces one pointer:

```
<output dir>/
  latest.json                 the newest run: scanId, dir, asOf, complete, agentCount
  runs/<scanId>/
    report.signed.json        the signed report
    results.json              levels, criteria and findings, scored locally
    agents.csv, findings.csv  the same, for a spreadsheet
    summary.html              the same, to read in a browser
    report.pdf                the same, as a document
    manifest.json             the name, size and SHA-256 of the six files above
```

A run directory is written whole or not at all, mode `0750`, files `0640`. A
run is never changed after it is written. `retainRuns` removes the oldest runs;
without it nothing is ever removed. `docs/scanner.md`, "Local results", has
every member.

## Is it working?

| Question | How to answer it |
|---|---|
| Is the estate ready to be scanned? | `scanent doctor --config <file>`. Exit 0 is ready |
| Did the last scan finish? | `latest.json` exists and its `asOf` is recent |
| Was everything read? | `latest.json` has `"complete": true`. If not, `summary.html` lists the sources that were not, first on the page |
| What changed since the last scan? | `scanent diff <older results.json> <newer results.json>` |
| Which hosts must the firewall allow? | `scanent hosts --config <file>` |
| What does it request, exactly? | `docs/network-and-permissions.md` |

## Asking for help: the support bundle

```bash
scanent support-bundle --config /etc/scanent/config.json --out support.json
```

writes one JSON document, `scanent-support/1`, for whoever is helping you.
Read it before you send it: it is yours to send or not.

| Member | What it holds |
|---|---|
| `support` | The schema id, `scanent-support/1` |
| `at` | When the bundle was made |
| `identifiers` | `REPLACED` or `INCLUDED`: whether the names below are tokens or the names themselves |
| `versions` | The scanner's version and manifest hash, the report contracts and the ladder version it speaks, the schemas of its files, and Node's version, platform and architecture |
| `config` | The estate's label and, when one is configured, the tenant's host and slug (each a token by default). The kinds of source, how many entries each lists, and each source's hosts with what each is for (a host your configuration names is a token by default; a host that is the same for everyone is named). The outputs (a directory is a token by default) and `retainRuns`, the schedule and time box, whether an inventory and an egress proof are configured. For each credential variable: its NAME, what uses it, and whether it is set in the environment, as a file, both, or not at all |
| `configProblem` | Why the configuration could not be read, when it could not. The bundle is still made |
| `environment` | Whether each of these is set, and nothing of its value: a proxy, `NO_PROXY`, `NODE_USE_ENV_PROXY`, an extra certificate authority, `NODE_TLS_REJECT_UNAUTHORIZED=0`, the egress proxy's allowlists, and `EGRESS_PROXY_CHECKS_ADDRESSES`. And three facts worked out from them: whether this Node honours the proxy variables, whether a proxy is in effect, and whether the egress proxy is the one checking addresses |
| `doctor` | With `--doctor` only: whether the estate is ready, the exit code `doctor` would give, the count of checks by status, and each check's scope, id and status, with the class of a failure and the cause of a skipped check. A scope's label is a token by default, and a check's text is left out |
| `lastRun` | From the output directory, when it holds a run: the scan id (its first part a token by default, its timestamp kept), when it was, whether it was complete, the report contract and the results schema, the scanner's version and manifest hash, why the results could not be read if they could not, each source's status, reason, rows and agents, counts of findings by code, **one entry per agent** (its id, a token by default; the sources it was found through; whether it was judged; its level), and the name and size of each file |

**What it never holds.** A credential's value. A request or a response. A
finding's text. If anything in the document has the shape of a secret, the
command writes nothing and says where.

**Whether it reads a credential depends on `--doctor`.** Without `--doctor`
the command resolves no credential and opens no secret file: it asks only
whether each variable is set. With `--doctor` it runs the preflight, and the
preflight is `scanent doctor`: it resolves every credential the configuration
names, opens every secret file, the signing key among them, and sends each
credential to its own source to check it. No value is written to the bundle
in either case.

**What it replaces.** Every name of your estate is replaced by a token such as
`host-3f9a1c2e`: the estate's label, the hosts and paths your configuration
names, labels, the tenant, the scan id's first part, and every agent id. One
name is one token throughout a bundle, so "the host that fails is the tenant's
host" can still be seen. The tokens are made with a key drawn for that one
bundle and kept nowhere, so two bundles cannot be matched to each other and a
token cannot be turned back into a name. The text of a doctor check is left
out, because it may name a host. Hosts that are the same for everyone
(`graph.microsoft.com`, `api.github.com`) are kept.

Credential variable names are kept as they are, with one exception. `init`
names an MCP server's token variable after the server's label
(`MCP_<LABEL>_TOKEN`), so that name is derived from an identifier: when a
configuration uses it, the bundle writes the label's token in its place
(`MCP_label-3f9a1c2e_TOKEN`), the same token the label has everywhere else in
the bundle. Every other variable name is one `init` gives to everyone
(`OKTA_API_TOKEN`) or one you chose, and is written as it is. If a name you
chose says more than you want to send, edit it out.

| Flag | Effect |
|---|---|
| `--out <file>` | Write to a new file, mode `0600`. An existing file is never replaced. Without it the document goes to stdout |
| `--runs <dir>` | Read the last run from this output directory, when the configuration names none |
| `--doctor` | Include the checks of `scanent doctor`. This makes the requests `doctor` makes; without it the command makes none |
| `--include-identifiers` | Keep the names instead of tokens, and the text of each doctor check. That text can name hosts, among them the outbound proxy's, and gives the signing key's public fingerprint. No credential value is written |

A run does not record its exit code or how long it took; the bundle says so
under `lastRun.notRecorded`. Send the scheduler's own record of those with it.
