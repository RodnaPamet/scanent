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
| `source incomplete` | warn | the fields of `source read` with `status` `INCOMPLETE`, and `reason` (string: the contract's reason, such as `AUTH_FAILED`, `RATE_LIMITED`, `TIME_BOX`, `UNREACHABLE`) | A source was not read in full. Its agents are reported without a level |
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
| `egress refused` | warn | `reason` (string: `NOT_CONNECT`, `MALFORMED_TARGET`, `IP_LITERAL`, `PORT_NOT_ALLOWED`, `HOST_NOT_ALLOWED`, `HOST_DID_NOT_RESOLVE`, `ADDRESS_NOT_ALLOWED`), and `host` (string) or, for `NOT_CONNECT`, `method` (string) | A request was refused. Nothing was forwarded |
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
    summary.html              the same, to read
    manifest.json             the name, size and SHA-256 of the five files above
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
| `versions` | The scanner's version and manifest hash, the report contracts and the ladder version it speaks, the schemas of its files, and Node's version, platform and architecture |
| `config` | The kinds of source and how many entries each lists, the outputs, the schedule and time box, whether an inventory and an egress proof are configured, and for each credential variable its NAME, what uses it, and whether it is set in the environment, as a file, both, or not at all |
| `configProblem` | Why the configuration could not be read, when it could not. The bundle is still made |
| `environment` | Whether each of these is set, and nothing of its value: a proxy, `NO_PROXY`, `NODE_USE_ENV_PROXY`, an extra certificate authority, `NODE_TLS_REJECT_UNAUTHORIZED=0`, and the egress proxy's variables |
| `doctor` | With `--doctor` only: each check's scope, id and status |
| `lastRun` | From the output directory, when it holds a run: when it was, whether it was complete, each source's status and reason, counts of agents and of findings by code, and the size of each file |

**What it never holds.** A credential's value: the command does not read one,
and it opens no secret file. A request or a response. A finding's text. If
anything in the document has the shape of a secret, the command writes nothing
and says where.

**What it replaces.** Every name of your estate is replaced by a token such as
`host-3f9a1c2e`: the estate's label, the hosts and paths your configuration
names, labels, the tenant, the scan id's first part, and every agent id. One
name is one token throughout a bundle, so "the host that fails is the tenant's
host" can still be seen. The tokens are made with a key drawn for that one
bundle and kept nowhere, so two bundles cannot be matched to each other and a
token cannot be turned back into a name. The text of a doctor check is left
out, because it may name a host. Hosts that are the same for everyone
(`graph.microsoft.com`, `api.github.com`) are kept.

Credential variable names are kept as they are. If your names say more than
you want to send, edit them out.

| Flag | Effect |
|---|---|
| `--out <file>` | Write to a new file, mode `0600`. An existing file is never replaced. Without it the document goes to stdout |
| `--runs <dir>` | Read the last run from this output directory, when the configuration names none |
| `--doctor` | Include the checks of `scanent doctor`. This makes the requests `doctor` makes; without it the command makes none |
| `--include-identifiers` | Keep the names instead of tokens, and the text of each doctor check. Credential values are still never read |

A run does not record its exit code or how long it took; the bundle says so
under `lastRun.notRecorded`. Send the scheduler's own record of those with it.
