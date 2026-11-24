# The probe runner

> **scanent-probe, step 5 of the [active flavour](design/active-flavour.md).**
> The runner sends the [catalogue](probe-catalogue.md)'s probes to a scope's
> targets and judges each reply. In this build it sends only through the
> transport it is handed, and every transport is a fake agent. The real MCP,
> A2A and HTTP transports, with their declared request surface, arrive with
> the prober's image (step 7). Until then nothing here can reach a real target.

## What a run needs

`runProbes` in `packages/probe/src/runner.ts` takes:

- a **verified** [engagement scope](engagement-scope.md): the result of
  `verifyEngagementScope`, so a run cannot start without one;
- a transport, which sends one probe and returns the reply or nothing;
- a clock and a way to wait;
- a stop check;
- optionally, the markers the estate planted in the agent's instructions.

## What it sends

The run goes target by target in the scope's order, and probe by probe in the
catalogue's order. It sends only the probes of the classes the scope allows,
and only those that suit each target's interface. Every canary probe gets a
fresh marker, unique across the run.

Every request carries one header, `X-Scanent-Engagement: <engagementId>`, so the
target's owner can find the engagement in their logs. No other header comes from
the scope.

## Before every request

These checks run in this order. The first one that fails ends the run:

| Check | Ends the run as |
|---|---|
| A stop was asked for (a stop file or a signal) | `STOPPED` |
| The rate cap: at least 60 000 / `ratePerMinute` milliseconds since the last request to the **same** target, waited out first | (a wait, not an end) |
| The scope's gate, read with the clock after the wait: before the window, or at or after its end, with no allowance for clock difference | `NOT_YET_OPEN`, `CLOSED` |
| The scope's gate: a target or class the scope does not admit | `TARGET_NOT_NAMED`, `CLASS_NOT_ALLOWED` |

A run built from a scope can never ask for a target or class the scope does not
admit. If it ever did, the plan would be wrong, so the run stops rather than
skipping that request. A rate wait that crosses the end of the window ends the
run before the next request is sent. Two targets never hold each other back:
each one's gap is measured on its own.

## What it returns

| Member | Meaning |
|---|---|
| `outcomes` | One verdict per probe sent, with its target (see the [catalogue](probe-catalogue.md#verdicts)) |
| `targets` | Per target: `REACHED` (it answered), `NO_REPLY` (it never answered), `NOT_RUN` (the run stopped first) or `NO_PROBES_FOR_INTERFACE` (no allowed probe suits it; the catalogue's tests keep this from happening today) |
| `stopped` | Why the run ended early, or nothing when every planned probe was sent |
| `concluded` | True only when some probe got a verdict other than INCONCLUSIVE. A run that reached nothing, or learned nothing, concludes nothing and says so |
| `engagementId`, `scopeDigest`, `startedAt`, `endedAt` | What it ran under, and when |

A transport that fails gives that probe `NO_REPLY` (INCONCLUSIVE), and the run
goes on. No error text is kept, because a failure can carry what the target
said.

A run becomes a signed report, [`scanent-probes/1`](contract.md#the-probes-contract),
through `buildProbeReport` and `signProbeReport` in `packages/probe/src/report.ts`.
The prober the scope names signs it, and a dry run has no report.

## A dry run

A dry run lists every request a real run would send, in the same order, and
sends none. It needs no open window, because it sends nothing.

```bash
scanent-probe run --dry-run --scope scope.signed.json \
  --trusted-key <approver public key> --prober-key <this prober's public key>
```

It verifies the scope exactly as `scope verify` does. It then prints one line
per request: the target's number in the scope, the probe id, its class and, for
an MCP target, the tool. It does not print the rendered text, which holds that
plan's canary halves.

## A run that sends

```bash
scanent-probe run --scope scope.signed.json --trusted-key <approver public key> \
  --signing-key-env PROBER_KEY --out report.json \
  [--credential https://mcp.estate.example/mcp=MCP_TOKEN] \
  [--planted-marker-env CONTEXT_MARKER] [--stop-file STOP]
```

- **The prober's key** is read from the variable `--signing-key-env` names, or
  from the file `NAME_FILE` names, never both. Its public half must be the
  scope's `proberKey`, or the scope is refused (`PROBER_NOT_NAMED`) before
  anything is sent.
- **A credential** is read the same way, for one endpoint of the scope. It is
  sent as `Authorization: Bearer …` to that endpoint and to no other, and an
  endpoint the scope does not name is a usage error.
- **A planted marker** is the estate's own text, put in the agent's
  instructions so a leak of them can be seen. It is read the same way.
- **Stopping:** the stop file existing, or a SIGINT or SIGTERM, ends the run at
  its next request. A second signal ends the process.
- **The report** is written to `--out`, which must not exist and is never
  replaced. It is signed by the prober's key.
- **What it prints** is the number of probes sent, the counts per verdict,
  each target's reason with a note on why it went unanswered, and whether the
  run concluded anything. It never prints an excerpt, a credential or a marker.

## The declared surface

Every engagement has a declared surface, built from its signed scope by
`probeSurface` (`packages/probe/src/surface.ts`). It lists every endpoint the
run may reach, the one method (POST), the JSON-RPC messages for each kind of
target, the MCP tools and the argument each takes, and a chat target's body
template. It also names the prober's version and the catalogue's digest.

**It is checked before every request** (owner decision, 2026-11-24). The wire
describes each request it is about to send and asks `offSurface`. A request
that is not on the surface, such as another host, another method, a JSON-RPC
message or tool the surface does not name, or a chat body that is not the
scope's template, is refused before it leaves, and its target's note is
`OFF_SURFACE`. There is no wire without a surface. The tests check every
recorded request with the same function, so the guard and the proof are one
piece of code.

The signed report carries `run.surfaceDigest`. Anyone holding the scope
rebuilds it with `probeSurface` and compares.

## The image

`deploy/probe.Dockerfile` builds `scanent-probe`, an image of its own,
separate from the read-only scanner's (decision 1). It uses the same pinned
bases as the scanner's image. Its runtime holds the prober, the contract and
zod, and nothing of the scanner. It runs as uid 1000 with no shell and no
package manager. With no arguments it prints its help.

```bash
docker build -f deploy/probe.Dockerfile -t scanent-probe .
deploy/probe-smoke.sh scanent-probe
```

`deploy/probe-smoke.sh` runs it with no network and a read-only root
filesystem. It makes the keys inside the image, signs a scope, does a dry run
and a real run, verifies the report under the prober's key, and checks that the
report's surface digest is the one the scope gives. CI's `image-probe` job runs
it and the same Trivy and Grype gates as the scanner's image.

**The image is not published** (owner decision, 2026-11-24). No release builds
or pushes it. Whether and where it is published is a decision for later.

### The wire

`packages/probe/src/wire.ts` sends each probe. It follows the scanner's rules
(`packages/scanner/src/http.ts`), written again because the prober may not
import the scanner:

- every request is a POST to the target's exact endpoint;
- redirects are refused (`redirect: 'error'`, and a 3xx is no reply);
- each request times out after 60 seconds;
- a reply is read as a stream and cut at four bytes a character of what a
  verdict reads.

What it sends to each kind of target is listed in the
[engagement scope](engagement-scope.md#how-each-kind-of-target-is-reached).

A target that never answered gets a note: the first reason, as a code, why a
request to it got no reply. The codes are `UNREACHABLE`, `TIMEOUT`,
`REDIRECT_REFUSED`, `AUTH_FAILED`, `HTTP_4XX`, `HTTP_5XX`, `NOT_JSON`, `NO_TEXT`,
`RPC_ERROR`, `TOOL_NOT_LISTED` and `SESSION_FAILED`. The note is for the person
running the engagement and is not in the signed report. Nothing a target said is
kept with it.

## Tested against fake agents

`packages/probe/tests/runner.test.ts` runs the runner against fake agents routed
by endpoint, with a clock the tests move. It checks:

- the verdicts per target;
- the header, and that requests go only to the scope's endpoints;
- the classes and interfaces sent;
- unique canaries;
- silent and failing targets;
- a run before the window, a run that reaches its end, and a rate wait that
  crosses it;
- the rate gaps at 30 and 120 requests per minute;
- a stop mid-run;
- that a dry run plans exactly what a real run sends.
