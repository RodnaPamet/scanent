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
per request: the target's number in the scope, the probe id and its class. It
does not print the rendered text, which holds that plan's canary halves.
`run` without `--dry-run` is refused: this build has nothing to send with.

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
