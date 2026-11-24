# The engagement scope

> **scanent-probe, step 2 of the [active flavour](design/active-flavour.md).**
> The prober does not exist yet. What exists is the file it will require, the
> command that signs it, and the check it will run before it sends anything.
> Nothing here probes, and nothing here is in the read-only scanner's image.

The active flavour sends crafted inputs to an agent and reports which ones the
agent acted on. That is a tool that can be used either way, so it is held by
one rule: **no verified scope, no probe.** A scope is a small JSON file that
says exactly what may be probed, when, how, and with whose approval. It is
signed by someone in the estate who is not the prober.

## What a scope says

```json
{
  "contract": "scanent-engagement-scope/1",
  "engagementId": "eng-2026-12-acme",
  "targets": [
    {
      "kind": "mcp",
      "endpoint": "https://mcp.estate.example/mcp",
      "tools": [{ "name": "search_orders", "argument": "query" }]
    },
    { "kind": "a2a", "endpoint": "https://a2a.estate.example/tasks" },
    {
      "kind": "http-chat",
      "endpoint": "https://chat.estate.example/api/turn",
      "request": {
        "body": { "messages": [{ "role": "user", "content": "{{probe}}" }] },
        "replyPath": ["reply"]
      }
    }
  ],
  "window": { "start": "2026-12-01T09:00:00.000Z", "end": "2026-12-03T17:00:00.000Z" },
  "classes": ["canary", "disclosure"],
  "approver": { "name": "Dana Approver", "role": "Head of Security" },
  "killContact": "security on-call, +44 20 0000 0000",
  "ratePerMinute": 30,
  "proberKey": "<the prober's raw Ed25519 public key, hex or base64>"
}
```

| Member | Rule |
|---|---|
| `contract` | `scanent-engagement-scope/1` |
| `engagementId` | 8 to 64 letters, digits, `-` and `_`. Every probe request will carry it, so the target's owner can find the engagement in their logs |
| `targets` | 1 to 50, each named once. `kind` is `mcp`, `a2a` or `http-chat`. `endpoint` is an **exact** https URL: no credentials, no query, no fragment, no `*`, and spelt exactly as a URL serialises (`new URL(endpoint).href`): a lower-case host, no `:443`, a `/` after a bare host. A request is admitted only to an endpoint equal to one listed, byte for byte. What else a target says depends on its kind (below) |
| `window` | `start` and `end` in UTC (ending in `Z`). The end is after the start, and **at most seven days** after it |
| `classes` | `canary`, `disclosure`, or both. `side-effect` is not allowed in version 1 |
| `approver` | The name and role of the person who approved the engagement. One line each, never a secret |
| `killContact` | Who to call to stop it. One line, never a secret |
| `ratePerMinute` | Requests per minute to each target, a whole number **from 1 to 120** |
| `proberKey` | The one prober allowed to run this scope. A scope copied to another prober is refused there |

Any other member is refused.

### How each kind of target is reached

| Kind | It also names | What the prober sends |
|---|---|---|
| `mcp` | `tools`: 1 to 10, each named once, with the `argument` the probe goes in (letters, digits, `_`, `.`, `-`; at most 128) | Once per run: `initialize`, `notifications/initialized` and `tools/list`. Then `tools/call` of each named tool, once per probe. **A tool the scope does not name is never called**, and a named tool is called only if the server lists it and its input takes that argument as a string. The approver's signature is the estate's statement that these tools are safe to call |
| `a2a` | Nothing else | One JSON-RPC `message/send` per probe, blocking, with the probe as a text part. No polling |
| `http-chat` | `request.body`: a JSON template of at most 8 KiB and depth 16 holding **exactly one** string that is `{{probe}}` (a whole string, never part of one), and no key or string of a secret's shape; `request.replyPath`: 1 to 16 keys or indices to the reply | One POST of that body per probe, with the probe put in as a JSON value, so it cannot break out of the template. The reply is the string at `replyPath` |

A credential is never in a scope. The approver signs exactly what is sent, so a
token would be signed into a file people pass around. The prober reads one from
its own environment and sends it only to its endpoint (see the
[runner](probe-runner.md#a-run-that-sends)).

## Who signs it

The scope is signed by an **approver key**: an Ed25519 key the estate made for
this purpose and registered with the prober in advance. It is never the
prober's own key. The party that runs the probes does not authorise them. The
approver makes a key with `scanent keygen`, and the public key that command
prints is what the estate registers:

```bash
scanent keygen --out approver-key.pem
scanent-probe scope sign --key approver-key.pem --in scope.json --out scope.signed.json
```

`scope sign` refuses a scope that would not verify, and refuses to sign with the
key of the prober the scope names. The signed file is created and never
overwritten: it is the record of what was authorised.

## How the prober checks it

```bash
scanent-probe scope verify --scope scope.signed.json \
  --trusted-key <approver public key> --prober-key <this prober's public key> \
  [--target <endpoint>] [--class <class>]
```

The checks run in this order. The first one that fails is the refusal:

| Refusal | Meaning |
|---|---|
| `NO_SCOPE` | No scope file, or it cannot be read |
| `TOO_LARGE`, `NOT_JSON`, `NOT_AN_OBJECT` | Not a scope file at all |
| `UNSIGNED`, `MALFORMED_SIGNATURE` | No signature, or one that cannot be read |
| `UNTRUSTED_SIGNER` | Signed by a key the estate did not register |
| `BAD_SIGNATURE` | Changed after it was signed |
| `SCHEMA` | Breaks a rule in the table above. The refusal names the member and the rule, never the value |
| `SIGNER_IS_PROBER` | Signed by the prober's own key, or by the prober the scope names, even if that key was registered by mistake |
| `PROBER_NOT_NAMED` | The scope names a different prober |
| `NOT_YET_OPEN` | Before `start` |
| `CLOSED` | At or after `end`. There is no allowance for clock difference either way, so a wrong clock stops a run rather than stretching its window |
| `TARGET_NOT_NAMED` | `--target` is not one of the scope's endpoints |
| `CLASS_NOT_ALLOWED` | `--class` is not one of the scope's classes |

A verified scope prints its engagement, window, classes, number of targets,
rate, **digest** (`sha256:` over the signed content; a probe report will name
it) and the signer key's fingerprint. It never prints the approver or the
contact. Every refusal exits with code 1, and a usage error with code 2.

The prober will run the last four checks again **before every request**, with
the time read at that request, so a run that outlives its window stops at its
next request. In code that is `scopeAdmits` in `packages/probe/src/scope.ts`.

## Where it lives

`packages/probe` is its own package with its own command, `scanent-probe`. It
imports only the contract package and `zod`, never the scanner. The
read-only image's build names its three packages and nothing else, and a test
holds that no file of `packages/probe` reaches the image. The package is not an
npm workspace yet: the root lockfile is the read-only image's bill of
materials, so the prober will get an install of its own with its image (step 7).
Until then it runs on the repository's own install:

```bash
npm ci && npm run build && npm run build:probe
node packages/probe/bin/scanent-probe.js help
```
