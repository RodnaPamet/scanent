#!/usr/bin/env bash
# The scanent image's smoke test: what CI runs against the image it has just
# built, and what anyone can run against one they built themselves. It builds
# nothing.
#
#   deploy/smoke.sh <image>
#
# Every run of the image is the way an estate is told to run it (README.md,
# "Quick start, container"): no network, a read-only root filesystem, every
# capability dropped, no privilege gain, as the image's own non-root user. It
# checks, in order:
#
#   1. the image runs as a user other than root, carries no shell and no
#      package manager (npm, npx, corepack, yarn, apk, apt, dpkg), and holds no
#      TypeScript source and no run-time compiler;
#   2. `public-key` prints the raw Ed25519 public key of the key it was given;
#   3. `scan --dry-run` reads an estate of LangChain code, one Python agent and
#      one TypeScript agent, so both readers and the pinned TypeScript parser
#      run, and prints a signed report;
#   4. that report verifies against that key through the image's own contract
#      module, speaks `/3`, and holds both agents (`smoke-verify.js`);
#   5. `scan` without `--dry-run`, with nowhere to post to, exits non-zero:
#      a scan that could not be delivered is never reported as a success;
#   6. `scan --dry-run --out /out`, with the root filesystem still read-only
#      and one writable mount, writes one directory per run holding the six
#      files, and a second run leaves the first run's files as they were;
#   7. run as the invoking user (`--user`, with `--userns=keep-id` under Podman)
#      into an output directory that user owns with mode 0700, a scan writes
#      runs the invoking user can read without the container: the run
#      directory 0750, its files 0640, all owned by that user;
#   8. the signing key given only as a mounted file (mode 0444) named by
#      SCANNER_SIGNING_KEY_FILE: `public-key` prints the same key;
#   9. `init --answers` writes a configuration, an env template and a signing
#      key into a writable mount, and `doctor --json` on what it wrote exits 0
#      or 3 with no failed check;
#  10. `hosts` on a code-only configuration prints nothing and exits 0;
#  11. through deploy/compose.yaml with the egress overlay, an MCP server on
#      the proxy's outer network (`smoke-mcp-server.js`, run from the image):
#      the scan reads its tools through the proxy and reports the source
#      COMPLETE; with the host taken off EGRESS_ALLOW the proxy refuses it and
#      the source is UNREACHABLE; and the scanner's container cannot reach the
#      server except through the proxy.
#
#   CONTAINER_RUNTIME    docker (default) or podman
#   SMOKE_SKIP_COMPOSE   1 leaves step 11 out, and says so. For a runtime with
#                        no `compose`. Unset, a missing `compose` fails.
#
# Nothing here needs a shell or any other tool inside the image: what is read
# back from a container is read by the image's own `node`.
#
# The estate is written here rather than committed: a committed `.ts` fixture
# would be type-checked and linted as this repository's own code.
set -euo pipefail

IMAGE="${1:?usage: smoke.sh <image>}"
RUNTIME="${CONTAINER_RUNTIME:-docker}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
# The runs of step 6 are written by the image's user, in directories this user
# may not be able to enter, so they are removed the way they were made.
cleanup() {
    if [ -n "${COMPOSE_PROJECT:-}" ]; then
        compose down --volumes --remove-orphans > /dev/null 2>&1 || true
    fi
    if [ -d "$WORK/out" ]; then
        "$RUNTIME" run --rm --network none -v "$WORK/out:/out" --entrypoint node "$IMAGE" -e 'for (const p of ["/out/runs", "/out/latest.json"]) require("node:fs").rmSync(p, { recursive: true, force: true })' > /dev/null 2>&1 || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
    echo "FAIL $*" >&2
    exit 1
}

# Step 11's Compose project: the two files a site uses, and one more that
# names this image, the stand-in MCP server and the mounts of this test.
compose() {
    "$RUNTIME" compose -p "$COMPOSE_PROJECT" --project-directory "$WORK/overlay" \
        -f "$HERE/compose.yaml" -f "$HERE/compose.egress.yaml" -f "$WORK/overlay/compose.smoke.yaml" "$@"
}

# The way an estate runs the image, plus whatever a step adds.
run() {
    "$RUNTIME" run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges "$@"
}

mkdir -p "$WORK/config" "$WORK/estate/support" "$WORK/estate/research"

cat > "$WORK/estate/support/agent.py" <<'PY'
import os

from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI


@tool
def lookup_order(order_id: str) -> str:
    """Look an order up by its id."""
    return f"order {order_id}"


llm = ChatOpenAI(model="gpt-4o-mini", api_key=os.environ["SUPPORT_OPENAI_KEY"])
tools = [lookup_order]
prompt = ChatPromptTemplate.from_messages([("system", "You are a support agent."), ("human", "{input}")])
agent = create_tool_calling_agent(llm, tools, prompt)
support_executor = AgentExecutor(agent=agent, tools=tools)
PY

cat > "$WORK/estate/research/agent.ts" <<'TS'
import { ChatAnthropic } from "@langchain/anthropic";
import { ChatPromptTemplate } from "@langchain/core/prompts";
import { tool } from "@langchain/core/tools";
import { AgentExecutor, createToolCallingAgent } from "langchain/agents";
import { z } from "zod";

const searchPapers = tool(async ({ query }: { query: string }) => `results for ${query}`, {
  name: "search_papers",
  description: "Search the paper index.",
  schema: z.object({ query: z.string() }),
});

const llm = new ChatAnthropic({ model: "research-model-v1", apiKey: process.env.RESEARCH_ANTHROPIC_KEY });
const prompt = ChatPromptTemplate.fromMessages([["system", "You research."], ["human", "{input}"]]);
const tools = [searchPapers];
const agent = await createToolCallingAgent({ llm, tools, prompt });
export const researchExecutor = new AgentExecutor({ agent, tools });
TS

cat > "$WORK/config/config.json" <<'JSON'
{
  "estate": "smoke",
  "scanner": { "agentId": "agt_smoke_scanner", "signingKeyEnv": "SCANNER_SIGNING_KEY" },
  "inflect": { "baseUrl": "https://inflect.invalid", "tenantSlug": "smoke", "apiKeyEnv": "INFLECT_INGEST_KEY" },
  "schedule": { "everyHours": 24 },
  "sources": [
    { "kind": "code", "product": "langchain", "roots": [{ "label": "estate", "path": "/estate" }] }
  ]
}
JSON

# The image's user is not this one: let it read what it is given, and no more.
chmod -R a+rX "$WORK"

SCANNER_SIGNING_KEY="$(openssl genpkey -algorithm ed25519)"
export SCANNER_SIGNING_KEY
# Not a key: the post it is sent with cannot leave a container with no network.
export INFLECT_INGEST_KEY=smoke-not-a-key

MOUNTS=(-v "$WORK/config:/etc/scanent:ro" -v "$WORK/estate:/estate:ro")

echo "== 1. the image's user and tooling"
declared="$("$RUNTIME" image inspect --format '{{.Config.User}}' "$IMAGE")"
case "$declared" in
    "" | 0 | 0:* | root | root:*) fail "the image declares the user '$declared'" ;;
esac
uid="$(run --entrypoint node "$IMAGE" -e 'process.stdout.write(String(process.getuid()))')"
[ "$uid" != "0" ] || fail "the image runs as root"
echo "ok   runs as uid $uid (declared: $declared)"
# No shell and no package manager, under any directory of the image's PATH or
# the usual ones. A shell that cannot be started is also asked for by name.
run --entrypoint node "$IMAGE" -e '
const fs = require("node:fs");
const names = ["sh", "bash", "ash", "dash", "busybox", "npm", "npx", "corepack", "yarn", "yarnpkg", "apk", "apt", "apt-get", "dpkg"];
const dirs = [...new Set([...(process.env.PATH || "").split(":"), "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/nodejs/bin"])].filter(Boolean);
const found = dirs.flatMap((d) => names.map((n) => `${d}/${n}`)).filter((p) => fs.existsSync(p));
for (const p of ["/usr/local/lib/node_modules/npm", "/usr/local/lib/node_modules/corepack"]) if (fs.existsSync(p)) found.push(p);
if (found.length > 0) { console.error(found.join(" ")); process.exit(1); }
' || fail "the image carries a shell or a package manager"
if "$RUNTIME" run --rm --network none --entrypoint sh "$IMAGE" -c true > /dev/null 2>&1; then
    fail "a shell started inside the image"
fi
echo "ok   no shell, and no npm, npx, corepack, yarn, apk, apt or dpkg"
# Compiled JavaScript only: no TypeScript source of its own, and neither of the
# two packages that would compile it at start.
run --entrypoint node "$IMAGE" -e '
const fs = require("node:fs");
const path = require("node:path");
const found = [];
const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        if (e.name === "node_modules") continue;
        const child = path.join(dir, e.name);
        if (e.isDirectory()) walk(child);
        else if (e.name.endsWith(".ts")) found.push(child);
    }
};
walk("/app/packages");
for (const p of ["/app/node_modules/tsx", "/app/node_modules/esbuild"]) if (fs.existsSync(p)) found.push(p);
if (found.length > 0) { console.error(found.slice(0, 5).join(" ")); process.exit(1); }
' || fail "the image holds TypeScript source, tsx or esbuild"
echo "ok   compiled JavaScript only"

echo "== 2. public-key"
key="$(run -e SCANNER_SIGNING_KEY "${MOUNTS[@]}" "$IMAGE" public-key --config /etc/scanent/config.json)"
[[ "$key" =~ ^[0-9a-f]{64}$ ]] || fail "public-key printed '$key', not a raw Ed25519 key in hex"
expected="$(printf '%s\n' "$SCANNER_SIGNING_KEY" | openssl pkey -pubout -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n')"
[ "$key" = "$expected" ] || fail "public-key printed a key other than the one it was given"
echo "ok   $key"

echo "== 3. scan --dry-run"
run -e SCANNER_SIGNING_KEY "${MOUNTS[@]}" "$IMAGE" scan --dry-run --config /etc/scanent/config.json \
    > "$WORK/report.json" 2> "$WORK/scan.log" || { cat "$WORK/scan.log" >&2; fail "the dry run exited non-zero"; }
echo "ok   $(wc -c < "$WORK/report.json") bytes"

echo "== 4. the report, verified inside the image"
run -i -v "$HERE/smoke-verify.js:/app/smoke-verify.js:ro" \
    --entrypoint node "$IMAGE" /app/smoke-verify.js "$key" \
    < "$WORK/report.json" || fail "the report did not verify"

echo "== 5. scan with nowhere to post"
if run -e SCANNER_SIGNING_KEY -e INFLECT_INGEST_KEY "${MOUNTS[@]}" "$IMAGE" scan --config /etc/scanent/config.json \
    > /dev/null 2> "$WORK/post.log"; then
    fail "a scan that could not be posted exited 0"
fi
echo "ok   exited non-zero"

echo "== 6. scan --out"
# One writable mount; everything else, the root filesystem included, stays
# read-only. The image's user is not this one, so the directory is opened up
# for it, and what it wrote is read back through the image.
mkdir -p "$WORK/out"
chmod 0777 "$WORK/out"
OUT=(-v "$WORK/out:/out")
scan_out() {
    run -e SCANNER_SIGNING_KEY "${MOUNTS[@]}" "${OUT[@]}" "$IMAGE" scan --dry-run --out /out --config /etc/scanent/config.json \
        > /dev/null 2> "$WORK/out.log" || { cat "$WORK/out.log" >&2; fail "scan --out exited non-zero"; }
}
# What the image's user wrote, read by the image's own node: one line per entry.
inspect() {
    run "${OUT[@]}" --entrypoint node "$IMAGE" -e "$1"
}
LIST_RUNS='console.log(require("node:fs").readdirSync("/out/runs").sort().join("\n"))'
# `<sha256>  <name>` for every file of one run, sorted by name.
hashes_of() {
    inspect "
const fs = require('node:fs');
const dir = '/out/runs/$1';
for (const name of fs.readdirSync(dir).sort()) {
    console.log(require('node:crypto').createHash('sha256').update(fs.readFileSync(dir + '/' + name)).digest('hex') + '  ' + name);
}"
}
scan_out
first="$(inspect "$LIST_RUNS")"
[ "$(printf '%s\n' "$first" | wc -l)" -eq 1 ] || fail "one run should have written one directory, found: $first"
[[ "$first" =~ ^smoke-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$ ]] || fail "the run directory is not named by a scan id: $first"
files="$(hashes_of "$first" | sed 's/^[0-9a-f]*  //' | sort | tr '\n' ' ')"
[ "$files" = "agents.csv findings.csv manifest.json report.signed.json results.json summary.html " ] \
    || fail "the run holds '$files', not the six files"
inspect 'process.exit(require("node:fs").statSync("/out/latest.json").isFile() ? 0 : 1)' || fail "no latest.json pointer was written"
before="$(hashes_of "$first")"
[ "$(printf '%s\n' "$before" | grep -cE '^[0-9a-f]{64}  ')" -eq 6 ] || fail "the first run's files could not be hashed"
echo "ok   six files in runs/$first"
scan_out
[ "$(inspect "$LIST_RUNS" | wc -l)" -eq 2 ] || fail "a second run should add a second directory"
after="$(hashes_of "$first")"
[ "$before" = "$after" ] || fail "the second run changed the first run's files"
echo "ok   a second run left the first as it was"

echo "== 7. scan --out as the invoking user, into a directory only that user can enter"
# The way the quick start says to run it: the scanner is the person running it,
# so the runs are theirs to read, and the directory needs no opening up.
if [ "$RUNTIME" = "podman" ]; then
    # Both: `keep-id` maps the invoking user to the same uid inside, and
    # `--user` runs as it. Alone, `keep-id` leaves the image's own user (uid
    # 1000), which is the invoking user only on a machine where that is 1000.
    AS_ME=(--userns=keep-id --user "$(id -u):$(id -g)")
else
    AS_ME=(--user "$(id -u):$(id -g)")
fi
mkdir -m 0700 "$WORK/mine"
run "${AS_ME[@]}" -e SCANNER_SIGNING_KEY "${MOUNTS[@]}" -v "$WORK/mine:/out" "$IMAGE" scan --dry-run --out /out --config /etc/scanent/config.json \
    > /dev/null 2> "$WORK/mine.log" || { cat "$WORK/mine.log" >&2; fail "scan --out as uid $(id -u) exited non-zero"; }
# Read back here, with no container: that is the point.
[ -s "$WORK/mine/latest.json" ] || fail "latest.json is not readable by the invoking user"
mine="$(ls "$WORK/mine/runs")"
[ "$(printf '%s\n' "$mine" | wc -l)" -eq 1 ] || fail "one run should have written one directory, found: $mine"
grep -q '<html' "$WORK/mine/runs/$mine/summary.html" || fail "summary.html is not readable by the invoking user"
[ "$(stat -c '%a %u' "$WORK/mine/runs/$mine")" = "750 $(id -u)" ] \
    || fail "the run directory is $(stat -c '%a, owned by uid %u' "$WORK/mine/runs/$mine"), not 750 owned by uid $(id -u)"
for f in "$WORK/mine/runs/$mine"/*; do
    [ "$(stat -c '%a %u' "$f")" = "640 $(id -u)" ] || fail "$(basename "$f") is $(stat -c '%a, owned by uid %u' "$f"), not 640 owned by uid $(id -u)"
done
[ "$(stat -c '%a' "$WORK/mine")" = "700" ] || fail "the output directory's mode changed"
echo "ok   uid $(id -u) reads its own run: directory 750, six files 640"

echo "== 8. the signing key from a mounted file"
mkdir "$WORK/secrets"
printf '%s\n' "$SCANNER_SIGNING_KEY" > "$WORK/secrets/signing-key.pem"
chmod 0444 "$WORK/secrets/signing-key.pem"
chmod 0755 "$WORK/secrets"
from_file="$(run -e SCANNER_SIGNING_KEY_FILE=/run/secrets/scanner_signing_key \
    -v "$WORK/secrets/signing-key.pem:/run/secrets/scanner_signing_key:ro" \
    "${MOUNTS[@]}" "$IMAGE" public-key --config /etc/scanent/config.json)"
[ "$from_file" = "$key" ] || fail "public-key from SCANNER_SIGNING_KEY_FILE printed '$from_file', not the key of step 2"
if run -e SCANNER_SIGNING_KEY -e SCANNER_SIGNING_KEY_FILE=/run/secrets/scanner_signing_key \
    -v "$WORK/secrets/signing-key.pem:/run/secrets/scanner_signing_key:ro" \
    "${MOUNTS[@]}" "$IMAGE" public-key --config /etc/scanent/config.json > /dev/null 2>&1; then
    fail "the key given both as a value and as a file was accepted; one of the two would be silently ignored"
fi
echo "ok   the same key, and both forms at once are refused"

echo "== 9. init --answers, then doctor on what it wrote"
mkdir -m 0700 "$WORK/init" "$WORK/answers"
cat > "$WORK/answers/answers.json" <<'JSON'
{
  "answers": "scanent-init-answers/1",
  "estate": "smoke-init",
  "outputDir": "/out",
  "sources": [{ "kind": "code", "roots": [{ "label": "estate", "path": "/estate" }] }]
}
JSON
chmod 0755 "$WORK/answers"
chmod 0644 "$WORK/answers/answers.json"
run "${AS_ME[@]}" -v "$WORK/init:/etc/scanent" -v "$WORK/answers:/answers:ro" "$IMAGE" \
    init --dir /etc/scanent --answers /answers/answers.json > /dev/null 2> "$WORK/init.log" \
    || { cat "$WORK/init.log" >&2; fail "init --answers exited non-zero"; }
for f in config.json scanent.env signing-key.pem; do
    [ "$(stat -c '%a' "$WORK/init/$f")" = "600" ] || fail "init wrote $f with mode $(stat -c '%a' "$WORK/init/$f"), not 600"
done
grep -qx 'SCANNER_SIGNING_KEY_FILE=/etc/scanent/signing-key.pem' "$WORK/init/scanent.env" \
    || fail "scanent.env does not name the signing key's file"
# Every line of the env template is a comment, blank, or a NAME with nothing or a path after it.
if grep -vE '^(#.*|[A-Z][A-Z0-9_]*=(/[^[:space:]]*)?)?$' "$WORK/init/scanent.env" > /dev/null; then
    fail "scanent.env holds a line that is not a NAME, an empty value or a path"
fi
mkdir -m 0700 "$WORK/init-out"
set +e
run "${AS_ME[@]}" --env-file "$WORK/init/scanent.env" -v "$WORK/init:/etc/scanent:ro" -v "$WORK/estate:/estate:ro" -v "$WORK/init-out:/out" \
    "$IMAGE" doctor --json --config /etc/scanent/config.json > "$WORK/doctor.json" 2> "$WORK/doctor.log"
doctor_exit=$?
set -e
[ "$doctor_exit" -eq 0 ] || [ "$doctor_exit" -eq 3 ] || { cat "$WORK/doctor.json" "$WORK/doctor.log" >&2; fail "doctor exited $doctor_exit, not 0 or 3"; }
run -i --entrypoint node "$IMAGE" -e '
const doc = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
const failed = doc.checks.filter((c) => c.status === "FAIL");
const passed = doc.checks.filter((c) => c.status === "PASS").length;
if (doc.doctor !== "scanent-doctor/1" || failed.length > 0 || passed === 0 || doc.counts.PASS !== passed) {
    console.error(JSON.stringify({ schema: doc.doctor, failed, passed }));
    process.exit(1);
}
console.log(`ok   doctor: ${passed} passed, ${doc.counts.WARN} warnings, 0 failed, ${doc.counts.SKIPPED} not checked`);
' < "$WORK/doctor.json" || fail "doctor reported a failed check, or nothing that passed"
[ -z "$(ls -A "$WORK/init-out")" ] || fail "doctor wrote into the output directory"
echo "ok   doctor exited $doctor_exit and wrote nothing"

echo "== 10. hosts on a code-only configuration"
hosts="$(run "${AS_ME[@]}" -v "$WORK/init:/etc/scanent:ro" "$IMAGE" hosts --config /etc/scanent/config.json)" \
    || fail "hosts exited non-zero"
[ -z "$hosts" ] || fail "a code-only configuration reaches no host, but hosts printed: $hosts"
echo "ok   no host"

echo "== 11. an MCP server through the Compose egress overlay"
if [ "${SMOKE_SKIP_COMPOSE:-}" = "1" ]; then
    echo "SKIPPED step 11 was left out by SMOKE_SKIP_COMPOSE=1: the egress overlay was NOT tested"
    echo "smoke: passed, without step 11"
    exit 0
fi
"$RUNTIME" compose version > /dev/null 2>&1 || fail "$RUNTIME compose is not available; step 11 needs it (SMOKE_SKIP_COMPOSE=1 leaves the step out)"

MCP_HOST=mcp.smoke.example
# A range of the documentation's own kind would be refused as public by nothing
# and private by nothing; this one is private, so the proxy must be told it.
MCP_SUBNET="${SMOKE_MCP_SUBNET:-172.31.251.0/24}"
mkdir -m 0700 "$WORK/overlay" "$WORK/overlay-out"
mkdir -m 0755 "$WORK/overlay/tls"
cp "$WORK/init/signing-key.pem" "$WORK/overlay/signing-key.pem"
# Names only: the key reaches the scanner as the Compose secret.
printf '# step 11: no credential besides the signing key\n' > "$WORK/overlay/scanent.env"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
    -subj "/CN=$MCP_HOST" -addext "subjectAltName=DNS:$MCP_HOST" \
    -keyout "$WORK/overlay/tls/key.pem" -out "$WORK/overlay/tls/cert.pem" > /dev/null 2>&1 \
    || fail "openssl could not make the stand-in server's certificate"
cp "$WORK/overlay/tls/cert.pem" "$WORK/overlay/ca.pem"
chmod 0644 "$WORK/overlay/tls/key.pem" "$WORK/overlay/tls/cert.pem"
cat > "$WORK/overlay/config.json" <<JSON
{
  "estate": "smoke-overlay",
  "scanner": { "agentId": "agt_smoke_scanner", "signingKeyEnv": "SCANNER_SIGNING_KEY" },
  "outputs": [{ "kind": "file", "dir": "/out" }],
  "schedule": { "everyHours": 24 },
  "timeBoxSeconds": 30,
  "sources": [
    { "kind": "code", "product": "langchain", "roots": [{ "label": "estate", "path": "/estate" }] },
    { "kind": "mcp", "servers": [{ "label": "smoke", "url": "https://$MCP_HOST/mcp", "agents": ["code:estate/support/agent.py#support_executor"] }] }
  ]
}
JSON
chmod 0600 "$WORK/overlay/config.json" "$WORK/overlay/scanent.env" "$WORK/overlay/signing-key.pem" "$WORK/overlay/ca.pem"
cat > "$WORK/overlay/compose.smoke.yaml" <<YAML
services:
  scanent:
    image: $IMAGE
    environment:
      NODE_EXTRA_CA_CERTS: /etc/scanent/ca.pem
    volumes:
      - $WORK/estate:/estate:ro
  egress-proxy:
    image: $IMAGE
  smoke-mcp:
    image: $IMAGE
    entrypoint: ["node", "/smoke/smoke-mcp-server.js"]
    command: []
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    environment:
      SMOKE_MCP_CERT: /tls/cert.pem
      SMOKE_MCP_KEY: /tls/key.pem
    volumes:
      - $HERE/smoke-mcp-server.js:/smoke/smoke-mcp-server.js:ro
      - $WORK/overlay/tls:/tls:ro
    networks:
      scanent-egress:
        aliases: [$MCP_HOST]
networks:
  scanent-egress:
    ipam:
      config:
        - subnet: $MCP_SUBNET
YAML
COMPOSE_PROJECT="scanent-smoke-$$"
export SCANENT_VERSION=smoke SCANENT_DIR="$WORK/overlay" SCANENT_OUT="$WORK/overlay-out"
SCANENT_UID="$(id -u)"
SCANENT_GID="$(id -g)"
export SCANENT_UID SCANENT_GID
export EGRESS_PRIVATE_CIDR_ALLOWLIST="$MCP_SUBNET"

# The proxy and the stand-in server, with the server's host on the list.
export EGRESS_ALLOW="$MCP_HOST"
compose up -d egress-proxy smoke-mcp > "$WORK/compose-up.log" 2>&1 || { cat "$WORK/compose-up.log" >&2; fail "the overlay did not start"; }
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if compose logs --no-log-prefix smoke-mcp 2> /dev/null | grep -q '^listening 443$' \
        && compose logs --no-log-prefix egress-proxy 2> /dev/null | grep -q '"msg":"egress proxy listening"'; then
        break
    fi
    sleep 0.5
done
compose logs --no-log-prefix smoke-mcp 2> /dev/null | grep -q '^listening 443$' || { compose logs >&2; fail "the stand-in MCP server did not start"; }
compose logs --no-log-prefix egress-proxy 2> /dev/null | grep -q '"msg":"egress proxy listening"' || { compose logs >&2; fail "the egress proxy did not start"; }

overlay_scan() {
    compose run --rm -T scanent scan --dry-run --out /out --config /etc/scanent/config.json > "$1" 2> "$WORK/overlay-scan.log" \
        || { cat "$WORK/overlay-scan.log" >&2; compose logs egress-proxy >&2; fail "the scan through the overlay exited non-zero"; }
}
# The `mcp` source of a signed report on stdin: its status and reason, and the tools the agent holds from that server.
MCP_OF_REPORT='
const signed = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
const body = signed.body ?? signed;
const source = body.population.sources.find((s) => s.kind === "mcp");
const agent = body.agents.find((a) => a.discoveredId === "code:estate/support/agent.py#support_executor");
const tools = agent === undefined ? [] : agent.tools.filter((t) => String(t.server).startsWith("https://mcp.smoke.example/")).map((t) => t.name).sort();
console.log([source === undefined ? "ABSENT" : source.status, (source && source.reason) || "-", tools.join(",") || "-"].join(" "));
'
overlay_scan "$WORK/overlay-allowed.json"
allowed="$(run -i --entrypoint node "$IMAGE" -e "$MCP_OF_REPORT" < "$WORK/overlay-allowed.json")" || fail "the report of the overlay scan could not be read"
[ "$allowed" = "COMPLETE - smoke_close_ticket,smoke_lookup_ticket" ] \
    || { cat "$WORK/overlay-scan.log" >&2; compose logs egress-proxy >&2; fail "through the proxy the mcp source read '$allowed', not COMPLETE with the server's two tools"; }
proxy_log="$(compose logs --no-log-prefix egress-proxy 2> /dev/null)"
printf '%s\n' "$proxy_log" | grep -q "\"msg\":\"egress allowed\",\"host\":\"$MCP_HOST\",\"port\":443" || fail "the proxy logged no allowed tunnel to $MCP_HOST"
if printf '%s\n' "$proxy_log" | grep '"msg":"egress allowed"' | grep -vq "\"host\":\"$MCP_HOST\""; then
    fail "the proxy allowed a tunnel to a host other than $MCP_HOST"
fi
if printf '%s\n' "$proxy_log" | grep -q '"msg":"egress refused"'; then fail "the proxy refused a tunnel while the host was on its list"; fi
# What the server was asked: the three declared messages, and no other.
asked="$(compose logs --no-log-prefix smoke-mcp 2> /dev/null | grep -v '^listening 443$' | sort -u | tr '\n' ';')"
[ "$asked" = "message initialize;message notifications/initialized;message tools/list;" ] || fail "the MCP server was asked: $asked"
echo "ok   through the proxy: the mcp source is COMPLETE with both tools, and the server saw only the three declared messages"

# The scanner's container has no way to the server but the proxy.
mcp_address="$("$RUNTIME" inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$(compose ps -q smoke-mcp)" | tr ' ' '\n' | grep -m1 .)"
[ -n "$mcp_address" ] || fail "the stand-in server's address could not be read"
direct="$(compose run --rm -T --entrypoint node scanent -e '
const net = require("node:net");
const dns = require("node:dns");
const done = (line) => { console.log(line); process.exit(0); };
dns.lookup(process.argv[2], (lookupError) => {
    const socket = net.connect({ host: process.argv[1], port: 443, timeout: 3000 });
    socket.on("connect", () => done("CONNECTED"));
    socket.on("timeout", () => done(`NO_ROUTE name=${lookupError ? "unresolved" : "RESOLVED"}`));
    socket.on("error", () => done(`NO_ROUTE name=${lookupError ? "unresolved" : "RESOLVED"}`));
});
' "$mcp_address" "$MCP_HOST" 2> /dev/null)" || fail "the direct-connection probe did not run"
[ "$direct" = "NO_ROUTE name=unresolved" ] || fail "from the scanner's network, a direct connection to the server gave: $direct"
echo "ok   no route from the scanner to $mcp_address, and no name for it, except through the proxy"

# The host off the list: the proxy refuses, and the source says it could not be reached.
export EGRESS_ALLOW=other.smoke.example
compose up -d egress-proxy > "$WORK/compose-up.log" 2>&1 || { cat "$WORK/compose-up.log" >&2; fail "the proxy did not restart with the new list"; }
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if compose logs --no-log-prefix egress-proxy 2> /dev/null | grep -q '"hosts":"other.smoke.example"'; then break; fi
    sleep 0.5
done
compose logs --no-log-prefix egress-proxy 2> /dev/null | grep -q '"hosts":"other.smoke.example"' || fail "the proxy did not start with the new list"
overlay_scan "$WORK/overlay-refused.json"
refused="$(run -i --entrypoint node "$IMAGE" -e "$MCP_OF_REPORT" < "$WORK/overlay-refused.json")" || fail "the report of the refused scan could not be read"
[ "$refused" = "INCOMPLETE UNREACHABLE -" ] || { cat "$WORK/overlay-scan.log" >&2; fail "with the host off the list the mcp source read '$refused', not INCOMPLETE UNREACHABLE with no tool"; }
proxy_log="$(compose logs --no-log-prefix egress-proxy 2> /dev/null)"
printf '%s\n' "$proxy_log" | grep -q "\"msg\":\"egress refused\",\"reason\":\"HOST_NOT_ALLOWED\",\"host\":\"$MCP_HOST\"" || { printf '%s\n' "$proxy_log" >&2; fail "the proxy did not log the refusal of $MCP_HOST"; }
if printf '%s\n' "$proxy_log" | grep -q '"msg":"egress allowed"'; then fail "the proxy allowed a tunnel with the host off its list"; fi
echo "ok   off the list: the proxy refused $MCP_HOST and the mcp source is INCOMPLETE (UNREACHABLE)"

echo "smoke: passed"
