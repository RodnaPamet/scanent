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
#   1. the image runs as a user other than root, carries no npm, npx, corepack
#      or yarn, and holds no TypeScript source and no run-time compiler;
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
#   7. run as the invoking user (`--user`, or `--userns=keep-id` under Podman)
#      into an output directory that user owns with mode 0700, a scan writes
#      runs the invoking user can read without the container: the run
#      directory 0750, its files 0640, all owned by that user;
#   8. the signing key given only as a mounted file (mode 0444) named by
#      SCANNER_SIGNING_KEY_FILE: `public-key` prints the same key;
#   9. `init --answers` writes a configuration, an env template and a signing
#      key into a writable mount, and `doctor --json` on what it wrote exits 0
#      or 3 with no failed check;
#  10. `hosts` on a code-only configuration prints nothing and exits 0.
#
#   CONTAINER_RUNTIME   docker (default) or podman
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
    if [ -d "$WORK/out" ]; then
        "$RUNTIME" run --rm --network none -v "$WORK/out:/out" --entrypoint sh "$IMAGE" -c 'rm -rf /out/runs /out/latest.json' > /dev/null 2>&1 || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
    echo "FAIL $*" >&2
    exit 1
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
uid="$(run --entrypoint id "$IMAGE" -u)"
[ "$uid" != "0" ] || fail "the image runs as root"
echo "ok   runs as uid $uid"
run --entrypoint sh "$IMAGE" -c '! command -v npm && ! command -v npx && ! command -v corepack && ! command -v yarn' \
    || fail "the image carries a package manager"
echo "ok   no npm, npx, corepack or yarn"
# Compiled JavaScript only: no TypeScript source of its own, and neither of the
# two packages that would compile it at start.
run --entrypoint sh "$IMAGE" -c '[ -z "$(find /app/packages -name "*.ts" -not -path "*/node_modules/*")" ] && [ ! -e /app/node_modules/tsx ] && [ ! -e /app/node_modules/esbuild ]' \
    || fail "the image holds TypeScript source, tsx or esbuild"
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
inspect() {
    run "${OUT[@]}" --entrypoint sh "$IMAGE" -c "$1"
}
scan_out
first="$(inspect 'ls /out/runs')"
[ "$(printf '%s\n' "$first" | wc -l)" -eq 1 ] || fail "one run should have written one directory, found: $first"
[[ "$first" =~ ^smoke-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$ ]] || fail "the run directory is not named by a scan id: $first"
files="$(inspect "ls /out/runs/$first" | sort | tr '\n' ' ')"
[ "$files" = "agents.csv findings.csv manifest.json report.signed.json results.json summary.html " ] \
    || fail "the run holds '$files', not the six files"
inspect 'test -f /out/latest.json' || fail "no latest.json pointer was written"
before="$(inspect "cd /out/runs/$first && sha256sum ./*")"
echo "ok   six files in runs/$first"
scan_out
[ "$(inspect 'ls /out/runs | wc -l')" -eq 2 ] || fail "a second run should add a second directory"
after="$(inspect "cd /out/runs/$first && sha256sum ./*")"
[ "$before" = "$after" ] || fail "the second run changed the first run's files"
echo "ok   a second run left the first as it was"

echo "== 7. scan --out as the invoking user, into a directory only that user can enter"
# The way the quick start says to run it: the scanner is the person running it,
# so the runs are theirs to read, and the directory needs no opening up.
if [ "$RUNTIME" = "podman" ]; then
    AS_ME=(--userns=keep-id)
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

echo "smoke: passed"
