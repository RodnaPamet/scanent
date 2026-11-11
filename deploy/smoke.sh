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
#      files, and a second run leaves the first run's files as they were.
#
# The estate is written here rather than committed: a committed `.ts` fixture
# would be type-checked and linted as this repository's own code.
set -euo pipefail

IMAGE="${1:?usage: smoke.sh <image>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
# The runs of step 6 are written by the image's user, in directories this user
# may not be able to enter, so they are removed the way they were made.
cleanup() {
    if [ -d "$WORK/out" ]; then
        docker run --rm --network none -v "$WORK/out:/out" --entrypoint sh "$IMAGE" -c 'rm -rf /out/runs /out/latest.json' > /dev/null 2>&1 || true
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
    docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges "$@"
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

echo "smoke: passed"
