#!/usr/bin/env bash
# The scanent-probe image's smoke test: what CI runs against the image it has
# just built. It builds nothing, and nothing it runs reaches a network.
#
#   deploy/probe-smoke.sh <image>
#
# Every run of the image has no network, a read-only root filesystem, every
# capability dropped and no privilege gain, as the image's own non-root user;
# one writable mount, /work, holds what a step writes. It checks, in order:
#
#   1. the image runs as a user other than root, carries no shell and no
#      package manager, and holds no TypeScript source of scanent's (nor a
#      declaration file) and no file of the read-only scanner;
#   2. with no arguments it prints its help;
#   3. inside the image: an approver's key and a prober's key are made, a scope
#      naming that prober is signed with `scope sign`, and `scope verify`
#      accepts it;
#   4. `run --dry-run` lists the requests a run would send;
#   5. a real `run`, with no network: every target is NO_REPLY, the report is
#      written, it verifies under the prober's key through the image's own
#      contract module, and its surfaceDigest is the one the image rebuilds
#      from the scope;
#   6. a second `run` to the same --out is refused, and the first report is
#      left as it was.
#
#   CONTAINER_RUNTIME    docker (default) or podman
#
# What is read back from a container is read by the image's own `node`.
set -euo pipefail

IMAGE="${1:?usage: probe-smoke.sh <image>}"
RUNTIME="${CONTAINER_RUNTIME:-docker}"
WORK="$(mktemp -d)"
cleanup() {
    "$RUNTIME" run --rm --network none -v "$WORK:/work" --entrypoint node "$IMAGE" -e 'for (const f of require("node:fs").readdirSync("/work")) require("node:fs").rmSync("/work/" + f, { recursive: true, force: true })' > /dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
    echo "FAIL $*" >&2
    exit 1
}

# The way the prober is to be run, plus whatever a step adds.
run() {
    "$RUNTIME" run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges "$@"
}

# The image's user writes into /work.
chmod 0777 "$WORK"

echo "1. the image's user, and what it does not carry"
run --entrypoint node "$IMAGE" -e '
const fs = require("node:fs");
const path = require("node:path");
if (process.getuid() === 0) { console.error("runs as root"); process.exit(1); }
const names = ["sh", "bash", "ash", "dash", "busybox", "npm", "npx", "corepack", "yarn", "yarnpkg", "apk", "apt", "apt-get", "dpkg"];
for (const dir of (process.env.PATH || "").split(":")) for (const n of names) if (fs.existsSync(path.join(dir, n))) { console.error("carries " + n); process.exit(1); }
const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]));
const files = walk("/app");
// Only the TypeScript source of scanent itself: a dependency as published (zod ships its sources) is left alone.
const own = files.filter((f) => f.startsWith("/app/packages/") || f.startsWith("/app/node_modules/@rodnapamet/"));
if (own.length === 0 || own.some((f) => f.endsWith(".ts"))) { console.error("holds TypeScript source of its own"); process.exit(1); }
if (files.some((f) => f.includes("/packages/scanner/") || f.includes("/packages/report/") || f.includes("/@scanent/report/"))) { console.error("holds a file of the scanner"); process.exit(1); }
if (!files.includes("/app/LICENSE") || !files.includes("/app/NOTICE")) { console.error("no LICENSE or NOTICE"); process.exit(1); }
' || fail "step 1"
if run --entrypoint sh "$IMAGE" -c true > /dev/null 2>&1; then fail "step 1: a shell started inside the image"; fi

echo "2. help"
run "$IMAGE" > "$WORK/help.txt" 2>&1 || true
grep -q 'Nothing is probed without a verified engagement scope' "$WORK/help.txt" || fail "step 2: no help"

echo "3. keys, a signed scope, and its verification"
run -v "$WORK:/work" --entrypoint node "$IMAGE" -e '
const { generateKeyPairSync } = require("node:crypto");
const fs = require("node:fs");
const raw = (k) => k.export({ format: "der", type: "spki" }).subarray(12).toString("hex");
for (const who of ["approver", "prober"]) {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    fs.writeFileSync(`/work/${who}.pem`, privateKey.export({ format: "pem", type: "pkcs8" }));
    fs.writeFileSync(`/work/${who}.hex`, raw(publicKey));
}
const now = Date.now();
fs.writeFileSync("/work/scope.json", JSON.stringify({
    contract: "scanent-engagement-scope/1",
    engagementId: "smoke-engagement-1",
    targets: [
        { kind: "mcp", endpoint: "https://mcp.smoke.invalid/mcp", tools: [{ name: "search_orders", argument: "query" }] },
        { kind: "a2a", endpoint: "https://a2a.smoke.invalid/tasks" },
        { kind: "http-chat", endpoint: "https://chat.smoke.invalid/api/turn", request: { body: { messages: [{ role: "user", content: "{{probe}}" }] }, replyPath: ["reply"] } },
    ],
    window: { start: new Date(now - 3600000).toISOString(), end: new Date(now + 3600000).toISOString() },
    classes: ["canary", "disclosure"],
    approver: { name: "Smoke Approver", role: "Test" },
    killContact: "nobody, this is a smoke test",
    ratePerMinute: 120,
    proberKey: fs.readFileSync("/work/prober.hex", "utf8"),
}));
' || fail "step 3: keys and scope"
APPROVER="$(cat "$WORK/approver.hex")"
PROBER="$(cat "$WORK/prober.hex")"
run -v "$WORK:/work" "$IMAGE" scope sign --key /work/approver.pem --in /work/scope.json --out /work/scope.signed.json > /dev/null || fail "step 3: scope sign"
run -v "$WORK:/work" "$IMAGE" scope verify --scope /work/scope.signed.json --trusted-key "$APPROVER" --prober-key "$PROBER" > "$WORK/verify.txt" || fail "step 3: scope verify"
grep -q '^scope: verified$' "$WORK/verify.txt" || fail "step 3: not verified"

echo "4. a dry run"
run -v "$WORK:/work" "$IMAGE" run --dry-run --scope /work/scope.signed.json --trusted-key "$APPROVER" --prober-key "$PROBER" > "$WORK/dry.txt" || fail "step 4"
grep -q '^dry run: [0-9]* requests, none sent$' "$WORK/dry.txt" || fail "step 4: no plan"
grep -q 'tool search_orders' "$WORK/dry.txt" || fail "step 4: no MCP tool in the plan"

echo "5. a run with no network, and its report"
run -v "$WORK:/work" -e PROBER_KEY_FILE=/work/prober.pem "$IMAGE" \
    run --scope /work/scope.signed.json --trusted-key "$APPROVER" --signing-key-env PROBER_KEY --out /work/report.json > "$WORK/run.txt" \
    || fail "step 5: run"
grep -q '^report: written$' "$WORK/run.txt" || fail "step 5: no report"
[ "$(grep -c '  NO_REPLY  (UNREACHABLE)$' "$WORK/run.txt")" = "3" ] || fail "step 5: a target was not NO_REPLY (UNREACHABLE)"
run -v "$WORK:/work" --entrypoint node "$IMAGE" -e '
const fs = require("node:fs");
const { verifyAndParseProbesReport, probeReportConcluded } = require("/app/node_modules/@rodnapamet/scanent-contract/dist/probes-contract.js");
const { verifyEngagementScope } = require("/app/packages/probe/dist/scope.js");
const { probeSurface, surfaceDigest } = require("/app/packages/probe/dist/surface.js");
const prober = fs.readFileSync("/work/prober.hex", "utf8");
const read = verifyAndParseProbesReport(fs.readFileSync("/work/report.json", "utf8"), [prober]);
if (!read.ok) { console.error("the report does not verify: " + read.reason); process.exit(1); }
const scope = verifyEngagementScope(fs.readFileSync("/work/scope.signed.json", "utf8"), { trustedScopeKeys: [fs.readFileSync("/work/approver.hex", "utf8")], proberKey: prober });
if (!scope.ok) { console.error("the scope does not verify"); process.exit(1); }
if (read.body.run.surfaceDigest !== surfaceDigest(probeSurface(scope.scope))) { console.error("the surface digest is not the one the scope gives"); process.exit(1); }
if (read.body.engagement.scopeDigest !== scope.digest) { console.error("the scope digest differs"); process.exit(1); }
if (probeReportConcluded(read.body)) { console.error("a run that reached nothing concluded something"); process.exit(1); }
if (!read.body.targets.every((t) => t.reason === "NO_REPLY")) { console.error("a target was reached with no network"); process.exit(1); }
' || fail "step 5: the report"

echo "6. a second run to the same report is refused"
BEFORE="$(sha256sum "$WORK/report.json")"
if run -v "$WORK:/work" -e PROBER_KEY_FILE=/work/prober.pem "$IMAGE" \
    run --scope /work/scope.signed.json --trusted-key "$APPROVER" --signing-key-env PROBER_KEY --out /work/report.json > /dev/null 2>&1; then
    fail "step 6: the report was overwritten"
fi
[ "$(sha256sum "$WORK/report.json")" = "$BEFORE" ] || fail "step 6: the first report changed"

echo "probe smoke: passed"
