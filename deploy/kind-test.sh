#!/usr/bin/env bash
# Installs the chart into a cluster and runs one scan there. CI runs it against
# a kind cluster it has just made (the `chart-install` job); anyone can run it
# against a throwaway cluster of their own.
#
#   deploy/kind-test.sh <image-repository> <image-tag>
#
# The image must already be in the cluster's nodes (`kind load docker-image`)
# and in the local Docker store: nothing is pulled and nothing is pushed. It
# uses `kubectl` (the current context), `helm`, `docker` and `jq`.
#
# It checks, in order:
#
#   1. a Secret holding a signing key made by `scanent keygen`, a claim holding
#      one agent's code, and `helm install` with the code-only values;
#   2. a Job made from the chart's CronJob completes, and its log says a report
#      was signed;
#   3. the pod ran non-root with a read-only root, no added capability and no
#      privilege gain, and did not restart;
#   4. the run on the output volume, read through a second pod: six files,
#      owned by uid 1000, a results file of this version's schema, one agent;
#   5. the NetworkPolicy, when the cluster's network plugin enforces policy: a
#      pod carrying the scanner's labels cannot open a connection to a private
#      address, and a pod without them can. When the unlabelled pod cannot
#      connect either, the probe proves nothing and the script fails.
#
#   KEEP=1                       leave the namespace in place afterwards
#   NETWORK_POLICY=not-enforced  the cluster's plugin does not enforce policy:
#                                step 5 is left out, and that is printed
set -euo pipefail

REPOSITORY="${1:?usage: kind-test.sh <image-repository> <image-tag>}"
TAG="${2:?usage: kind-test.sh <image-repository> <image-tag>}"
IMAGE="$REPOSITORY:$TAG"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART="$HERE/helm/scanent"
NS="scanent-test-$$"
WORK="$(mktemp -d)"

fail() {
    echo "FAIL $*" >&2
    echo "--- pods" >&2
    kubectl -n "$NS" get pods -o wide >&2 || true
    echo "--- events" >&2
    kubectl -n "$NS" get events --sort-by=.lastTimestamp >&2 || true
    exit 1
}
cleanup() {
    if [ "${KEEP:-}" != "1" ]; then
        kubectl delete namespace "$NS" --wait=false > /dev/null 2>&1 || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

# One pod that runs the image's node on a script, to completion; its log is the answer.
#   node_pod <name> <labels-yaml-or-empty> <volume-claim-or-empty> <script>
node_pod() {
    local name="$1" labels="$2" claim="$3" script="$4"
    local volumes="" mounts=""
    if [ -n "$claim" ]; then
        volumes="  volumes:
    - name: data
      persistentVolumeClaim:
        claimName: ${claim%%:*}"
        mounts="      volumeMounts:
        - name: data
          mountPath: ${claim#*:}"
    fi
    # The script is written into the manifest as a JSON string, which YAML reads as it is.
    kubectl -n "$NS" apply -f - > /dev/null <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: $name
  labels:
    scanent-test: probe
$labels
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
  containers:
    - name: node
      image: $IMAGE
      imagePullPolicy: Never
      command: ["node", "-e", $(printf '%s' "$script" | jq -Rs .)]
      securityContext:
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
        capabilities:
          drop: [ALL]
$mounts
$volumes
YAML
    local phase=""
    for _ in $(seq 1 90); do
        phase="$(kubectl -n "$NS" get pod "$name" -o jsonpath='{.status.phase}' 2> /dev/null || true)"
        if [ "$phase" = "Succeeded" ] || [ "$phase" = "Failed" ]; then break; fi
        sleep 2
    done
    [ "$phase" = "Succeeded" ] || { kubectl -n "$NS" logs "$name" >&2 || true; fail "the pod $name ended as '$phase', not Succeeded"; }
    kubectl -n "$NS" logs "$name"
}

echo "== 1. the namespace, the signing key, the code, and helm install"
kubectl create namespace "$NS" > /dev/null
mkdir -m 0700 "$WORK/key"
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
    --user "$(id -u):$(id -g)" -v "$WORK/key:/key" "$IMAGE" keygen --out /key/signing-key.pem > "$WORK/public-key" 2> /dev/null \
    || fail "scanent keygen did not write a signing key"
grep -Eq '^[0-9a-f]{64}$' "$WORK/public-key" || fail "keygen did not print a public key"
kubectl -n "$NS" create secret generic scanent-credentials --from-file=signing-key.pem="$WORK/key/signing-key.pem" > /dev/null
rm -f "$WORK/key/signing-key.pem"

kubectl -n "$NS" apply -f - > /dev/null <<'YAML'
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: agents-code
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 16Mi
YAML
# The estate: one LangChain agent, written by the image's own node.
SEED='
const fs = require("node:fs");
fs.mkdirSync("/estate/support", { recursive: true });
fs.writeFileSync("/estate/support/agent.py", [
    "import os",
    "from langchain.agents import AgentExecutor, create_tool_calling_agent",
    "from langchain_core.prompts import ChatPromptTemplate",
    "from langchain_core.tools import tool",
    "from langchain_openai import ChatOpenAI",
    "",
    "@tool",
    "def lookup_order(order_id: str) -> str:",
    "    \"\"\"Look an order up by its id.\"\"\"",
    "    return order_id",
    "",
    "llm = ChatOpenAI(model=\"gpt-4o-mini\", api_key=os.environ[\"SUPPORT_OPENAI_KEY\"])",
    "tools = [lookup_order]",
    "prompt = ChatPromptTemplate.from_messages([(\"system\", \"You are a support agent.\"), (\"human\", \"{input}\")])",
    "agent = create_tool_calling_agent(llm, tools, prompt)",
    "support_executor = AgentExecutor(agent=agent, tools=tools)",
    "",
].join("\n"));
console.log("seeded");
'
[ "$(node_pod seed-code "" "agents-code:/estate" "$SEED")" = "seeded" ] || fail "the code volume was not written"
kubectl -n "$NS" delete pod seed-code --wait=true > /dev/null

helm install scanent "$CHART" --namespace "$NS" -f "$CHART/ci/base-values.yaml" \
    --set image.repository="$REPOSITORY" --set image.tag="$TAG" --set image.pullPolicy=Never --set strict=true \
    > "$WORK/helm.log" 2>&1 || { cat "$WORK/helm.log" >&2; fail "helm install failed"; }
echo "ok   installed"

echo "== 2. one scan, as a Job made from the CronJob"
kubectl -n "$NS" create job scan-now --from=cronjob/scanent > /dev/null
if ! kubectl -n "$NS" wait --for=condition=complete job/scan-now --timeout=240s > /dev/null 2>&1; then
    kubectl -n "$NS" logs job/scan-now >&2 || true
    kubectl -n "$NS" describe job/scan-now >&2 || true
    fail "the scan did not complete"
fi
kubectl -n "$NS" logs job/scan-now > "$WORK/scan.log" 2>&1
grep -q '"msg":"report signed"' "$WORK/scan.log" || { cat "$WORK/scan.log" >&2; fail "the scan's log does not say a report was signed"; }
grep -q '"msg":"results written"' "$WORK/scan.log" || { cat "$WORK/scan.log" >&2; fail "the scan's log does not say results were written"; }
echo "ok   the Job completed and signed a report"

echo "== 3. how the pod ran"
kubectl -n "$NS" get pods -l job-name=scan-now -o json > "$WORK/pods.json"
jq -e '
    (.items | length) == 1
    and (.items[0].status.phase == "Succeeded")
    and (.items[0].spec.securityContext.runAsNonRoot == true)
    and (.items[0].spec.securityContext.runAsUser == 1000)
    and (.items[0].spec.automountServiceAccountToken == false)
    and ([.items[0].spec.containers[].securityContext
          | (.readOnlyRootFilesystem == true and .allowPrivilegeEscalation == false and (.privileged // false) == false and .capabilities.drop == ["ALL"] and (.capabilities.add // []) == [])]
         | all)
    and ([.items[0].status.containerStatuses[].restartCount] | add) == 0
    and ([.items[0].spec.containers[] | has("command")] | any | not)
' "$WORK/pods.json" > /dev/null || { jq '.items[0] | {spec: .spec.securityContext, containers: [.spec.containers[].securityContext], status: .status.containerStatuses}' "$WORK/pods.json" >&2; fail "the pod did not run as the chart says it does"; }
echo "ok   one pod, non-root, read-only root, nothing added, no restart, the image's own entrypoint"

echo "== 4. the run on the output volume, read through a second pod"
READ='
const fs = require("node:fs");
const latest = JSON.parse(fs.readFileSync("/out/latest.json", "utf8"));
const dir = "/out/" + latest.dir;
const results = JSON.parse(fs.readFileSync(dir + "/results.json", "utf8"));
console.log(JSON.stringify({
    files: fs.readdirSync(dir).sort(),
    owners: [...new Set(fs.readdirSync(dir).map((f) => fs.statSync(dir + "/" + f).uid))],
    schema: results.schema,
    agents: results.estate.agentCount,
    complete: latest.complete,
    runs: fs.readdirSync("/out/runs").length,
}));
'
node_pod read-out "" "scanent-out:/out" "$READ" > "$WORK/out.json"
jq -e '
    .files == ["agents.csv", "findings.csv", "manifest.json", "report.pdf", "report.signed.json", "results.json", "summary.html"]
    and .owners == [1000]
    and .schema == "scanent-results/1"
    and .agents == 1
    and .runs == 1
' "$WORK/out.json" > /dev/null || { cat "$WORK/out.json" >&2; fail "the run on the output volume is not what one scan of one agent writes"; }
echo "ok   $(cat "$WORK/out.json")"

echo "== 5. the NetworkPolicy"
if [ "${NETWORK_POLICY:-}" = "not-enforced" ]; then
    echo "SKIPPED the NetworkPolicy was NOT tested: NETWORK_POLICY=not-enforced says this cluster does not enforce policy"
else
    # A private address every pod can normally reach: the API server's Service.
    api="$(kubectl -n default get service kubernetes -o jsonpath='{.spec.clusterIP}')"
    [ -n "$api" ] || fail "the API server's Service address could not be read"
    # It waits before it connects: a policy takes a moment to reach a new pod,
    # and a connection made before it did would read as "not enforced".
    PROBE="
const done = (line) => { console.log(line); process.exit(0); };
setTimeout(() => {
    const socket = require('node:net').connect({ host: '$api', port: 443, timeout: 5000 });
    socket.on('connect', () => done('CONNECTED'));
    socket.on('timeout', () => done('BLOCKED'));
    socket.on('error', () => done('BLOCKED'));
}, 10000);
"
    open="$(node_pod probe-unlabelled "" "" "$PROBE")"
    [ "$open" = "CONNECTED" ] || fail "a pod with no policy could not reach $api:443 either ($open), so the probe proves nothing"
    scanner_labels="    app.kubernetes.io/name: scanent
    app.kubernetes.io/instance: scanent
    app.kubernetes.io/component: scanner"
    closed="$(node_pod probe-as-scanner "$scanner_labels" "" "$PROBE")"
    [ "$closed" = "BLOCKED" ] || fail "a pod carrying the scanner's labels reached the private address $api:443: the NetworkPolicy is not enforced here"
    echo "ok   a pod with the scanner's labels cannot reach $api:443; a pod without them can"
fi

echo "kind-test: passed"
