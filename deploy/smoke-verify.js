/**
 * The scanent image's smoke check, run INSIDE the image by `smoke.sh`.
 *
 * It takes what the image's dry run printed, on stdin — two signed reports,
 * one per line: the agent report, then the agent-rules report — and the public
 * key the image's `public-key` command printed, as its argument, and verifies
 * each through the other with the contract module the image itself ships: the
 * same `verifyAndParseHarnessReport` and `verifyAndParseAgentRulesReport` a
 * receiver runs. So a pass says the image signs reports a receiver would
 * accept, from a key it would register, and that what it read of the smoke
 * estate is in them: both agents, and the one skill with its script, read in
 * full by the agent-surface rules, which raised the one finding it plants.
 *
 * Prints one line per check and exits 1 when any fails. Not part of the image:
 * `smoke.sh` mounts it read-only at /app/smoke-verify.js for the one run, so
 * the two requires below resolve against the image's own files. Plain
 * JavaScript, because the image holds nothing that could compile it.
 */
const { readFileSync } = require('node:fs');

const { HARNESS_CONTRACT_V4, verifyAndParseHarnessReport } = require('@rodnapamet/scanent-contract/harness-contract');
const { AGENT_RULES_CONTRACT_V1, verifyAndParseAgentRulesReport } = require('@rodnapamet/scanent-contract/agent-rules-contract');
const { SCANNER_VERSION, scannerManifestHash } = require('./packages/scanner/dist/scanner-surface.js');

/** The agents `smoke.sh`'s estate defines, by the id the `code` source gives each, and a tool each binds. */
const EXPECTED_AGENTS = [
    ['code:estate/research/agent.ts#researchExecutor', 'search_papers'],
    ['code:estate/support/agent.py#support_executor', 'lookup_order'],
];

const results = [];
const check = (ok, what) => {
    results.push([ok, what]);
};

const [publicKeyHex] = process.argv.slice(2);
const lines = readFileSync(0, 'utf8').split('\n').filter((l) => l.length > 0);
check(lines.length === 2, `the dry run printed two reports (it printed ${lines.length} lines)`);
const [raw = '', rulesRaw = ''] = lines;
const parsed = verifyAndParseHarnessReport(raw, publicKeyHex ? [publicKeyHex] : []);

check(parsed.ok, `the report verifies against the printed key${parsed.ok ? '' : ` (refused: ${parsed.reason})`}`);
if (parsed.ok) {
    const { body } = parsed;
    check(body.contract === HARNESS_CONTRACT_V4, `it speaks ${HARNESS_CONTRACT_V4}`);
    check(body.scan.scanner.version === SCANNER_VERSION, `it names scanner version ${SCANNER_VERSION}`);
    check(body.scan.scanner.manifestHash === scannerManifestHash(), 'it carries the scanner surface hash');
    check(
        body.population.sources.length === 1 &&
            body.population.sources[0].kind === 'code' &&
            body.population.sources[0].status === 'COMPLETE',
        'its one source, code, was read in full',
    );
    check(parsed.complete, 'the receiver would read it as a complete scan');
    for (const [discoveredId, tool] of EXPECTED_AGENTS) {
        const agent = body.agents.find((a) => a.discoveredId === discoveredId);
        check(agent !== undefined, `it reports ${discoveredId}`);
        check(agent !== undefined && agent.tools.some((t) => t.name === tool), `${discoveredId} binds ${tool}`);
    }
    check(body.agents.length === EXPECTED_AGENTS.length, `it reports ${EXPECTED_AGENTS.length} agents and no others`);
}

const rules = verifyAndParseAgentRulesReport(rulesRaw, publicKeyHex ? [publicKeyHex] : []);
check(rules.ok, `the agent-rules report verifies against the printed key${rules.ok ? '' : ` (refused: ${rules.reason})`}`);
if (rules.ok) {
    const { body } = rules;
    check(body.contract === AGENT_RULES_CONTRACT_V1, `it speaks ${AGENT_RULES_CONTRACT_V1}`);
    check(parsed.ok && body.scan.id === parsed.body.scan.id, 'it names the agent report\'s scan');
    check(rules.complete, 'the receiver would read it as a complete read');
    const kinds = body.population.map((p) => `${p.kind} ${p.status} ${p.subjects}`).join(', ');
    check(kinds === 'skill COMPLETE 1, skill-file COMPLETE 1', `it read the one skill and its script in full (${kinds})`);
    check(body.origins.length === 1 && body.origins[0].ref === 'code:estate' && body.origins[0].status === 'COMPLETE', 'its one origin is the code root, read in full');
    const fired = body.findings.map((f) => `${f.ruleId} ${f.locator}`).join(', ');
    check(
        fired === 'atr:2026-00123.unrestricted-shell skill:code:estate/support/skills/order-notes/SKILL.md#frontMatter',
        `it raised the one finding the skill plants, on its front matter (${fired || 'none'})`,
    );
}

for (const [ok, what] of results) process.stdout.write(`${ok ? 'ok  ' : 'FAIL'} ${what}\n`);
process.exit(results.every(([ok]) => ok) ? 0 : 1);
