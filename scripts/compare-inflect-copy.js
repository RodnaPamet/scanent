#!/usr/bin/env node
// Compares this repository's contract and scanner with the copy the Inflect
// Compliance repository still carries, and prints the CODE lines that exist
// only on Inflect's side.
//
//   node scripts/compare-inflect-copy.js <path to the Inflect repository> [--ref <git ref>] [--worktree] [--verbose]
//
// By default the Inflect side is read at `origin/main` through `git show`,
// because a local working tree may be behind. `--ref` names another ref;
// `--worktree` reads the files on disk instead. `--verbose` prints each line
// a listed exception covers, not only how many.
//
// What is compared (docs/EXTRACTION.md, "File mapping"):
//
//   • the eight contract files: src/lib/agentic/{harness-contract,
//     harness-contract-rules, harness-findings, harness-ladder}.ts,
//     src/lib/canonical-json.ts, src/lib/security/cidr.ts,
//     src/lib/mcp/receipt-verification.ts and src/lib/audit-redact.ts, against
//     packages/contract/src;
//   • every file under packages/agent-harness-scanner/src, against the file at
//     the same relative path under packages/scanner/src.
//
// What is ignored: blank lines, comment-only lines (and comment blocks), a
// trailing `//` comment, runs of whitespace, and the difference between the
// two repositories' import specifiers (an application alias there, the
// package name or a relative path here: each is reduced to the module's last
// path segment). A line is "Inflect-only" when it occurs more often in the
// Inflect file than in its counterpart here, so a line that moved within a
// file is not reported.
//
// Lines listed in EXCEPTIONS below are deliberate differences: they are
// counted apart, with the reason, and do not fail the run. An exception line
// that no longer occurs on Inflect's side is reported as stale, so the list
// cannot outlive what it explains. The exit code is 0 when nothing else is
// Inflect-only and no exception is stale, 1 otherwise, 2 on a usage error.
// Read-only: it runs `git show` and `git ls-tree` in the Inflect repository
// and reads files in both, and writes nothing.
'use strict';

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

const CONTRACT_FILES = [
    ['src/lib/agentic/harness-contract.ts', 'packages/contract/src/harness-contract.ts'],
    ['src/lib/agentic/harness-contract-rules.ts', 'packages/contract/src/harness-contract-rules.ts'],
    ['src/lib/agentic/harness-findings.ts', 'packages/contract/src/harness-findings.ts'],
    ['src/lib/agentic/harness-ladder.ts', 'packages/contract/src/harness-ladder.ts'],
    ['src/lib/canonical-json.ts', 'packages/contract/src/canonical-json.ts'],
    ['src/lib/security/cidr.ts', 'packages/contract/src/cidr.ts'],
    ['src/lib/mcp/receipt-verification.ts', 'packages/contract/src/receipt-verification.ts'],
    ['src/lib/audit-redact.ts', 'packages/contract/src/audit-redact.ts'],
];
const SCANNER_ROOT_THERE = 'packages/agent-harness-scanner/src';
const SCANNER_ROOT_HERE = 'packages/scanner/src';

/**
 * Deliberate differences: lines Inflect has and scanent does not, because
 * scanent replaced them with its own (a hardening, a rename, a wider type).
 * Each entry names the Inflect file, the normalised lines exactly as this
 * script prints them, and why. A line is matched exactly, so a new Inflect
 * line in the same file is still reported. Nothing contract-level is Inflect
 * behaviour scanent lacks: the three contract entries are a type spelled as
 * an array, a parameter widened to unknown, and a fix scanent made.
 */
const EXCEPTIONS = [
    {
        file: "src/lib/agentic/harness-contract.ts",
        reason: "scanent declares the refusal codes as the HARNESS_REFUSALS array, in the order the verifier checks them, and derives HarnessRefusal from it: the same eight codes, which docs/contract.md is held to.",
        lines: [
            "export type HarnessRefusal =",
            "| 'TOO_LARGE'",
            "| 'NOT_JSON'",
            "| 'NOT_AN_OBJECT'",
            "| 'UNSIGNED'",
            "| 'MALFORMED_SIGNATURE'",
            "| 'UNTRUSTED_SIGNER'",
            "| 'BAD_SIGNATURE'",
            "| 'SCHEMA';",
        ],
    },
    {
        file: "src/lib/agentic/harness-findings.ts",
        reason: "scanent's firstSecretShapedMember takes unknown rather than a report body, because local results, inventories and diff inputs are walked by it too. Both are the same wrapper over firstSecretShapedPath.",
        lines: [
            "export function firstSecretShapedMember(body: HarnessReportBody): string | null {",
        ],
    },
    {
        file: "src/lib/security/cidr.ts",
        reason: "scanent's fix: an IPv6 address with more than eight groups around '::' is not an address (null), where this line throws on Array(negative).",
        lines: [
            "? [...head, ...Array(8 - head.length - tail.length).fill('0'), ...tail]",
        ],
    },
    {
        file: "packages/agent-harness-scanner/src/cli.ts",
        reason: "scanent's command line is its own (init, keygen, doctor, hosts, diff, support-bundle, exit codes, secrets from files) behind an exported run(); Inflect's three-command main is replaced, not missing.",
        lines: [
            "import { readFileSync } from 'fs';",
            "import { parseScannerConfig } from 'config';",
            "import { rawPublicKeyHex } from 'report';",
            "import { loadSigningKey, runScan, scanAndPost } from 'scan';",
            "export async function main(argv: readonly string[], env: NodeJS.ProcessEnv): Promise<number> {",
            "process.stderr.write('usage: agent-harness-scanner <scan|schedule|public-key> --config <file> [--dry-run]\\n');",
            "const config = parseScannerConfig(JSON.parse(readFileSync(file, 'utf8')) as unknown);",
            "const pem = env[config.scanner.signingKeyEnv];",
            "process.stdout.write(`${rawPublicKeyHex(loadSigningKey(pem).publicKey)}\\n`);",
            "if (argv.includes('--dry-run')) {",
            "const { raw } = await runScan({ config, env, log });",
            "process.stdout.write(`${raw}\\n`);",
            "return (await scanAndPost({ config, env, log })).ok ? 0 : 1;",
            "case 'schedule':",
            "await scanAndPost({ config, env, log });",
            "default:",
            "if (require.main === module) {",
            "process.exit(1);",
        ],
    },
    {
        file: "packages/agent-harness-scanner/src/config.ts",
        reason: "scanent exports its configuration walker, which also refuses a secret-shaped member name, and makes the ingest block optional (outputs), so its key is named only when configured.",
        lines: [
            "function firstSecretShaped(node: unknown, path: string): string | null {",
            "return [config.scanner.signingKeyEnv, config.inflect.apiKeyEnv, ...fromSources];",
        ],
    },
    {
        file: "packages/agent-harness-scanner/src/customer-host.ts",
        reason: "scanent's address check also reads an IPv4 address carried inside an IPv6 one (mapped, compatible, NAT64, 6to4) and refuses more never-public ranges; it covers what these lines check.",
        lines: [
            "].map((c) => {",
            "if (isNeverAllowlistable(address)) return false;",
            "if (!isPrivateAddress(address)) return true;",
            "return allowlist.length > 0 && inAny(address, allowlist);",
            "const host = new URL(origin).hostname.toLowerCase();",
            "if (allowlist.length === 0 && (host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.localhost'))) {",
            "return 'is a private, loopback or link-local address outside the allowlist';",
        ],
    },
    {
        file: "packages/agent-harness-scanner/src/egress-proxy.ts",
        reason: "scanent's proxy resolves an allowed name, checks the address and dials that address, with a connection cap and an idle timeout, in place of dialling the name.",
        lines: [
            "const dial = opts.dial ?? ((host: string, port: number) => connect({ host, port }));",
            "const upstream = dial(decision.host, decision.port);",
            "createEgressProxy({ allow, log }).listen(EGRESS_PROXY_LISTEN_PORT, () => {",
        ],
    },
    {
        file: "packages/agent-harness-scanner/src/http.ts",
        reason: "scanent's SourceReadError also carries the HTTP status (doctor reads it), and the client-credentials grant is a named constant the surface declares. Same requests, same reasons.",
        lines: [
            "throw new SourceReadError(reasonForStatus(res.status), `the source answered HTTP ${res.status}`);",
            "throw new SourceReadError(reason, `the token endpoint answered HTTP ${res.status}`);",
            "new URLSearchParams({ grant_type: 'client_credentials', client_id: clientId, client_secret: clientSecret, scope }),",
            "throw new SourceReadError(reasonForStatus(res.status), `the MCP server answered HTTP ${res.status}`);",
            "if ('error' in answer) throw new SourceReadError('UNREACHABLE', `the MCP server refused ${method}`);",
            "throw new SourceReadError(reason, `the token exchange answered HTTP ${res.status}`);",
        ],
    },
    {
        file: "packages/agent-harness-scanner/src/index.ts",
        reason: "scanent's package index exports more (outputs, local results, init, doctor and others); every name on these lines is still exported, on wrapped lines.",
        lines: [
            "export { parseScannerConfig, ScannerConfigSchema, ConfigError, credentialEnvNames, sourceCredentialEnv, type ScannerConfig } from 'config';",
            "export { buildSources, loadSigningKey, runScan, scanAndPost, type Env, type ScanDeps } from 'scan';",
        ],
    },
    {
        file: "packages/agent-harness-scanner/src/report.ts",
        reason: "scanent keeps a '<key>:*' tool's whole MCP endpoint in memory to match it to the mcp source (never reported), and refuses to sign a report over MAX_REPORT_BYTES. Same steps.",
        lines: [
            "tools: Map<string, { tool: ObservedTool; via: SourceKind }>;",
            "for (const { tool } of o.tools ?? []) if (!agent.tools.has(toolKey(tool))) agent.tools.set(toolKey(tool), { tool, via: read.kind });",
            "for (const [key, { tool }] of [...agent.tools]) {",
            "const server = served.get(endpointKey(tool.server));",
            "return JSON.stringify({ ...wireBody, signature });",
        ],
    },
    {
        file: "packages/agent-harness-scanner/src/scan.ts",
        reason: "scanent's scan also returns each source's notes for local results, and posts through outputs, where the ingest is one optional output (ingestTarget). Same reads, same signing.",
        lines: [
            "import { sourceCredentialEnv, type ScannerConfig } from 'config';",
            "import type { ResolveHost } from 'customer-host';",
            "import { sourceResult, SourceReadError, toolCallsOf, type HarnessSource, type SourceRead } from 'source';",
            "seams: { readonly resolveHost?: ResolveHost; readonly egressProof?: EgressProof } = {},",
            "const apiKey = env[config.inflect.apiKeyEnv];",
            "if (typeof apiKey !== 'string' || apiKey.trim() === '') {",
            "baseUrl: config.inflect.baseUrl,",
            "tenantSlug: config.inflect.tenantSlug,",
            "export async function runScan(deps: ScanDeps): Promise<{ raw: string; body: HarnessReportBodyV4 }> {",
            "const keys = loadSigningKey(requiredEnv(env, config.scanner.signingKeyEnv, 'the signing key'));",
            "const egressProof = config.egress",
            "const { sources, unreadable } = buildSources(config, env, { resolveHost: deps.resolveHost, egressProof });",
            "log.warn('source incomplete', { ...fields, reason: r.reason ?? null });",
            "const listed = (r.notRead ?? []).length;",
            "if ((r.notReadTotal ?? 0) > listed) log.warn('not read: more places than are listed', { source: r.kind, listed, total: r.notReadTotal ?? 0 });",
            "return { raw, body };",
            "const apiKey = requiredEnv(deps.env, deps.config.inflect.apiKeyEnv, 'the ingest API key');",
            "const { raw, body } = await runScan(deps);",
            "baseUrl: deps.config.inflect.baseUrl,",
            "tenantSlug: deps.config.inflect.tenantSlug,",
            "apiKey,",
            "raw,",
            "deps.log.info('report ingested', { scan: body.scan.id, complete: result.complete, agents: result.agentCount });",
            "deps.log.error('report refused', { scan: body.scan.id, status: result.status, refusal: result.refusal });",
        ],
    },
    {
        file: "packages/agent-harness-scanner/src/scanner-surface.ts",
        reason: "SCANNER_VERSION is scanent's own release line (Inflect's copy names 0.13.0 for /4); scanent also declares each token exchange's grant inside the surface.",
        lines: [
            "import { HARNESS_REGISTER_TOOL, MCP_MESSAGES, TOKEN_EXCHANGE_GRANT, OPENSHELL_METHODS, OPENSHELL_PROFILE_SCOPE, OPENSHELL_READ_SCOPE, OPENSHELL_SERVICE } from 'http';",
            "export const SCANNER_VERSION = '0.13.0';",
            "{ product: 'azure-key-vault', method: 'POST', origin: AZURE_LOGIN_ORIGIN, path: '/{directoryTenantId}/oauth2/v2.0/token' },",
            "{ product: 'entra', method: 'POST', origin: AZURE_LOGIN_ORIGIN, path: '/{directoryId}/oauth2/v2.0/token' },",
            "{ product: 'gcp-iam', method: 'POST', origin: GOOGLE_OAUTH_ORIGIN, path: GOOGLE_TOKEN_PATH },",
        ],
    },
    {
        file: "packages/agent-harness-scanner/src/source.ts",
        reason: "scanent's sourceResult also carries the read's own words (detail) for local results; the reason is the same.",
        lines: [
            "const reason: IncompleteReason = stoppedBy instanceof SourceReadError ? stoppedBy.reason : 'UNREACHABLE';",
            "return { kind, status: 'INCOMPLETE', reason, rows, observations };",
        ],
    },
    {
        file: "packages/agent-harness-scanner/src/sources/code/provider-sdk.ts",
        reason: "scanent passes an MCP server's whole endpoint (mcpEndpoint) beside the origin it reports.",
        lines: [
            "private push(r: Resolved, name: string | null, kind: DetectedTool['kind'], line: number, where?: string): void {",
            "r.tools.push({ name, kind, server: where ?? this.s.reportable.locator(at), at });",
            "this.push(r, `${label}:*`, 'mcp', this.defined(item), where);",
        ],
    },
    {
        file: "packages/agent-harness-scanner/src/sources/code/python.ts",
        reason: "scanent's Python reader is hardened: a work budget per file, prefix operators read in a loop, and a conditional never re-read at the same token. These are the unbudgeted forms of the same parser.",
        lines: [
            "constructor(private readonly toks: readonly Tok[]) {}",
            "expr(depth = 0): Expr {",
            "if (t.t === 'name' && t.v === 'if' && depth >= 0) {",
            "if (t.t === 'op' && (t.v === '-' || t.v === '+' || t.v === '~')) {",
            "this.unary(depth + 1);",
            "if (t.t === 'name' && t.v === 'not') {",
            "this.unary(depth + 1);",
            "return this.unary(depth + 1);",
            "if (t.t === 'name' && t.v === 'lambda') {",
            "return { k: 'func', line };",
            "return this.postfix(this.primary(depth), depth);",
            "this.expr(depth + 1);",
            "return { k: 'opaque', line };",
            "return { k: 'opaque', line };",
            "this.expr(depth + 1);",
            "this.next();",
            "const p = new LineParser(lineToks);",
            "decorators.push({ expr: new LineParser(lineToks.slice(1)).expr(), line });",
            "const bases = new LineParser(lineToks.slice(2));",
            "collect(new LineParser(lineToks.slice(inAt + 1, end)).expr(), null);",
            "const p = new LineParser(lineToks.slice(isAsync ? 2 : 1));",
            "const value = new LineParser(lineToks.slice(last + 1)).expr();",
            "const value = new LineParser(lineToks.slice(aug.at + 1)).expr();",
        ],
    },
    {
        file: "packages/agent-harness-scanner/src/sources/code/recognize.ts",
        reason: "scanent reports an MCP server written in code by its origin, keeps the whole endpoint in memory (mcpEndpoint), and holds model names to reportableModelName. These are the earlier forms.",
        lines: [
            "readonly reportable = { locator: codeLocator, name: reportableName, modelName: reportableName, credentialKey: isCredentialKey };",
            "r.tools.push({ name: `${label}:*`, kind: 'mcp', server: endpoint ?? codeLocator(this.at(server.line)), at });",
            "model: model !== null ? reportableName(model) : null,",
            "const model = nameExpr?.k === 'str' && !nameExpr.template ? reportableName(nameExpr.value) : null;",
            "private credentialOptions(call: CallExpr): Resolved {",
            "endpointOf(e: Expr, depth = 0): string | null {",
            "if (env !== null) return ENV_NAME.test(env) ? `env://${env}` : null;",
            "return bound === null ? null : this.endpointOf(bound, depth + 1);",
            "const clean = `${url.protocol}//${url.host}${url.pathname === '/' ? '' : url.pathname}`;",
            "return clean.length <= 400 && !looksLikeSecret(clean) ? clean : null;",
            "r.tools.push({ name: `${label}:*`, kind: 'mcp', server: where, at });",
            "if (v !== null && v.k === 'str' && !v.template) model = reportableName(v.value);",
            "tools: dedupe(f.r.tools, (t) => `${t.server}\\u0000${t.name}`),",
        ],
    },
    {
        file: "packages/agent-harness-scanner/src/sources/langchain.ts",
        reason: "scanent reads files without following a link or blocking on a pipe (readRegularFileCapped), passes the marker set and the providerSdks option, and carries mcpEndpoint and detail. Same reads, hardened.",
        lines: [
            "import { lstat, readdir, readFile } from 'fs/promises';",
            "import { MAX_NOT_READ_LOCATIONS, sourceResult, type HarnessSource, type IncompleteReason, type Observation, type SourceRead } from 'source';",
            "import { markersFor, readCodeFiles } from 'files';",
            "const NODE_FS: CodeFs = {",
            "readFile: (p) => readFile(p),",
            "tools: agent.tools.map((t) => ({ tool: { server: t.server, name: t.name, manifestHash: null, pinned: false, readOnlyHint: null } })),",
            "export function notReadOf(problems: readonly FileProblem[], reason: IncompleteReason): Pick<SourceRead, 'notRead' | 'notReadTotal'> {",
            "return { kind: 'code', status: 'INCOMPLETE', reason, rows: scan.rows, observations, ...notReadOf(scan.problems, reason) };",
        ],
    },
    {
        file: "packages/agent-harness-scanner/src/sources/langsmith.ts",
        reason: "scanent's host check is injectable (checkHost: the environment's proxy-aware check) and a page size can be given for the preflight. Same guard, same query.",
        lines: [
            "function projectsQuery(since: string, offset: number): string {",
            "['limit', String(LANGSMITH_PAGE_SIZE)],",
            "function guarded(http: ReadOnlyHttp, resolve: ResolveHost, allowlist: PrivateCidrAllowlist): ReadOnlyHttp {",
            "await assertResolvesReachable(new URL(url).hostname, resolve, allowlist);",
            "const http = selfHosted ? guarded(ctx.http, resolve, allowlist) : ctx.http;",
        ],
    },
    {
        file: "packages/agent-harness-scanner/src/sources/mcp.ts",
        reason: "scanent's host check is injectable (checkHost) and runs before every request through the wire's beforeRequest. Same guard.",
        lines: [
            "const guard = () => assertResolvesReachable(hostname, resolve, allowlist);",
            "await guard();",
            "const session: McpSession = await ctx.mcp.open({ url: server.url, headers });",
            "await guard();",
        ],
    },
];

function usage(message) {
    process.stderr.write(`${message}\nusage: node scripts/compare-inflect-copy.js <inflect repository> [--ref <git ref>] [--worktree] [--verbose]\n`);
    process.exit(2);
}

function parseArgs(argv) {
    let repo = null;
    let ref = 'origin/main';
    let worktree = false;
    let verbose = false;
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        if (a === '--ref') {
            ref = argv[++i];
            if (!ref) usage('--ref needs a value');
        } else if (a === '--worktree') {
            worktree = true;
        } else if (a === '--verbose') {
            verbose = true;
        } else if (a.startsWith('-')) {
            usage(`unknown option ${a}`);
        } else if (repo === null) {
            repo = a;
        } else {
            usage(`unexpected argument ${a}`);
        }
    }
    if (repo === null) usage('the Inflect repository path is required');
    if (!fs.existsSync(path.join(repo, '.git'))) usage(`${repo} is not a git repository`);
    return { repo, ref, worktree, verbose };
}

function git(repo, args) {
    return execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
}

/** The Inflect side: a reader by repository-relative path, and the scanner's file list. */
function inflectSide({ repo, ref, worktree }) {
    if (worktree) {
        const walk = (dir) =>
            fs.readdirSync(path.join(repo, dir), { withFileTypes: true }).flatMap((e) => {
                const rel = `${dir}/${e.name}`;
                return e.isDirectory() ? walk(rel) : e.name.endsWith('.ts') ? [rel] : [];
            });
        return {
            label: `${repo} (working tree)`,
            read: (rel) => (fs.existsSync(path.join(repo, rel)) ? fs.readFileSync(path.join(repo, rel), 'utf8') : null),
            scannerFiles: () => walk(SCANNER_ROOT_THERE),
        };
    }
    const commit = git(repo, ['rev-parse', '--short', ref]).trim();
    return {
        label: `${repo} at ${ref} (${commit})`,
        read: (rel) => {
            try {
                return git(repo, ['show', `${ref}:${rel}`]);
            } catch {
                return null;
            }
        },
        scannerFiles: () =>
            git(repo, ['ls-tree', '-r', '--name-only', ref, '--', SCANNER_ROOT_THERE])
                .split('\n')
                .filter((f) => f.endsWith('.ts')),
    };
}

/** A module specifier as both repositories can agree on it: its last path segment, with no `node:` prefix. */
function normaliseSpecifier(spec) {
    const bare = spec.replace(/^node:/, '');
    if (/^(@\/|@rodnapamet\/scanent-contract\/|\.{1,2}\/)/.test(bare)) return bare.split('/').pop();
    return bare;
}

/** Drop a trailing `//` comment that is outside a string. */
function stripTrailingComment(line) {
    let quote = null;
    for (let i = 0; i < line.length; i++) {
        const c = line[i];
        if (quote !== null) {
            if (c === '\\') i++;
            else if (c === quote) quote = null;
            continue;
        }
        if (c === '"' || c === "'" || c === '`') quote = c;
        else if (c === '/' && line[i + 1] === '/' && (i === 0 || /\s/.test(line[i - 1]))) return line.slice(0, i);
    }
    return line;
}

/** The code lines of a file, normalised, each with its 1-based line number. */
function codeLines(text) {
    const out = [];
    let inBlock = false;
    text.split('\n').forEach((raw, index) => {
        let line = raw.trim();
        if (inBlock) {
            const end = line.indexOf('*/');
            if (end === -1) return;
            inBlock = false;
            line = line.slice(end + 2).trim();
        }
        if (line.startsWith('/*')) {
            const end = line.indexOf('*/', 2);
            if (end === -1) {
                inBlock = true;
                return;
            }
            line = line.slice(end + 2).trim();
        }
        if (line === '' || line.startsWith('//') || line.startsWith('*')) return;
        line = stripTrailingComment(line).trim();
        if (line === '') return;
        line = line.replace(/(\bfrom\s+|\bimport\s+|\brequire\(\s*|\bimport\(\s*)(['"])([^'"]+)\2/g, (_m, lead, q, spec) => `${lead}${q}${normaliseSpecifier(spec)}${q}`);
        line = line.replace(/\s+/g, ' ');
        out.push({ line, number: index + 1 });
    });
    return out;
}

/** Lines of `there` that occur more often there than in `here`. */
function onlyThere(thereText, hereText) {
    const counts = new Map();
    for (const { line } of codeLines(hereText ?? '')) counts.set(line, (counts.get(line) ?? 0) + 1);
    const result = [];
    for (const entry of codeLines(thereText)) {
        const left = counts.get(entry.line) ?? 0;
        if (left > 0) counts.set(entry.line, left - 1);
        else result.push(entry);
    }
    return result;
}

function exceptionFor(file, line) {
    return EXCEPTIONS.find((e) => e.file === file && e.lines.includes(line));
}

function main() {
    const opts = parseArgs(process.argv.slice(2));
    const there = inflectSide(opts);
    const pairs = [
        ...CONTRACT_FILES,
        ...there.scannerFiles().map((f) => [f, `${SCANNER_ROOT_HERE}/${f.slice(SCANNER_ROOT_THERE.length + 1)}`]),
    ];

    let unexplained = 0;
    let explained = 0;
    const missingHere = [];
    const used = new Set();
    process.stdout.write(`Inflect side: ${there.label}\nscanent side: ${ROOT}\n\n`);
    for (const [thereRel, hereRel] of pairs) {
        const thereText = there.read(thereRel);
        if (thereText === null) {
            process.stdout.write(`${thereRel}: not found on the Inflect side\n`);
            continue;
        }
        const herePath = path.join(ROOT, hereRel);
        const hereText = fs.existsSync(herePath) ? fs.readFileSync(herePath, 'utf8') : null;
        if (hereText === null) missingHere.push(`${thereRel} -> ${hereRel}`);
        const lines = onlyThere(thereText, hereText);
        const open = [];
        const listed = [];
        for (const l of lines) {
            const e = exceptionFor(thereRel, l.line);
            if (e !== undefined) used.add(`${thereRel}\u0000${l.line}`);
            (e === undefined ? open : listed).push({ ...l, reason: e?.reason });
        }
        unexplained += open.length;
        explained += listed.length;
        if (open.length === 0 && listed.length === 0) continue;
        process.stdout.write(`== ${thereRel} -> ${hereRel}${hereText === null ? ' (MISSING HERE)' : ''}\n`);
        for (const l of open) process.stdout.write(`  L${l.number}: ${l.line}\n`);
        if (listed.length > 0) {
            process.stdout.write(`  ${listed.length} line(s) listed as deliberate: ${listed[0].reason}\n`);
            if (opts.verbose) for (const l of listed) process.stdout.write(`    L${l.number}: ${l.line}\n`);
        }
        process.stdout.write('\n');
    }
    if (missingHere.length > 0) process.stdout.write(`Files with no counterpart here:\n${missingHere.map((m) => `  ${m}\n`).join('')}\n`);
    const stale = EXCEPTIONS.flatMap((e) => e.lines.filter((l) => !used.has(`${e.file}\u0000${l}`)).map((l) => `${e.file}: ${l}`));
    if (stale.length > 0) process.stdout.write(`Stale exceptions (no longer Inflect-only; remove them):\n${stale.map((s) => `  ${s}\n`).join('')}\n`);
    process.stdout.write(`Inflect-only code lines: ${unexplained} unexplained, ${explained} listed as deliberate exceptions, ${stale.length} stale exception(s).\n`);
    process.exit(unexplained === 0 && stale.length === 0 ? 0 : 1);
}

main();
