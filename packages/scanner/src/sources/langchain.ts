/**
 * THE `code` SOURCE: LANGCHAIN, LANGGRAPH AND CLAUDE AGENT SDK AGENTS IN AN
 * ESTATE'S CODE, AND AGENTS BUILT DIRECTLY ON A MODEL PROVIDER'S SDK.
 *
 * Agents built on these frameworks, or on Anthropic's, OpenAI's, Google's or
 * AWS Bedrock's own SDK (a model call that is given tools:
 * `code/provider-sdk.ts`; on unless the configuration says
 * `providerSdks: false`), are things the scanner DISCOVERS: it does
 * not run them and does not depend on them. None of the frameworks is a
 * dependency of this scanner; it reads the text of the code and configuration
 * it is pointed at and reports each agent definition through the signed
 * contract (the `code` kind and the `UNPARSEABLE` reason are what
 * `inflect-agent-harness/2` added for it).
 *
 * ── STATIC ONLY ─────────────────────────────────────────────────────────────
 *
 * Python is read by a bounded tokenizer and expression reader (`code/python.ts`),
 * JavaScript and TypeScript by TypeScript's syntax-only parser
 * (`code/javascript.ts`). Neither imports, requires, evaluates or spawns
 * anything: a scanned repository cannot run code in the scanner.
 * `eslint.config.mjs` refuses `child_process`, `vm`, `worker_threads`, `module`,
 * a dynamic `import()`, `require()` and `eval` in `sources/code/` and here, and
 * a test plants a definition whose import would have a side effect.
 *
 * ── WHAT EACH AGENT BECOMES ─────────────────────────────────────────────────
 *
 *   discoveredId  `code:<root label>/<path>#<name the definition is bound to>`;
 *                 for a model call on a provider's SDK, the function it is
 *                 written in, since `response = …` names nothing
 *   tools         one per tool it binds: an MCP server's URL, or the `code://`
 *                 locator of the tool's definition, with no pin and an
 *                 undeclared read-only hint (so: a write, as the contract says)
 *   credentials   by REFERENCE: `env://NAME`, or `code://…#L<line>` where a
 *                 value is written into the code — never the value
 *   owner         null; code names no accountable person
 *   verdicts      none for LangChain, LangGraph and a provider's SDK, whose
 *                 code holds no evidence for a harness criterion. For an
 *                 Agent SDK agent,
 *                 the NOT MET verdicts its options support, by the
 *                 contract's mapping (`agentSdkOptionVerdicts`): code can
 *                 show a control is missing, never that one works
 *
 *   paymentCapabilities
 *                 `/4`'s member: each place the agent's FILE calls a
 *                 recognised payment client (`code/payment.ts`), by protocol,
 *                 library and `code://` locator — `[]` when the file shows
 *                 none. `[]` is what this reader saw, not that the agent
 *                 cannot pay (a helper module is not followed), so the planner
 *                 never closes SPENDING_AGENT_UNDECLARED on it. Never an
 *                 amount, a wallet or a key
 *
 *   models        the model endpoints it calls (`/2`'s optional `models[]`):
 *                 an https URL, an `env://` reference to where the URL is
 *                 configured, or the `code://` locator of the model's
 *                 construction when neither is knowable — with the model id
 *                 when the code names it
 *
 * ── COMPLETENESS ────────────────────────────────────────────────────────────
 *
 * A location that cannot be read is INCOMPLETE with the reason from
 * `code/files.ts`; a file that does not parse, or a definition with a part the
 * reader cannot resolve, is INCOMPLETE `UNPARSEABLE`. Neither is left out, and
 * what was read is still reported. A tree with no agent in it is a COMPLETE
 * read of nothing, which the ingest raises as EMPTY_SCAN when no other source
 * found one either.
 */
import { constants } from 'fs';
import { lstat, open, readdir } from 'fs/promises';

import {
    ProbeLog,
    sourceResult,
    SourceReadError,
    type HarnessSource,
    MAX_NOT_READ_LOCATIONS,
    type IncompleteReason,
    type Observation,
    type ProbeStep,
    type SourceRead,
} from '../source';
import type { CodeFs, CodeRoot, FileProblem } from './code/files';
import { MAX_MARKER_SCAN_BYTES, markersFor, readCodeFiles } from './code/files';
import { JavaScriptReadError, readJavaScript } from './code/javascript';
import { recognizePaymentCalls, type DetectedPaymentCall } from './code/payment';
import { PythonReadError, readPython } from './code/python';
import { agentSdkOptionVerdicts } from '@rodnapamet/scanent-contract/harness-findings';

import { codeLocator, recognizeAgents, type DetectedAgent } from './code/recognize';

export interface LangChainCodeSourceOptions {
    readonly roots: readonly CodeRoot[];
    /**
     * Agents built directly on a model provider's SDK. On unless it is
     * `false`; off, neither their files are parsed nor their calls read, and
     * the source reads exactly what it read before it knew them.
     */
    readonly providerSdks?: boolean;
    /** A TEST SEAM. The scanner never passes one, so production reads the real filesystem. */
    readonly fs?: CodeFs;
}

/** The order a source's reason is chosen in when several apply: what was not read at all comes first. */
const REASON_ORDER: readonly IncompleteReason[] = ['AUTH_FAILED', 'UNREACHABLE', 'TIME_BOX', 'BYTE_CAP', 'UNPARSEABLE'];

/**
 * One file's bytes, at most one more than the most that is ever read of a
 * file (`MAX_MARKER_SCAN_BYTES`), from a REGULAR file
 * that is not reached through a link.
 *
 * The walk stats an entry and then reads it, and a tree somebody else can
 * write to may change in between. Read by name alone, a file swapped for a
 * link would be followed out of the root, one swapped for a pipe would block
 * the scan for ever (the deadline is checked between entries, not inside a
 * read), and one that grew would be read whole into memory before its size was
 * looked at. So the file is opened without following a link and without
 * blocking, what was opened is checked to be a regular file, and the read
 * stops one byte past the cap, which is enough for the walk to see it is over.
 *
 * The last path component only: a DIRECTORY swapped for a link between its
 * stat and its listing is still listed. Closing that takes directory handles
 * Node does not offer; it needs somebody who can already write the scanned
 * tree while it is being read.
 */
async function readRegularFileCapped(path: string): Promise<Buffer> {
    // Absent on a platform without them (Windows), where the flags are zero.
    const noFollow = (constants.O_NOFOLLOW as number | undefined) ?? 0;
    const nonBlock = (constants.O_NONBLOCK as number | undefined) ?? 0;
    const handle = await open(path, constants.O_RDONLY | noFollow | nonBlock);
    try {
        const st = await handle.stat();
        if (!st.isFile()) throw Object.assign(new Error('not a regular file'), { code: 'ENOTSUP' });
        const buffer = Buffer.alloc(Math.min(st.size, MAX_MARKER_SCAN_BYTES) + 1);
        let length = 0;
        while (length < buffer.byteLength) {
            const { bytesRead } = await handle.read(buffer, length, buffer.byteLength - length, null);
            if (bytesRead === 0) break;
            length += bytesRead;
        }
        // More than the size stated, on a file that was under the cap: it grew while it was read, and
        // what was read is a cut of it. That is a file not read, never text to parse.
        if (st.size <= MAX_MARKER_SCAN_BYTES && length > st.size) throw Object.assign(new Error('changed while read'), { code: 'EBUSY' });
        return buffer.subarray(0, length);
    } finally {
        await handle.close();
    }
}

/** The real file system, as the `code` source reads it. Exported for the tests that swap a file under it. */
export const NODE_CODE_FS: CodeFs = {
    lstat: (p) => lstat(p),
    readdir: (p) => readdir(p),
    readFile: readRegularFileCapped,
};
const NODE_FS = NODE_CODE_FS;

/** A detected agent, and the payment client calls its file makes. */
export interface CodeAgent extends DetectedAgent {
    readonly paymentCalls: readonly DetectedPaymentCall[];
}

export interface CodeScan {
    readonly rows: number;
    readonly agents: readonly CodeAgent[];
    readonly problems: readonly FileProblem[];
}

/** Read the roots and recognise every agent definition in them. Pure apart from the file reads. */
export async function scanLangChainCode(
    roots: readonly CodeRoot[],
    fs: CodeFs,
    opts: { readonly deadline: number; readonly now: () => number; readonly providerSdks?: boolean },
): Promise<CodeScan> {
    const agents: CodeAgent[] = [];
    const parseProblems: FileProblem[] = [];
    const providerSdks = opts.providerSdks !== false;
    const { rows, problems } = await readCodeFiles(roots, fs, { deadline: opts.deadline, now: opts.now, markers: markersFor(providerSdks) }, (file) => {
        try {
            const facts = /\.py$/i.test(file.path) ? readPython(file.text) : readJavaScript(file.path, file.text);
            const found = recognizeAgents(facts, file, { providerSdks });
            const payments = recognizePaymentCalls(facts, file, { definesAgent: found.agents.length > 0 });
            agents.push(...found.agents.map((a) => ({ ...a, paymentCalls: payments.calls })));
            for (const at of [...found.unresolved, ...payments.unresolved]) parseProblems.push({ reason: 'UNPARSEABLE', at });
        } catch (err) {
            // A reader's own refusal names the line. Anything else is a fault in
            // a reader or the recogniser on THIS file: it is still a file that
            // was not read, and it must not take the other files' agents with it.
            const line = err instanceof PythonReadError || err instanceof JavaScriptReadError ? err.line : 0;
            parseProblems.push({ reason: 'UNPARSEABLE', at: { label: file.label, path: file.path, line } });
        }
    });
    return { rows, agents, problems: [...problems, ...parseProblems] };
}

/** One detected agent as the report's observation of it. */
export function observationOf(agent: CodeAgent): Observation {
    return {
        discoveredId: agent.discoveredId,
        owner: null,
        credentials: agent.credentials.map((c) => ({
            ref: c.ref,
            ageDays: null,
            expires: null,
            boundToAgent: false,
            grant: 'unknown' as const,
        })),
        // A definition binds tools; it counts no calls, so none is given.
        tools: agent.tools.map((t) => ({
            tool: { server: t.server, name: t.name, manifestHash: null, pinned: false, readOnlyHint: null },
            ...(t.mcpEndpoint !== undefined ? { mcpEndpoint: t.mcpEndpoint } : {}),
        })),
        models: agent.models.map((m) => ({ endpoint: m.endpoint ?? codeLocator(m.at), model: m.model })),
        // Always stated, `[]` included: a code read is the one source that can say "none".
        paymentCapabilities: agent.paymentCalls.map((p) => ({ protocol: p.protocol, library: p.library, at: codeLocator(p.at) })),
        // An Agent SDK agent's options, mapped by the planner; the other frameworks', and a provider SDK's, code evidences nothing.
        verdicts: agent.sdkOptions === null ? [] : agentSdkOptionVerdicts(agent.sdkOptions),
    };
}

/** What each reason means for the code source, in fixed words. */
const REASON_DETAIL: Readonly<Partial<Record<IncompleteReason, string>>> = {
    AUTH_FAILED: 'the operating system refused a read',
    UNREACHABLE: 'a root or an entry is missing, is not a directory, or is a symbolic link, which is never followed',
    TIME_BOX: 'the scan reached its time box before the tree was read',
    BYTE_CAP: 'a file that names a framework is over the per-file limit, or the tree is over the file-count, total-size or depth limit',
    UNPARSEABLE: 'a file that names a framework could not be read as code, or an agent in it could not be resolved',
};

/** The two reasons that are about which files are parsed and what is read in them, while a provider's SDK is looked for too. */
const REASON_DETAIL_WITH_PROVIDER_SDKS: Readonly<Partial<Record<IncompleteReason, string>>> = {
    BYTE_CAP: 'a file that names a framework or a model provider\'s SDK is over the per-file limit, or the tree is over the file-count, total-size or depth limit',
    UNPARSEABLE: 'a file that names a framework or a model provider\'s SDK could not be read as code, or an agent in it, or a model call that may be one, could not be resolved',
};

/**
 * The places this read did not cover, for the operator: the source's reason
 * first, then the others, each as the locator an agent in that file would
 * carry. A problem with no place (the time box) is counted and not listed.
 */
export function notReadOf(
    problems: readonly FileProblem[],
    reason: IncompleteReason,
    providerSdks = true,
): Pick<SourceRead, 'detail' | 'notRead' | 'notReadTotal'> {
    const placed = problems.filter((p): p is FileProblem & { at: NonNullable<FileProblem['at']> } => p.at !== null);
    const ordered = [...placed.filter((p) => p.reason === reason), ...placed.filter((p) => p.reason !== reason)];
    return {
        detail: (providerSdks ? REASON_DETAIL_WITH_PROVIDER_SDKS[reason] : undefined) ?? REASON_DETAIL[reason] ?? 'the tree was not read in full',
        notRead: ordered.slice(0, MAX_NOT_READ_LOCATIONS).map((p) => ({ where: codeLocator(p.at), reason: p.reason })),
        notReadTotal: problems.length,
    };
}

export function langchainCodeSource(options: LangChainCodeSourceOptions): HarnessSource {
    const fs = options.fs ?? NODE_FS;
    return {
        kind: 'code',
        product: 'langchain',
        async read(ctx): Promise<SourceRead> {
            const scan = await scanLangChainCode(options.roots, fs, { deadline: ctx.deadline, now: ctx.now, providerSdks: options.providerSdks });
            const observations = scan.agents.map(observationOf);
            const reason = REASON_ORDER.find((r) => scan.problems.some((p) => p.reason === r));
            if (reason === undefined) return sourceResult('code', scan.rows, observations, null);
            return { kind: 'code', status: 'INCOMPLETE', reason, rows: scan.rows, observations, ...notReadOf(scan.problems, reason, options.providerSdks !== false) };
        },
        async preflight(): Promise<readonly ProbeStep[]> {
            const steps: ProbeStep[] = [];
            // Each root on its own: `lstat` and one `readdir`, the operations `read` starts with. No file is opened.
            for (const root of options.roots) {
                const log = new ProbeLog(root.label);
                await ProbeLog.run(async () => {
                    await log.read('the root', '', async () => {
                        try {
                            const st = await fs.lstat(root.path);
                            if (st.isSymbolicLink() || !st.isDirectory()) throw new SourceReadError('UNREACHABLE', 'the root is not a directory');
                            return { entries: (await fs.readdir(root.path)).length };
                        } catch (err) {
                            if (err instanceof SourceReadError) throw err;
                            const code = (err as { code?: unknown } | null)?.code;
                            throw new SourceReadError(code === 'EACCES' || code === 'EPERM' ? 'AUTH_FAILED' : 'UNREACHABLE', 'the root could not be listed');
                        }
                    });
                });
                steps.push(...log.steps);
            }
            return steps;
        },
    };
}

