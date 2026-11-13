/**
 * `docs/guide/`, the guide for the organisation being scanned, held to the
 * code where a machine can hold it.
 *
 * The guide is written for people who cannot check it against the source, so
 * what it says about levels, findings, files and commands is checked here:
 *
 *   - every level, criterion, finding code, incomplete reason, CSV column and
 *     CSV word the code has is in the guide, and the guide names no other;
 *   - a finding's severity, and whether a scan with no tenant can raise it,
 *     are what the planner and the local scorer do;
 *   - the highest level each kind of run can show is what the criterion
 *     readers allow;
 *   - the access table agrees with the access guide `init` prints;
 *   - every command in a `bash` block is a real command with real flags, as
 *     the command line itself parses it;
 *   - every relative link resolves, to the file and to the heading;
 *   - the guide cites no source path, and never calls the licence open source.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { SCANNER_VERSION } from '../src/scanner-surface';

import { INCOMPLETE_REASONS, type HarnessReportBody } from '@rodnapamet/scanent-contract/harness-contract';
import { HARNESS_FINDING_CODES, planHarnessScan, type PriorHarnessState } from '@rodnapamet/scanent-contract/harness-findings';
import { ALL_HARNESS_CRITERIA, HARNESS_CRITERIA, HARNESS_LEVEL_NAMES, HARNESS_LEVELS, type HarnessLevel } from '@rodnapamet/scanent-contract/harness-ladder';
import { AGENTS_CSV_LEADING_COLUMNS, csvCriterionState, FINDINGS_CSV_COLUMNS } from '@scanent/report/render/csv';
import { RUN_FILE_NAMES } from '@scanent/report/render/files';
import { scoreReportLocally } from '@scanent/report/results/score';
import { harnessCoverageOf } from '@rodnapamet/scanent-contract/harness-matrix-model';
import type { ReaderKind } from '@scanent/report/results/types';

import { HELP, main, USAGE_HINT } from '../src/cli';
import { ConfigError } from '../src/config';
import { CRITERION_READERS } from '../src/criterion-readers';
import { parseDiffArgs } from '../src/diff-command';
import { ACCESS_GUIDE, credentialVariable, GUIDE_ORDER } from '../src/init/access-guide';

const REPO = path.resolve(__dirname, '../../..');
const GUIDE_DIR = path.join(REPO, 'docs/guide');
const PAGES = ['README.md', 'what-it-reads.md', 'run-it.md', 'read-the-report.md', 'findings.md', 'faq.md'] as const;
const page = (name: string): string => fs.readFileSync(path.join(GUIDE_DIR, name), 'utf8');
const GUIDE: Readonly<Record<string, string>> = Object.fromEntries(PAGES.map((name) => [name, page(name)]));
const ALL = PAGES.map((name) => GUIDE[name]).join('\n');

/** The rows of the table between `<!-- guide:<name> -->` markers, header and rule dropped, each as its cells. */
function tableRows(text: string, name: string): string[][] {
    const m = new RegExp(`<!-- guide:${name} -->\\n([\\s\\S]*?)<!-- /guide:${name} -->`).exec(text);
    if (m === null) throw new Error(`no guide:${name} table`);
    return m[1]
        .split('\n')
        .filter((l) => l.startsWith('|'))
        .slice(2)
        .map((l) => l.slice(1, -1).split('|').map((c) => c.trim()));
}

const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;

describe('docs/guide: the pages', () => {
    it('are exactly the six the guide is made of, and none is a stub', () => {
        expect(fs.readdirSync(GUIDE_DIR).sort()).toEqual([...PAGES].sort());
        for (const name of PAGES) expect(GUIDE[name].length).toBeGreaterThan(2500);
    });

    it('are linked from the root README, and from the guide\'s own first page', () => {
        expect(fs.readFileSync(path.join(REPO, 'README.md'), 'utf8')).toContain('](docs/guide/README.md)');
        for (const name of PAGES.filter((p) => p !== 'README.md')) expect(GUIDE['README.md']).toContain(`](${name})`);
    });
});

describe('docs/guide/read-the-report.md: the ladder', () => {
    const text = GUIDE['read-the-report.md'];

    it('has a row for every level, in order, with the name the code gives it', () => {
        const rows = tableRows(text, 'levels');
        expect(rows.map((r) => r[0])).toEqual([...HARNESS_LEVELS]);
        expect(rows.map((r) => r[1])).toEqual(HARNESS_LEVELS.map((level) => HARNESS_LEVEL_NAMES[level]));
        // A meaning and an example for each.
        for (const row of rows) {
            expect(row[2].length).toBeGreaterThan(20);
            expect(row[3].length).toBeGreaterThan(40);
        }
    });

    it('has a row for every criterion, in ladder order, and for nothing else', () => {
        expect(tableRows(text, 'criteria').map((r) => r[0])).toEqual(ALL_HARNESS_CRITERIA.map((c) => `\`${c}\``));
    });

    it('states the highest level each kind of run can show, as the criterion readers allow', () => {
        const sources = GUIDE_ORDER.filter((kind) => kind !== 'inflect-register') as ReaderKind[];
        const reachable = (readers: ReaderKind[]): HarnessLevel => harnessCoverageOf(CRITERION_READERS, readers).coverage.reachableLevel;
        expect(tableRows(text, 'ceilings').map((r) => r[1])).toEqual([
            reachable(sources),
            reachable([...sources, 'inventory']),
            reachable([...sources, 'inflect-register']),
        ]);
        // The three the page writes out, so a change of ceiling fails here by name.
        expect(tableRows(text, 'ceilings').map((r) => r[1])).toEqual(['H0', 'H1', 'H3']);
    });

    it('says which levels only a tenant can confirm, and that nothing reads H4 or H5: true of the readers', () => {
        const metBy = (criterion: (typeof ALL_HARNESS_CRITERIA)[number]): readonly ReaderKind[] => CRITERION_READERS[criterion].metBy;
        // "Two of its five checks can be confirmed only through an Inflect tenant."
        expect(HARNESS_CRITERIA.H2.length).toBe(5);
        expect(HARNESS_CRITERIA.H2.filter((c) => metBy(c).length === 1 && metBy(c)[0] === 'inflect-register')).toEqual(['H2.audience_tokens', 'H2.policy_card']);
        expect(text).toContain('Two of its five checks can be confirmed only through an Inflect tenant');
        // "The other three ... from Microsoft Entra ID, Google Cloud, Okta and GitHub Actions."
        const others = HARNESS_CRITERIA.H2.filter((c) => !['H2.audience_tokens', 'H2.policy_card'].includes(c));
        expect([...new Set(others.flatMap((c) => metBy(c)))].filter((r) => r !== 'inflect-register').sort()).toEqual(['cicd', 'entra-sp', 'gcp-sa', 'okta-app']);
        // "Every check on it can be confirmed only through an Inflect tenant."
        for (const c of HARNESS_CRITERIA.H3) expect(metBy(c)).toEqual(['inflect-register']);
        // "From agent code the scan can show three of them as failed, never as met."
        expect(HARNESS_CRITERIA.H3.filter((c) => CRITERION_READERS[c].reportedBy.includes('code')).length).toBe(3);
        expect(text).toContain('show three of them as **failed**');
        // "Nothing in the scanner checks this level today."
        for (const c of [...HARNESS_CRITERIA.H4, ...HARNESS_CRITERIA.H5]) expect(CRITERION_READERS[c].reportedBy).toEqual([]);
        // The inventory supplies the four H1 checks and nothing else.
        expect(ALL_HARNESS_CRITERIA.filter((c) => metBy(c).includes('inventory'))).toEqual([...HARNESS_CRITERIA.H1]);
    });

    it('names every file of a run, every CSV column and every word a criterion cell can hold', () => {
        for (const file of Object.values(RUN_FILE_NAMES)) expect(text).toContain(`\`${file}\``);
        for (const column of [...AGENTS_CSV_LEADING_COLUMNS, ...FINDINGS_CSV_COLUMNS]) expect(text).toContain(`\`${column}\``);
        const words = new Set<string>();
        for (const state of ['EVIDENCED', 'MET_UNEVIDENCED', 'NOT_MET', 'UNANSWERED'] as const) {
            for (const basis of ['OBSERVED', 'DECLARED', null] as const) {
                for (const readable of [true, false]) words.add(csvCriterionState({ criterion: 'H1.owner', state, basis, evidence: null, readable }));
            }
        }
        expect([...words].sort()).toEqual(['DECLARED', 'EVIDENCED', 'MET_UNEVIDENCED', 'NOT_MET', 'NOT_MET_DECLARED', 'NOT_READABLE', 'UNANSWERED']);
        for (const word of words) expect(text).toContain(`\`${word}\``);
    });

    it('explains every reason a source can be incomplete, and every reason an agent is not judged', () => {
        for (const reason of INCOMPLETE_REASONS) expect(text).toContain(`| \`${reason}\` |`);
        for (const code of ['SOURCE_INCOMPLETE', 'VERDICT_SOURCE_INCOMPLETE', 'OTHER_SOURCE_INCOMPLETE']) expect(text).toContain(`| \`${code}\` |`);
    });

    it('names each section of the page by the heading the page gives it, and quotes the page\'s own sentences', () => {
        const html = fs.readFileSync(path.join(REPO, 'packages/report/src/render/html.ts'), 'utf8');
        const headings = [...new Set([...html.matchAll(/<h2 id="[a-z]+-h">([^<]+)<\/h2>/g)].map((m) => m[1]))];
        expect(headings.length).toBe(11);
        for (const heading of headings) expect(text).toContain(`### ${heading}\n`);
        // Sentences the guide puts in quotation marks are the page's own.
        for (const quoted of [
            'This run could not have shown any agent at its bar',
            'This scan found no agents. That is a finding, not a clean result.',
            'Every listed source was read in full.',
            'No reader in scanent reports this criterion',
            'A reader exists; this run did not configure it',
            'Seen unbound, not concluded',
            'The scan cannot show that one of these runs no model.',
            'None seen in the code this scan read. That is not a statement that no agent can pay',
            'Code calls a payment client',
            'No finding was raised',
            'The scan is incomplete, so this is not a clean result.',
            'name declared by the operator',
        ]) {
            expect(html).toContain(quoted);
            expect(text.replace(/\n/g, ' ')).toContain(quoted);
        }
        // And the three first sentences of a comparison.
        const diffText = fs.readFileSync(path.join(REPO, 'packages/report/src/render/diff-text.ts'), 'utf8');
        for (const quoted of ['No difference, and every comparison could be made.', 'The two runs differ.', 'No difference was found, but not every comparison could be made.']) {
            expect(diffText).toContain(quoted);
            expect(text).toContain(quoted);
        }
    });
});

describe('docs/guide/findings.md: the findings', () => {
    const text = GUIDE['findings.md'];

    const body = (over: Record<string, unknown>): HarnessReportBody =>
        ({
            contract: 'inflect-agent-harness/4',
            scan: { id: 'guide-scan', asOf: '2026-11-12T00:00:00.000Z', scanner: { agentId: 'guide-scanner', version: '0', manifestHash: 'sha256:0' } },
            population: { sources: [] },
            agents: [],
            unboundCredentials: [],
            findings: [],
            ...over,
        }) as unknown as HarnessReportBody;
    const agent = (discoveredId: string, via: string, tools: unknown[]): unknown => ({
        discoveredId,
        discoveredVia: [via],
        registeredAgentId: null,
        owner: null,
        credentials: [],
        tools,
        verdicts: [],
    });
    const writeTool = { server: 'code://guide/agent.py#L1', name: 'send', manifestHash: null, pinned: false, readOnlyHint: null };
    const readTool = { server: 'https://mcp.guide.example/crm', name: 'list_accounts', manifestHash: 'sha256:0', pinned: true, readOnlyHint: true };
    const PAYING_ROW = 'agt_guide_paying';

    /** Four scans that between them raise every kind of finding. */
    const BODIES: readonly HarnessReportBody[] = [
        // An unknown agent with a write tool nobody pinned, beside a source that was not read in full.
        body({
            population: { sources: [{ kind: 'code', status: 'COMPLETE', rows: 1 }, { kind: 'runtime', status: 'INCOMPLETE', reason: 'TIME_BOX', rows: 0 }] },
            agents: [agent('code:guide/agent.py#a', 'code', [writeTool])],
        }),
        // An agent that only reads, an automated account with no sign of a model, and a credential nothing uses, on a scan read in full.
        body({
            population: { sources: [{ kind: 'entra-sp', status: 'COMPLETE', rows: 2 }, { kind: 'mcp', status: 'COMPLETE', rows: 1 }] },
            agents: [
                agent('entra:sp:00000000-0000-0000-0000-000000000001', 'entra-sp', [readTool]),
                agent('entra:sp:00000000-0000-0000-0000-000000000002', 'entra-sp', []),
            ],
            unboundCredentials: [{ sourceKind: 'entra-sp', ref: 'entra://guide/applications/a/password/k' }],
        }),
        // A registered agent whose code calls a payment client.
        body({
            population: { sources: [{ kind: 'code', status: 'COMPLETE', rows: 1 }] },
            agents: [
                {
                    ...(agent('code:guide/shop.ts#agent', 'code', []) as Record<string, unknown>),
                    registeredAgentId: PAYING_ROW,
                    paymentCapabilities: [{ protocol: 'x402', library: 'x402-fetch', at: 'code://guide/shop.ts#L5' }],
                },
            ],
        }),
        // Nothing found.
        body({ population: { sources: [{ kind: 'code', status: 'COMPLETE', rows: 0 }] } }),
    ];
    const NO_HISTORY: PriorHarnessState = {
        previousLevels: new Map(),
        registeredAgentIds: new Set([PAYING_ROW]),
        acceptedShortfalls: new Set(),
        intakeClaims: new Map(),
        openOrphanCredentials: new Set(),
        spendingAuthority: new Map(),
        onRecordAsAgent: new Set(),
    };

    it('has one section for every finding code the planner has, and a row for each', () => {
        // The planner's: the local results raise no code of their own.
        const codes = [...HARNESS_FINDING_CODES];
        const sections = [...text.matchAll(/^## `([A-Z_]+)`$/gm)].map((m) => m[1]);
        expect([...sections].sort()).toEqual([...codes].sort());
        expect(tableRows(text, 'findings').map((r) => r[0]).sort()).toEqual(codes.map((c) => `\`${c}\``).sort());
        expect(text).toContain('There are\nnine kinds.');
        expect(codes.length).toBe(9);
        // Each section answers the same five questions.
        for (const section of text.split(/^## `/m).slice(1)) {
            for (const part of ['**What it means.**', '**Why it matters.**', '**What to do.**', '**When it closes.**', '**Who usually owns it.**']) expect(section).toContain(part);
        }
    });

    it('gives each finding the severity the planner gives it', () => {
        const planned = new Map<string, Set<string>>();
        // A system that keeps history: the first scan's agent was at H2 before.
        const withHistory: PriorHarnessState = { ...NO_HISTORY, previousLevels: new Map([['code:guide/agent.py#a', 'H2' as const]]) };
        for (const b of BODIES) {
            for (const f of planHarnessScan(b, withHistory).assert) planned.set(f.code, (planned.get(f.code) ?? new Set()).add(f.severity));
        }
        expect([...planned.keys()].sort()).toEqual([...HARNESS_FINDING_CODES].sort());
        for (const [code, severity] of tableRows(text, 'findings')) {
            const stated = SEVERITIES.filter((s) => new RegExp(`\\b${s}\\b`).test(severity));
            expect({ code, severities: stated.sort() }).toEqual({ code, severities: [...(planned.get(code.replace(/`/g, '')) ?? [])].sort() });
        }
        // "MEDIUM for an agent that only reads": the second scan's agent.
        expect(planHarnessScan(BODIES[1], NO_HISTORY).assert.find((f) => f.code === 'HARNESS_SHORTFALL')?.severity).toBe('MEDIUM');
    });

    it('says which findings a scan with no tenant raises: every one but LEVEL_DROP, as the local scorer does', () => {
        const raised = new Set<string>();
        for (const b of BODIES) {
            const results = scoreReportLocally({
                body: b,
                inventory: null,
                readers: { table: CRITERION_READERS, configuredSources: ['code', 'entra-sp', 'mcp', 'runtime'] },
                meta: { estate: 'guide', registerClaimsVerified: true, report: { sha256: '0'.repeat(64), signerKeyFingerprint: 'guide', signerPinned: true } },
            });
            for (const f of results.findings) raised.add(f.code);
        }
        const rows = tableRows(text, 'findings');
        expect(rows.filter((r) => r[2].startsWith('Yes')).map((r) => r[0].replace(/`/g, '')).sort()).toEqual([...raised].sort());
        expect(rows.filter((r) => r[2].startsWith('No')).map((r) => r[0])).toEqual(['`LEVEL_DROP`']);
    });
});

describe('docs/guide/what-it-reads.md: the access', () => {
    const text = GUIDE['what-it-reads.md'];

    it('has a row for every source, with the credential variable and the number of steps the access guide gives', () => {
        const rows = tableRows(text, 'access');
        expect(rows.map((r) => r[1])).toEqual(GUIDE_ORDER.map((kind) => `\`${kind}\``));
        for (const [, kindCell, , credential, steps] of rows) {
            const entry = ACCESS_GUIDE[kindCell.replace(/`/g, '') as keyof typeof ACCESS_GUIDE];
            expect({ kind: entry.kind, steps: Number(steps) }).toEqual({ kind: entry.kind, steps: entry.where.length });
            expect(credential).toBe(entry.credential === '(none)' ? 'none' : `\`${credentialVariable(entry)}\``);
        }
    });

    it('lists, under each system, as many steps as the access guide has', () => {
        const sections = text.slice(text.indexOf('## System by system'), text.indexOf('## What the scanner connects to')).split(/^### /m).slice(1);
        expect(sections.length).toBe(GUIDE_ORDER.length);
        sections.forEach((section, i) => {
            const steps = section.slice(section.indexOf('**How to grant it.**')).split('\n').filter((l) => /^\d+\. /.test(l)).length;
            expect({ section: section.split('\n')[0], steps }).toEqual({ section: section.split('\n')[0], steps: ACCESS_GUIDE[GUIDE_ORDER[i]].where.length });
        });
    });

    it('names every host the access guide names as fixed', () => {
        for (const host of ['login.microsoftonline.com', 'graph.microsoft.com', 'api.github.com', 'oauth2.googleapis.com', 'iam.googleapis.com', 'api.smith.langchain.com', 'eu.api.smith.langchain.com']) {
            expect(Object.values(ACCESS_GUIDE).some((e) => e.hostsNote.includes(host))).toBe(true);
            expect(text).toContain(`\`${host}\``);
        }
    });
});

// ── Commands ──

/** Every logical line of every ```bash block of a page: continuations joined, blanks and comments dropped. */
function bashLines(text: string): string[] {
    return [...text.matchAll(/^```bash\n([\s\S]*?)^```$/gm)].flatMap((m) =>
        m[1]
            .replace(/\s*\\\n\s*/g, ' ')
            .split('\n')
            .map((l) => l.trim())
            .filter((l) => l !== '' && !l.startsWith('#')),
    );
}

/** Words of a line, with a double-quoted string as one word. */
const words = (line: string): string[] => [...line.matchAll(/"[^"]*"|\S+/g)].map((m) => m[0]);

/** What the guide may put between `scanent` and the image: flags of the container runtime, never of scanent. */
const RUNTIME_FLAGS: Readonly<Record<string, boolean>> = { '-it': false, '--network': true, '-v': true, '--env-file': true };

/** The commands and flags `scanent help` documents: `{ scan: ['--config', '--out', ...] }`. */
function helpFlags(): Map<string, string[]> {
    const out = new Map<string, string[]>();
    for (const m of HELP.matchAll(/^ {2}scanent ([a-z-]+)(.*)$/gm)) out.set(m[1], [...m[2].matchAll(/--[a-z-]+/g)].map((f) => f[0]));
    return out;
}

/** A guide command as the command line would be given it, with the paths replaced by ones this test owns. */
interface GuideCommand {
    readonly page: string;
    readonly line: string;
    readonly runtime: readonly string[];
    readonly command: string;
    readonly args: readonly string[];
}

function guideCommands(): GuideCommand[] {
    const out: GuideCommand[] = [];
    for (const name of PAGES) {
        for (const line of bashLines(GUIDE[name])) {
            const w = words(line);
            if (w[0] !== 'scanent') continue;
            const at = w.indexOf('"$IMAGE"');
            if (at < 0) throw new Error(`${name}: a scanent command that names no image: ${line}`);
            out.push({ page: name, line, runtime: w.slice(1, at), command: w[at + 1], args: w.slice(at + 2) });
        }
    }
    return out;
}

describe('docs/guide: the commands it shows', () => {
    const commands = guideCommands();

    it('starts every line of every bash block with a program the guide has introduced', () => {
        const first = new Set(PAGES.flatMap((name) => bashLines(GUIDE[name]).map((line) => words(line)[0])));
        expect([...first].sort()).toEqual(['cat', 'cd', 'chmod', 'docker', 'export', 'mkdir', 'scanent', 'scanent()', '}'].sort());
    });

    it('shows the commands of a first run: init, doctor, scan, diff and hosts', () => {
        expect([...new Set(commands.map((c) => c.command))].sort()).toEqual(['diff', 'doctor', 'hosts', 'init', 'scan']);
        expect(commands.filter((c) => c.page === 'run-it.md').map((c) => c.command)).toEqual(['init', 'doctor', 'scan', 'diff']);
    });

    it('puts only container-runtime flags before the image, each with its value', () => {
        for (const c of commands) {
            for (let i = 0; i < c.runtime.length; i++) {
                const flag = c.runtime[i];
                expect({ line: c.line, known: Object.hasOwn(RUNTIME_FLAGS, flag) }).toEqual({ line: c.line, known: true });
                if (RUNTIME_FLAGS[flag]) i += 1;
            }
        }
    });

    it('uses only commands and flags that `scanent help` documents', () => {
        const help = helpFlags();
        for (const name of USAGE_HINT.slice(USAGE_HINT.indexOf(':') + 1).split(',')) expect(help.has(name.trim())).toBe(true);
        for (const c of commands) {
            const known = help.get(c.command);
            expect({ line: c.line, command: known !== undefined }).toEqual({ line: c.line, command: true });
            const flags = c.args.filter((a) => a.startsWith('--')).map((a) => a.split('=')[0]);
            expect({ line: c.line, unknown: flags.filter((f) => !(known as string[]).includes(f)) }).toEqual({ line: c.line, unknown: [] });
        }
    });

    /**
     * The same, asked of the command line itself. Each command is run with the
     * guide's own flags and a configuration that does not exist: an argument
     * the command line does not know ends in exit 2 before the configuration
     * is opened, so anything else shows the arguments were accepted.
     */
    it('is accepted by the command line itself', async () => {
        const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'scanent-guide-'));
        const stdout = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
        const stderr = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
        try {
            for (const c of commands) {
                if (c.command === 'diff') {
                    expect({ line: c.line, parsed: parseDiffArgs(c.args) !== null }).toEqual({ line: c.line, parsed: true });
                    continue;
                }
                const args = c.args.map((a) => (a === '/etc/scanent/config.json' ? path.join(tmp, 'absent.json') : a === '/etc/scanent' ? path.join(tmp, 'new') : a));
                stderr.mockClear();
                let outcome: string;
                try {
                    outcome = `exit ${await main([c.command, ...args], {}, { interactive: false, cwd: tmp })}`;
                } catch (err) {
                    outcome = err instanceof ConfigError ? 'the configuration could not be read' : `threw ${String(err)}`;
                }
                const said = stderr.mock.calls.map((call) => String(call[0])).join('');
                // What each command does once its arguments are accepted and the configuration is absent.
                const expected: Readonly<Record<string, string>> = {
                    // No terminal here: the wizard says so. A flag it did not know would print the usage alone.
                    init: 'exit 2',
                    doctor: 'exit 4',
                    scan: 'the configuration could not be read',
                    hosts: 'the configuration could not be read',
                };
                expect({ line: c.line, outcome }).toEqual({ line: c.line, outcome: expected[c.command] });
                if (c.command === 'init') expect(said).toContain('init asks its questions at a terminal');
                expect(said).not.toContain('unknown argument');
            }
            // The check bites: a flag the command line does not have is refused as usage.
            stderr.mockClear();
            expect(await main(['scan', '--config', path.join(tmp, 'absent.json'), '--no-such-flag'], {}, { interactive: false, cwd: tmp })).toBe(2);
            expect(stderr.mock.calls.map((call) => String(call[0])).join('')).toContain('unknown argument');
            expect(parseDiffArgs(['a', 'b', '--no-such-flag'])).toBeNull();
        } finally {
            stdout.mockRestore();
            stderr.mockRestore();
            fs.rmSync(tmp, { recursive: true, force: true });
        }
    });

    it('wraps the container the way the deployment page does: as the caller, read-only, no capability, no privilege gain', () => {
        const wrapper = bashLines(GUIDE['run-it.md']).find((l) => l.startsWith('docker run'));
        expect(wrapper).toBe('docker run --rm --user "$(id -u):$(id -g)" --read-only --cap-drop ALL --security-opt no-new-privileges "$@"');
        expect(fs.readFileSync(path.join(REPO, 'docs/quick-start.md'), 'utf8').replace(/\s*\\\n\s*/g, ' ')).toContain(wrapper as string);
    });

    it('pulls the released image, under the name the quick start uses', () => {
        const lines = bashLines(GUIDE['run-it.md']);
        expect(lines).toContain('docker pull "$IMAGE"');
        expect(lines.find((l) => l.startsWith('export IMAGE='))).toBe(`export IMAGE=ghcr.io/rodnapamet/scanent:${SCANNER_VERSION}`);
        const image = lines.find((l) => l.startsWith('export IMAGE=')) as string;
        expect(fs.readFileSync(path.join(REPO, 'docs/quick-start.md'), 'utf8')).toContain(image);
    });
});

// ── Links ──

/** GitHub's anchor for a heading: lower case, punctuation dropped, spaces to hyphens; a repeat gets `-1`, `-2`. */
function anchorsOf(markdown: string): Set<string> {
    const seen = new Map<string, number>();
    const out = new Set<string>();
    for (const m of markdown.replace(/^```[\s\S]*?^```$/gm, '').matchAll(/^#{1,6} (.+)$/gm)) {
        const base = m[1]
            .trim()
            .toLowerCase()
            .replace(/[^\p{L}\p{N} _-]/gu, '')
            .replace(/ /g, '-');
        const n = seen.get(base) ?? 0;
        seen.set(base, n + 1);
        out.add(n === 0 ? base : `${base}-${n}`);
    }
    return out;
}

describe('docs/guide: links', () => {
    it.each(PAGES)('%s links only to files and headings that exist', (name) => {
        const links = [...GUIDE[name].matchAll(/\]\((?!https?:)([^)\s#]*)(?:#([^)\s]*))?\)/g)].map((m) => ({ target: m[1], anchor: m[2] }));
        expect(links.length).toBeGreaterThan(0);
        const broken: string[] = [];
        for (const { target, anchor } of links) {
            const file = target === '' ? path.join(GUIDE_DIR, name) : path.resolve(GUIDE_DIR, target);
            if (!fs.existsSync(file)) broken.push(target);
            else if (anchor !== undefined && !anchorsOf(fs.readFileSync(file, 'utf8')).has(anchor)) broken.push(`${target}#${anchor}`);
        }
        expect(broken).toEqual([]);
    });

    it('links to no web address: the first run pulls the image, and clones nothing', () => {
        expect([...new Set([...ALL.matchAll(/https?:\/\/[^\s)"`]+/g)].map((m) => m[0]))]).toEqual([]);
    });
});

// ── What a client page must not hold ──

describe('docs/guide: written for a reader who is not an engineer', () => {
    it('cites no source file', () => {
        expect(ALL.match(/packages\/|\.ts\b|\.test\.|eslint|tsconfig/g) ?? []).toEqual([]);
    });

    it('never calls the licence open source, and names it where it speaks of it', () => {
        const lines = ALL.split('\n').filter((l) => /open[- ]source/i.test(l));
        expect(lines.length).toBeGreaterThan(0);
        for (const line of lines) expect(/\bnot\b/i.test(line) || line === '## Is it open source?').toBe(true);
        expect(GUIDE['README.md']).toContain('Business Source License 1.1');
        expect(GUIDE['faq.md']).toContain('Business Source License 1.1');
        expect(ALL).toContain('Inflect Ltd.');
    });

    it('says, on its first page and in its questions, what has not been done', () => {
        const flat = (text: string): string => text.replace(/\n\s*/g, ' ');
        for (const said of ['One release so far.', 'Its signatures have been checked once, by its maker', 'has not yet been run at a client', 'no independent security test', 'the planned 72-hour run has not']) {
            expect(flat(GUIDE['README.md'])).toContain(said);
        }
        expect(flat(GUIDE['faq.md'])).toContain('they were run against 0.13.2 from outside the build system');
        expect(flat(GUIDE['faq.md'])).toContain('no outside firm has tested it');
        // The technical page the guide points to for this still says the same.
        const notDone = fs.readFileSync(path.join(REPO, 'docs/threat-model.md'), 'utf8');
        for (const topic of ['penetration test', 'real estate', '72-hour soak']) expect(notDone.slice(notDone.indexOf('## What has not been done'))).toContain(topic);
    });

    it('holds no e-mail address, and speaks of "the engagement team" and "your organisation"', () => {
        expect(ALL.match(/[A-Za-z0-9._-]+@[A-Za-z0-9-]+\.[a-z]{2,}/g) ?? []).toEqual([]);
        expect(ALL).toContain('the engagement team');
        expect(ALL).toContain('your organisation');
    });
});
