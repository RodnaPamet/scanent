/**
 * The source refers to nothing a reader of this repository cannot open.
 *
 * The contract and the scanner were moved here from another repository, and
 * their comments cited that repository's issue numbers, the dates of decisions
 * recorded there, and paths of documents and modules that exist only there.
 * Each was replaced by the reason it stood for, or by a reference to
 * `docs/contract.md`. This holds them out.
 *
 * `docs/EXTRACTION.md` keeps the one statement of where the code came from.
 */
import { existsSync, readdirSync, readFileSync } from 'fs';
import { join, relative, resolve } from 'path';

const REPO = resolve(__dirname, '..', '..', '..');
const TREES = ['packages/contract/src', 'packages/scanner/src'];

function sources(): string[] {
    const out: string[] = [];
    const walk = (dir: string): void => {
        for (const entry of readdirSync(dir, { withFileTypes: true })) {
            const full = join(dir, entry.name);
            if (entry.isDirectory()) walk(full);
            else if (entry.name.endsWith('.ts')) out.push(relative(REPO, full));
        }
    };
    for (const tree of TREES) walk(join(REPO, tree));
    return out.sort();
}

/** What a line may not hold, and why. */
const FORBIDDEN: readonly (readonly [string, RegExp])[] = [
    ['an issue number of another repository', /#\d{4}\b/],
    ['a decision cited by who made it and when, in place of its reason', /\bowner(?:'s)? (?:decisions?|rulings?|answers?)\b|\bOwner (?:decision|answer|ruling)\b/],
    ['a decision cited by its date', /\b(?:decision|ruling|answer)s?,? (?:of )?20\d\d-\d\d-\d\d\b/],
    ['a condition of an assessment that is not in this repository', /\bDPIA\b/],
    ['a module path of the originating application', /\bsrc\/(?:lib|app-layer)\/|@\/lib\//],
    ['a test path of the originating repository', /\btests\/(?:unit|guards|guardrails|integration)\//],
    ['a document of the originating repository', /\bdocs\/(?:agent-harness-contract|agentic-[a-z-]+|claude-[a-z-]+|implementation-notes\/|guides\/)[A-Za-z0-9./-]*/],
    ['a deployment file of the originating repository', /docker-compose\.harness-scanner/],
];

describe('comments in the contract and the scanner', () => {
    const files = sources();

    it('the trees are the two that were moved, and they hold source', () => {
        expect(files.length).toBeGreaterThan(50);
        expect(files.some((f) => f.startsWith('packages/contract/src/'))).toBe(true);
        expect(files.some((f) => f.startsWith('packages/scanner/src/sources/'))).toBe(true);
    });

    it.each(FORBIDDEN)('no line holds %s', (_what, pattern) => {
        const hits: string[] = [];
        for (const file of files) {
            readFileSync(join(REPO, file), 'utf8')
                .split('\n')
                .forEach((line, i) => {
                    if (pattern.test(line)) hits.push(`${file}:${i + 1}`);
                });
        }
        expect(hits).toEqual([]);
    });

    it('every document a comment points at is in this repository', () => {
        const missing: string[] = [];
        for (const file of files) {
            for (const m of readFileSync(join(REPO, file), 'utf8').matchAll(/\bdocs\/[A-Za-z0-9._/-]+\.md\b/g)) {
                if (!existsSync(join(REPO, m[0]))) missing.push(`${file}: ${m[0]}`);
            }
        }
        expect(missing).toEqual([]);
    });

    it('the detector is live: each rule matches the kind of line it was written for', () => {
        const samples: readonly (readonly [number, string])[] = [
            [0, ' * The LangSmith source (#3738).'],
            [1, ' * off unless the estate opts in (owner decision, 2026-10-19).'],
            [1, " * The owner's ruling is that such a host is validated."],
            [2, ' * as decided, decision of 2026-11-08.'],
            [3, ' * and nothing else (DPIA condition 1).'],
            [4, ' * (`src/lib/security/egress-allowlist.ts`)'],
            [5, ' * `tests/unit/agent-harness-scanner/x.test.ts` holds it.'],
            [6, ' * See docs/agentic-iam-roadmap.md.'],
            [6, ' * `docs/agent-harness-contract.md` (Transport)'],
            [7, ' * (`deploy/docker-compose.harness-scanner.yml`)'],
        ];
        for (const [rule, line] of samples) expect([line, FORBIDDEN[rule][1].test(line)]).toEqual([line, true]);
        // And what must stay sayable: a scan id, a hex colour, a document of this repository, an owner of an agent.
        for (const line of [' * `docs/contract.md` (Transport)', ' * the owner of the agent', " * the estate's owner decides", ' * color #1a1f24', ' * version 2025-06-18']) {
            expect([line, FORBIDDEN.some(([, pattern]) => pattern.test(line))]).toEqual([line, false]);
        }
    });
});
