/**
 * The documents a security team reads cite files, functions and tests. Each
 * citation must resolve: a path that exists, and where a function is named
 * beside a file, a file that holds it.
 *
 * A threat model whose mitigations point at code that moved is worse than one
 * with no pointers. This fails when a cited file is renamed or removed, or a
 * cited function no longer appears in the file it is cited from.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';

const REPO = path.resolve(__dirname, '../../..');
const exists = (rel: string): boolean => fs.existsSync(path.join(REPO, rel));

const DOCUMENTS = [
    'SECURITY.md',
    'docs/threat-model.md',
    'docs/data-protection.md',
    'docs/operations.md',
    'docs/verify-a-release.md',
    'docs/release-checklist.md',
] as const;

/** Every repository path a document names in backticks: under a known top-level directory, or a root file. */
function citedPaths(text: string): string[] {
    const found = [...text.matchAll(/`((?:packages|deploy|scripts|docs|examples|\.github)\/[A-Za-z0-9._/-]+|eslint\.config\.mjs|SECURITY\.md|README\.md|package\.json)`/g)].map((m) => m[1]);
    return [...new Set(found)].sort();
}

/** `path` (`symbol`, `symbol`) pairs: a file and the names cited from it. */
function citedSymbols(text: string): { file: string; symbol: string }[] {
    const out: { file: string; symbol: string }[] = [];
    for (const m of text.matchAll(/`((?:packages|deploy|scripts)\/[A-Za-z0-9._/-]+\.(?:ts|js|sh))` \(((?:`[A-Za-z_][A-Za-z0-9_]*`(?:, )?)+)\)/g)) {
        for (const s of m[2].matchAll(/`([A-Za-z_][A-Za-z0-9_]*)`/g)) out.push({ file: m[1], symbol: s[1] });
    }
    return out;
}

describe.each(DOCUMENTS)('%s', (document) => {
    const text = fs.readFileSync(path.join(REPO, document), 'utf8');

    it('exists and is not a stub', () => {
        expect(text.length).toBeGreaterThan(1500);
    });

    it('names only files and directories that exist', () => {
        // A placeholder such as `<version>` in a path is not a citation.
        const missing = citedPaths(text).filter((p) => !p.includes('<') && !exists(p));
        expect(missing).toEqual([]);
    });

    it('names, beside a file, only functions and constants that file holds', () => {
        const absent = citedSymbols(text)
            .filter(({ file, symbol }) => exists(file) && !new RegExp(`\\b${symbol}\\b`).test(fs.readFileSync(path.join(REPO, file), 'utf8')))
            .map(({ file, symbol }) => `${file}: ${symbol}`);
        expect(absent).toEqual([]);
    });

    it('links only to documents that exist', () => {
        const broken = [...text.matchAll(/\]\((?!https?:|#)([^)#\s]+)(?:#[^)]*)?\)/g)]
            .map((m) => m[1])
            .filter((target) => !fs.existsSync(path.resolve(path.dirname(path.join(REPO, document)), target)));
        expect(broken).toEqual([]);
    });
});

describe('docs/threat-model.md', () => {
    const text = fs.readFileSync(path.join(REPO, 'docs/threat-model.md'), 'utf8');

    it('cites a real population: source files with functions, and the tests that hold them', () => {
        const paths = citedPaths(text);
        expect(paths.filter((p) => p.startsWith('packages/') && p.includes('/src/')).length).toBeGreaterThanOrEqual(15);
        expect(paths.filter((p) => p.includes('/tests/') && p.endsWith('.test.ts')).length).toBeGreaterThanOrEqual(25);
        expect(citedSymbols(text).length).toBeGreaterThanOrEqual(40);
    });

    it('has a table for each of the eight boundaries, and every row names what holds it', () => {
        const sections = text.split(/^### /m).slice(1);
        expect(sections.map((s) => s.slice(0, 2))).toEqual(['1.', '2.', '3.', '4.', '5.', '6.', '7.', '8.']);
        for (const section of sections) {
            const rows = section.split('\n').filter((l) => /^\| [STRIDE, ]+ \|/.test(l));
            expect(rows.length).toBeGreaterThanOrEqual(3);
            for (const row of rows) {
                const cells = row.split(' | ');
                // Threat, mitigation, held by: none is empty, and the last names a test, a script step, or says what does.
                expect(cells.length).toBeGreaterThanOrEqual(4);
                expect(cells[cells.length - 1]).toMatch(/`[^`]+`|The gates themselves/);
            }
        }
    });

    it('covers each letter of STRIDE somewhere', () => {
        const letters = new Set(
            text
                .split('\n')
                .flatMap((l) => /^\| ([STRIDE, ]+) \|/.exec(l)?.[1].split(', ') ?? []),
        );
        expect([...letters].sort()).toEqual(['D', 'E', 'I', 'R', 'S', 'T']);
    });

    it('states its residual risks and what has not been done, plainly', () => {
        const residual = text.slice(text.indexOf('## Residual risks'), text.indexOf('## What has not been done'));
        expect((residual.match(/^\d+\. \*\*/gm) ?? []).length).toBeGreaterThanOrEqual(8);
        for (const topic of ['more than read access', 'provider that lies', 'Okta API tokens', 'secret-shaped object key', 'DNS rebinding']) expect(residual).toContain(topic);
        const notDone = text.slice(text.indexOf('## What has not been done'));
        for (const topic of ['penetration test', 'real estate', '72-hour soak']) expect(notDone).toContain(topic);
    });
});

describe('docs/data-protection.md', () => {
    const text = fs.readFileSync(path.join(REPO, 'docs/data-protection.md'), 'utf8');

    it('has a row for every source kind, and the eight parts of the DPIA template', () => {
        for (const kind of ['entra-sp', 'okta-app', 'vault', 'inflect-register', 'cicd', 'gcp-sa', 'runtime', 'mcp', 'code']) expect(text).toContain(`\`${kind}\``);
        expect([...text.matchAll(/^### (\d)\. /gm)].map((m) => Number(m[1]))).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    });

    it('says what the owner fields are, as the sources read them', () => {
        const src = (rel: string): string => fs.readFileSync(path.join(REPO, 'packages/scanner/src/sources', rel), 'utf8');
        // The claims of the table, each against the line of code it describes.
        expect(src('entra.ts')).toContain("source: 'entra-owner'");
        expect(src('okta.ts')).toContain("source: 'okta-app-profile'");
        expect(src('okta.ts')).toContain("source: 'okta-api-token'");
        expect(src('azure-key-vault.ts')).toMatch(/owner === null \? null : \{ kind: 'user', id: owner/);
        // The sources the page says yield no owner report none.
        for (const file of ['github-actions.ts', 'gcp-service-accounts.ts', 'langsmith.ts']) expect(src(file)).toMatch(/owner: null/);
    });
});

describe('SECURITY.md', () => {
    const text = fs.readFileSync(path.join(REPO, 'SECURITY.md'), 'utf8');

    it('sends a report to private vulnerability reporting, and gives no e-mail address', () => {
        expect(text).toContain('https://github.com/RodnaPamet/scanent/security/advisories/new');
        expect(text).not.toMatch(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}/);
        for (const heading of ['## Reporting a vulnerability', '## What to expect', '## In scope', '## Out of scope', '## Supported versions']) expect(text).toContain(heading);
    });
});

describe('docs/release-checklist.md', () => {
    const text = fs.readFileSync(path.join(REPO, 'docs/release-checklist.md'), 'utf8');

    it('covers the settings, before, the tag and after, and the rule for compatibility fixtures', () => {
        expect([...text.matchAll(/^## (.+)$/gm)].map((m) => m[1])).toEqual(['Settings that must be on', 'Before the tag', 'The tag', 'After the tag', 'What has never been run']);
        for (const setting of ['Private vulnerability reporting', 'Secret scanning', 'push protection', 'Branch protection', 'Tag protection']) expect(text).toContain(setting);
        expect(text).toContain('packages/scanner/tests/fixtures/compat/<version>/');
        expect(text).toContain('No earlier directory is removed');
    });

    it('names commands and jobs that exist', () => {
        const scripts = (JSON.parse(fs.readFileSync(path.join(REPO, 'package.json'), 'utf8')) as { scripts: Record<string, string> }).scripts;
        for (const m of text.matchAll(/`npm run ([a-z:-]+)/g)) expect(Object.keys(scripts)).toContain(m[1]);
        const ci = fs.readFileSync(path.join(REPO, '.github/workflows/ci.yml'), 'utf8');
        for (const job of ['checks', 'image', 'chart', 'chart-install', 'image-podman']) {
            expect(text).toContain(`\`${job}\``);
            expect(ci).toMatch(new RegExp(`^  ${job}:$`, 'm'));
        }
        const release = fs.readFileSync(path.join(REPO, '.github/workflows/release.yml'), 'utf8');
        for (const job of ['build', 'bundle', 'publish', 'release']) expect(release).toMatch(new RegExp(`^  ${job}:$`, 'm'));
    });
});
