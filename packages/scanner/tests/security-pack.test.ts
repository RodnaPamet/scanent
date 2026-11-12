/**
 * The engagement kit, the security intake pack and the roadmap are read by
 * people deciding whether to let the scanner into an estate. This keeps what
 * can be checked by a machine true:
 *
 *   - every repository path a page cites exists, and a function or constant
 *     cited beside a file is in that file;
 *   - every relative link resolves to a file, and a link to a heading resolves
 *     to a heading of that file;
 *   - the dependency table equals the production set of the lockfile, with the
 *     licence each installed package states;
 *   - no page calls the product open source, names a person's address, or
 *     stops saying what has not been done.
 *
 * It checks that a citation resolves. It cannot check that a sentence is true.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';

const REPO = path.resolve(__dirname, '../../..');
const read = (rel: string): string => fs.readFileSync(path.join(REPO, rel), 'utf8');
const exists = (rel: string): boolean => fs.existsSync(path.join(REPO, rel));

/** The markdown files of a directory, not recursive, by repository path. */
function pagesOf(dir: string): string[] {
    return fs
        .readdirSync(path.join(REPO, dir), { withFileTypes: true })
        .filter((e) => e.isFile() && e.name.endsWith('.md'))
        .map((e) => `${dir}/${e.name}`)
        .sort();
}

const ENGAGEMENT = pagesOf('docs/engagement');
const PACK = pagesOf('docs/security-pack');
const PAGES = [...ENGAGEMENT, ...PACK, 'docs/roadmap.md'];

/** Every repository path a page names in backticks: under a known top-level directory, or a root file. */
function citedPaths(text: string): string[] {
    const found = [
        ...text.matchAll(/`((?:packages|deploy|scripts|docs|examples|\.github)\/[A-Za-z0-9._/-]+|eslint\.config\.mjs|SECURITY\.md|README\.md|LICENSE|NOTICE|package\.json|package-lock\.json)`/g),
    ].map((m) => m[1]);
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

/** The text of a page with its fenced code blocks removed: a link or a heading inside one is not one. */
function prose(text: string): string {
    return text.replace(/^```[\s\S]*?^```$/gm, '');
}

/** The anchors GitHub gives a page's headings: lower case, punctuation dropped, spaces to hyphens. */
function anchorsOf(text: string): Set<string> {
    const anchors = new Set<string>();
    for (const m of prose(text).matchAll(/^#{1,6} +(.+?) *$/gm)) {
        const slug = m[1]
            .replace(/`/g, '')
            .toLowerCase()
            .replace(/[^\p{L}\p{N} _-]/gu, '')
            .replace(/ /g, '-');
        anchors.add(slug);
    }
    return anchors;
}

/** Each relative link of a page: the file it points at (by repository path) and its fragment, if any. */
function relativeLinks(page: string): { target: string; file: string; fragment: string | null }[] {
    return [...prose(read(page)).matchAll(/\]\((?!https?:|mailto:)([^)\s]*)\)/g)].map((m) => {
        const [rel, fragment] = m[1].split('#');
        const file = rel === '' ? page : path.relative(REPO, path.resolve(path.dirname(path.join(REPO, page)), rel));
        return { target: m[1], file, fragment: fragment ?? null };
    });
}

describe('the pages exist', () => {
    it('the engagement kit holds its five pages and an index', () => {
        expect(ENGAGEMENT.map((p) => path.basename(p))).toEqual([
            'README.md',
            'access-request-templates.md',
            'data-handling.md',
            'run-book.md',
            'sample-report.md',
            'scoping-checklist.md',
        ]);
    });

    it('the security pack holds its five pages and an index', () => {
        expect(PACK.map((p) => path.basename(p))).toEqual([
            'README.md',
            'architecture.md',
            'assurance-status.md',
            'controls.md',
            'sbom-and-licences.md',
            'support-and-maintenance.md',
        ]);
    });

    it('the root README links to both folders and to the roadmap', () => {
        const readme = read('README.md');
        for (const target of ['docs/engagement/README.md', 'docs/security-pack/README.md', 'docs/roadmap.md']) expect(readme).toContain(`(${target})`);
    });

    it('each index links to every page of its folder', () => {
        for (const [index, pages] of [
            ['docs/engagement/README.md', ENGAGEMENT],
            ['docs/security-pack/README.md', PACK],
        ] as const) {
            const linked = new Set(relativeLinks(index).map((l) => l.file));
            expect(pages.filter((p) => p !== index && !linked.has(p))).toEqual([]);
        }
    });
});

describe.each(PAGES)('%s', (page) => {
    const text = read(page);

    it('names only files and directories that exist', () => {
        // A placeholder such as `<version>` in a path is not a citation.
        expect(citedPaths(text).filter((p) => !p.includes('<') && !exists(p))).toEqual([]);
    });

    it('names, beside a file, only functions and constants that file holds', () => {
        const absent = citedSymbols(text)
            .filter(({ file, symbol }) => exists(file) && !new RegExp(`\\b${symbol}\\b`).test(read(file)))
            .map(({ file, symbol }) => `${file}: ${symbol}`);
        expect(absent).toEqual([]);
    });

    it('links only to files that exist, and to headings those files have', () => {
        const broken = relativeLinks(page)
            .filter(({ file, fragment }) => {
                if (!exists(file)) return true;
                if (fragment === null || !file.endsWith('.md')) return false;
                return !anchorsOf(read(file)).has(fragment);
            })
            .map((l) => l.target);
        expect(broken).toEqual([]);
    });

    it('does not call the product open source, and names nobody\'s address', () => {
        // Each mention of "open source" must be a denial or the licence's own conversion.
        for (const m of text.matchAll(/open[- ]source/gi)) {
            const around = text.slice(Math.max(0, m.index - 80), m.index + 80).replace(/\s+/g, ' ');
            expect(around).toMatch(/\bnot\b|\bnever\b|ever become/i);
        }
        expect(text).not.toMatch(/[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[a-z]{2,}/);
    });
});

describe('the detectors are not vacuous', () => {
    it('a path that does not exist is found, and a placeholder is not a path', () => {
        expect(citedPaths('see `packages/scanner/src/nowhere.ts` and `deploy/x`')).toEqual(['deploy/x', 'packages/scanner/src/nowhere.ts']);
        expect(exists('packages/scanner/src/nowhere.ts')).toBe(false);
    });

    it('a symbol cited beside a file is paired with it', () => {
        expect(citedSymbols('`packages/scanner/src/http.ts` (`ReadOnlyHttp`, `notThere`)')).toEqual([
            { file: 'packages/scanner/src/http.ts', symbol: 'ReadOnlyHttp' },
            { file: 'packages/scanner/src/http.ts', symbol: 'notThere' },
        ]);
        expect(/\bnotThere\b/.test(read('packages/scanner/src/http.ts'))).toBe(false);
    });

    it('a heading becomes the anchor GitHub gives it, and a heading in a code block does not count', () => {
        expect([...anchorsOf('# A title\n\n## 1. Operator to scanner\n\n### The `code` source\n\n```\n## not one\n```\n')]).toEqual([
            'a-title',
            '1-operator-to-scanner',
            'the-code-source',
        ]);
    });

    it('the pages cite a real population', () => {
        const controls = read('docs/security-pack/controls.md');
        expect(citedPaths(controls).filter((p) => p.includes('/src/')).length).toBeGreaterThanOrEqual(25);
        expect(citedPaths(controls).filter((p) => p.endsWith('.test.ts')).length).toBeGreaterThanOrEqual(30);
        expect(citedSymbols(controls).length).toBeGreaterThanOrEqual(50);
        expect(PAGES.flatMap((p) => relativeLinks(p)).length).toBeGreaterThanOrEqual(60);
    });
});

describe('docs/security-pack/controls.md', () => {
    const text = read('docs/security-pack/controls.md');

    it('has a table for each family of control the pack promises', () => {
        expect([...text.matchAll(/^## (.+)$/gm)].map((m) => m[1])).toEqual([
            'Read-only',
            'No secret values',
            'Request forgery and where requests go',
            'Time and size caps',
            'Output escaping',
            'Signing',
            'Container hardening',
            'Supply chain',
        ]);
    });

    it('every row names where the control is enforced, and all but one what proves it', () => {
        const rows = text.split('\n').filter((l) => l.startsWith('| ') && !l.startsWith('| Control') && !l.startsWith('|---'));
        expect(rows.length).toBeGreaterThanOrEqual(40);
        const unproven: string[] = [];
        for (const row of rows) {
            // Control, enforced in, proven by, limit. No cell of this page holds a `|`.
            const cells = row.split('|').slice(1, -1).map((cell) => cell.trim());
            expect(cells).toHaveLength(4);
            expect(citedPaths(cells[1])).not.toEqual([]);
            if (!/`[^`]+`|themselves/.test(cells[2])) unproven.push(cells[0]);
        }
        // The one row with no proof says so by leaving the cell empty: the weekly update proposals.
        expect(unproven).toEqual(['Dependency and base-image updates are proposed weekly']);
    });
});

describe('docs/security-pack/sbom-and-licences.md', () => {
    const text = read('docs/security-pack/sbom-and-licences.md');
    // The licence gate's own reading of the lockfile, so the page and the gate cannot disagree on what "production" is.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { productionPackages, checkLicences, ALLOWED } = require(path.join(REPO, 'scripts/check-licences.js')) as {
        productionPackages: (lock: unknown) => { key: string; version: string }[];
        checkLicences: (lock: unknown, readManifest: (key: string) => unknown) => { checked: unknown[]; problems: string[] };
        ALLOWED: readonly string[];
    };
    const lock: unknown = JSON.parse(read('package-lock.json'));
    const manifest = (key: string): { name: string; version: string; license: string } =>
        JSON.parse(read(`${key}/package.json`)) as { name: string; version: string; license: string };

    it('the dependency table is the lockfile\'s production set, with the licence each installed package states', () => {
        const block = /<!-- deps:production -->\n([\s\S]*?)<!-- \/deps:production -->/.exec(text);
        expect(block).not.toBeNull();
        const rows = (block as RegExpExecArray)[1]
            .trim()
            .split('\n')
            .slice(2)
            .map((line) => line.split('|').slice(1, 4).map((cell) => cell.trim().replace(/`/g, '')));
        const expected = productionPackages(lock).map(({ key, version }) => {
            const m = manifest(key);
            expect(m.version).toBe(version);
            return [m.name, version, m.license];
        });
        expect(expected.length).toBeGreaterThanOrEqual(4);
        expect(rows).toEqual(expected);
    });

    it('every licence in the table passes the gate, and the page lists the gate\'s allowlist exactly', () => {
        expect(checkLicences(lock, (key) => (exists(`${key}/package.json`) ? manifest(key) : null)).problems).toEqual([]);
        const listed = /with no expression evaluated:\n\n([\s\S]*?)\n\n/.exec(text);
        expect(listed).not.toBeNull();
        expect([...(listed as RegExpExecArray)[1].matchAll(/`([^`]+)`/g)].map((m) => m[1])).toEqual([...ALLOWED]);
    });

    it('states the scanner\'s version as the code has it, and the Change Date as the licence has it', () => {
        const version = /export const SCANNER_VERSION = '([0-9.]+)';/.exec(read('packages/scanner/src/scanner-surface.ts'));
        expect(version).not.toBeNull();
        expect(text).toContain(`currently\n${(version as RegExpExecArray)[1]}.`);
        expect(read('LICENSE')).toMatch(/Change Date:\s+2030-11-11/);
        expect(text).toContain('11 November 2030');
        expect(read('LICENSE')).toMatch(/Licensor:\s+Inflect Ltd\./);
        expect(text).toContain('**Inflect Ltd.**');
    });

    it('says the licence is not open source, that no SBOM has been produced, and where commercial terms come from', () => {
        expect(text).toContain('**It is not an open-source licence.**');
        expect(text).toContain('No SBOM has been produced by the release pipeline yet');
        expect(text).toContain('Commercial terms come from the\nlicensor, Inflect Ltd., and from nobody else.');
    });
});

describe('docs/security-pack/assurance-status.md', () => {
    const text = read('docs/security-pack/assurance-status.md');
    const notDone = text.slice(text.indexOf('## What has not been done'), text.indexOf('## What has been done'));

    it('says what has not been done before what has, and names each item', () => {
        expect(text.indexOf('## What has not been done')).toBeGreaterThan(0);
        expect(text.indexOf('## What has not been done')).toBeLessThan(text.indexOf('## What has been done'));
        for (const heading of ['### No pilot on a real estate', '### No external penetration test, no independent review', '### No long soak', '### No signed release']) {
            expect(notDone).toContain(heading);
        }
        for (const phrase of ['False positives and false negatives are not measured', '72-hour', 'has never been started', 'never run']) expect(notDone).toContain(phrase);
    });

    it('agrees with the threat model, which still lists the same four', () => {
        const threat = read('docs/threat-model.md');
        const theirs = threat.slice(threat.indexOf('## What has not been done'));
        for (const topic of ['penetration test', 'real estate', '72-hour soak', 'No release exists']) expect(theirs).toContain(topic);
    });

    it('claims nothing the repository cannot show: no release directory of fixtures beyond the one it names', () => {
        const compat = fs
            .readdirSync(path.join(REPO, 'packages/scanner/tests/fixtures/compat'), { withFileTypes: true })
            .filter((e) => e.isDirectory())
            .map((e) => e.name);
        expect(compat).toEqual(['0.12.0']);
        // The one directory is named for a version that has not been released: the page says which commit made it.
        expect(text).toContain('Files written by an earlier commit of the code');
        expect(text).toContain('the same unreleased version 0.12.0');
        expect(text).toContain('No released version exists to compare with');
        expect(read('packages/scanner/tests/fixtures/compat/README.md')).toContain('`0.12.0` was made from commit `190f3fb`');
        expect(text).toContain('`190f3fb`');
    });

    it('names the CI jobs as the workflow names them', () => {
        const ci = read('.github/workflows/ci.yml');
        for (const name of ['Image, under rootless Podman', 'Helm chart, installed on kind', 'Helm chart']) {
            expect(text).toContain(`| ${name} |`);
            expect(ci).toContain(`name: ${name}`);
        }
        // The SBOM step is the release workflow's alone, as the page says.
        expect(ci).not.toMatch(/sbom-action/);
        expect(read('.github/workflows/release.yml')).toMatch(/sbom-action/);
    });
});

describe('docs/security-pack/support-and-maintenance.md', () => {
    const text = read('docs/security-pack/support-and-maintenance.md');

    it('shows the source interface as the code declares it', () => {
        const shown = /```ts\n([\s\S]*?)```/.exec(text);
        expect(shown).not.toBeNull();
        const source = read('packages/scanner/src/source.ts');
        const declared = source.slice(source.indexOf('export interface HarnessSource {'));
        const strip = (s: string): string[] =>
            s
                .split('\n')
                .map((l) => l.trim())
                .filter((l) => l !== '' && !l.startsWith('/**') && !l.startsWith('*'));
        const want = strip((shown as RegExpExecArray)[1]);
        expect(strip(declared.slice(0, declared.indexOf('\n}\n') + 2))).toEqual(want);
    });

    it('gives the response times of the security policy', () => {
        const policy = read('SECURITY.md');
        for (const [phrase, theirs] of [
            ['within 5 working days', 'within 5 working days'],
            ['within 15 working days', '15 working days'],
            ['90 days', '90 days'],
        ]) {
            expect(text).toContain(phrase);
            expect(policy).toContain(theirs);
        }
    });

    it('names the schema ids the code exports', () => {
        const ids: [string, string][] = [
            ['packages/report/src/results/types.ts', 'scanent-results/1'],
            ['packages/report/src/results/inventory.ts', 'scanent-inventory/1'],
            ['packages/scanner/src/init/answers.ts', 'scanent-init-answers/1'],
            ['packages/scanner/src/doctor/types.ts', 'scanent-doctor/1'],
            ['packages/scanner/src/support-bundle.ts', 'scanent-support/1'],
        ];
        for (const [file, id] of ids) {
            expect(text).toContain(`\`${id}\``);
            expect(read(file)).toContain(`'${id}'`);
        }
    });

    it('names every npm script it tells a maintainer to run', () => {
        const scripts = (JSON.parse(read('package.json')) as { scripts: Record<string, string> }).scripts;
        const named = [...text.matchAll(/`npm run ([a-z:-]+)`/g)].map((m) => m[1]);
        expect(named.length).toBeGreaterThanOrEqual(3);
        for (const name of named) expect(Object.keys(scripts)).toContain(name);
    });
});

describe('docs/roadmap.md', () => {
    const text = read('docs/roadmap.md');

    it('says the OpenShell source cannot be used, as the code has it', () => {
        expect(text).toContain('**It cannot be used.**');
        expect(read('packages/scanner/src/http.ts')).toContain('the OpenShell gRPC transport is not built into this scanner');
        expect(read('packages/scanner/src/config.ts')).not.toMatch(/openshell/i);
    });

    it('says no source reports an H4 or H5 criterion, as the reader table has it', () => {
        expect(text).toContain('**H4 and H5: no source reports any of their nine criteria.**');
        const readers = read('packages/scanner/src/criterion-readers.ts');
        const unread = [...readers.matchAll(/^ {4}'(H\d)\.[a-z_]+': NO_READER,$/gm)].map((m) => m[1]);
        expect(unread.filter((l) => l === 'H4').length + unread.filter((l) => l === 'H5').length).toBe(9);
        expect(unread.every((l) => l === 'H4' || l === 'H5')).toBe(true);
    });

    it('says the packages are unpublished, as their manifests have it', () => {
        expect(text).toContain('**The contract package is not published.**');
        for (const pkg of ['contract', 'report', 'scanner']) {
            expect((JSON.parse(read(`packages/${pkg}/package.json`)) as { private?: boolean }).private).toBe(true);
        }
    });

    it('names the cloud platforms no source reads, and offers none as coming', () => {
        for (const name of ['AWS', 'Azure AI Foundry', 'Vertex']) expect(text).toContain(name);
        expect(text).toContain('None is a promise');
        expect(text).not.toMatch(/\b(will be|coming soon|planned for|we will|is planned)\b/i);
    });
});
