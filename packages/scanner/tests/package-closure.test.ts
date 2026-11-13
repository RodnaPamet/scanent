/**
 * What each package ships is exactly what it runs.
 *
 * In the repository scanent was extracted from, one test held the scanner
 * image to the scanner's import closure: every application module the scanner
 * imports was copied, and no other. Here the closure is a package boundary,
 * and it can go wrong in the same two ways:
 *
 *   • a source file imports something its package does not declare: the
 *     build passes on a developer's machine, where a hoisted `node_modules`
 *     has it, and fails at the first start of an installed package;
 *   • a package declares a dependency nothing imports: surface for nothing.
 *
 * The imports are read with the TypeScript parser, the way the compiler sees
 * them. A type-only import is erased on build and so is not in the closure.
 */
import * as fs from 'node:fs';
import { builtinModules } from 'node:module';
import * as path from 'node:path';
import * as ts from 'typescript';

const REPO_ROOT = path.resolve(__dirname, '../../..');
const BUILTINS = new Set(builtinModules.flatMap((m) => [m, `node:${m}`]));

function sourceFiles(dir: string): string[] {
    return fs
        .readdirSync(dir, { withFileTypes: true })
        .flatMap((e) => (e.isDirectory() ? sourceFiles(path.join(dir, e.name)) : e.name.endsWith('.ts') ? [path.join(dir, e.name)] : []))
        .sort();
}

/** Every module specifier a file imports or re-exports at run time. */
function runtimeSpecifiers(file: string): string[] {
    const source = ts.createSourceFile(file, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.ES2022, true);
    const out: string[] = [];
    const visit = (node: ts.Node): void => {
        if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
            if (!node.importClause?.isTypeOnly) out.push(node.moduleSpecifier.text);
        } else if (ts.isExportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
            if (!node.isTypeOnly) out.push(node.moduleSpecifier.text);
        } else if (
            ts.isCallExpression(node) &&
            (node.expression.kind === ts.SyntaxKind.ImportKeyword || (ts.isIdentifier(node.expression) && node.expression.text === 'require')) &&
            node.arguments.length === 1 &&
            ts.isStringLiteral(node.arguments[0])
        ) {
            out.push(node.arguments[0].text);
        }
        ts.forEachChild(node, visit);
    };
    visit(source);
    return out;
}

interface Closure {
    readonly files: readonly string[];
    readonly packages: readonly string[];
    /** Relative imports that leave the package's own `src`. */
    readonly escapes: readonly string[];
    readonly aliased: readonly string[];
}

function closureOf(pkg: string): Closure {
    const src = path.join(REPO_ROOT, 'packages', pkg, 'src');
    const files = sourceFiles(src);
    const packages = new Set<string>();
    const escapes: string[] = [];
    const aliased: string[] = [];
    for (const file of files) {
        for (const spec of runtimeSpecifiers(file)) {
            const where = `${path.relative(REPO_ROOT, file)} -> ${spec}`;
            if (spec.startsWith('@/')) aliased.push(where);
            else if (spec.startsWith('.')) {
                const target = path.resolve(path.dirname(file), spec);
                if (!target.startsWith(src + path.sep) || !fs.existsSync(`${target}.ts`)) escapes.push(where);
            } else if (!BUILTINS.has(spec)) {
                // `zod/v4` and `zod` are one package.
                const [scopeOrName, name] = spec.split('/');
                packages.add(scopeOrName.startsWith('@') ? `${scopeOrName}/${name}` : scopeOrName);
            }
        }
    }
    return { files: files.map((f) => path.relative(src, f)), packages: [...packages].sort(), escapes, aliased };
}

/** Every Node built-in a package's source imports at run time, as `file -> specifier`. */
function builtinImportsOf(pkg: string): string[] {
    const src = path.join(REPO_ROOT, 'packages', pkg, 'src');
    return sourceFiles(src).flatMap((file) =>
        runtimeSpecifiers(file)
            .filter((spec) => BUILTINS.has(spec))
            .map((spec) => `${path.relative(REPO_ROOT, file)} -> ${spec}`),
    );
}

const manifest = (pkg: string) =>
    JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'packages', pkg, 'package.json'), 'utf8')) as {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
        bin?: Record<string, string>;
    };

describe('each package ships its import closure, and nothing else', () => {
    const contract = closureOf('contract');
    const scanner = closureOf('scanner');

    it('computes a closure at all', () => {
        // The denominator. An empty walk would make every equality below hold.
        expect(scanner.files).toEqual(expect.arrayContaining(['cli.ts', 'scan.ts', 'sources/code/recognize.ts']));
        expect(scanner.files.length).toBeGreaterThanOrEqual(25);
        expect(scanner.packages).toContain('@rodnapamet/scanent-contract');
    });

    it('the contract is the eight files the scanner ran with before the extraction, the shared table model, and the integrations contract, and no other', () => {
        expect(contract.files).toEqual([
            'audit-redact.ts',
            'canonical-json.ts',
            'cidr.ts',
            'harness-contract-rules.ts',
            'harness-contract.ts',
            'harness-findings.ts',
            'harness-ladder.ts',
            'harness-matrix-model.ts',
            'integrations-contract-rules.ts',
            'integrations-contract.ts',
            'integrations-findings.ts',
            'integrations-scopes.ts',
            'receipt-verification.ts',
        ]);
    });

    it('no source file reaches outside its own package by a relative path or an application alias', () => {
        expect([...contract.escapes, ...scanner.escapes]).toEqual([]);
        expect([...contract.aliased, ...scanner.aliased]).toEqual([]);
    });

    it('the contract imports no other package of this repository', () => {
        // Its own scope is the registry's (the repository owner's); the other two packages keep theirs.
        expect(contract.packages.filter((p) => p.startsWith('@scanent/') || p.startsWith('@rodnapamet/'))).toEqual([]);
    });

    it('declares each package the closure imports, and nothing else', () => {
        for (const [pkg, closure] of [['contract', contract], ['scanner', scanner]] as const) {
            expect([pkg, Object.keys(manifest(pkg).dependencies ?? {}).sort()]).toEqual([pkg, closure.packages]);
            expect(manifest(pkg).devDependencies).toBeUndefined();
        }
    });

    it('pins each third-party package to an exact version', () => {
        for (const pkg of ['contract', 'scanner']) {
            for (const [name, version] of Object.entries(manifest(pkg).dependencies ?? {})) {
                expect(`${name}@${version}`).toMatch(/@\d+\.\d+\.\d+$/);
            }
        }
    });

    describe('the report package', () => {
        const report = closureOf('report');

        it('computes a closure at all', () => {
            expect(report.files).toEqual(expect.arrayContaining(['results/score.ts', 'results/inventory.ts']));
            expect(report.files.length).toBeGreaterThanOrEqual(5);
        });

        it('reaches outside its own source by no relative path and no application alias', () => {
            expect(report.escapes).toEqual([]);
            expect(report.aliased).toEqual([]);
        });

        it('imports the contract and zod, and no other package', () => {
            expect(report.packages).toEqual(['@rodnapamet/scanent-contract', 'zod']);
        });

        it('imports no Node built-in: local results are functions of their input', () => {
            expect(builtinImportsOf('report')).toEqual([]);
            // The reader is not vacuous: the scanner does import built-ins.
            expect(builtinImportsOf('scanner').length).toBeGreaterThan(0);
        });

        it('declares exactly what it imports, each third-party package at an exact version', () => {
            expect(Object.keys(manifest('report').dependencies ?? {}).sort()).toEqual(report.packages);
            expect(manifest('report').devDependencies).toBeUndefined();
            expect(manifest('report').dependencies?.zod).toMatch(/^\d+\.\d+\.\d+$/);
            // One zod across the repository: a second copy would be a second set of schema classes.
            expect(manifest('report').dependencies?.zod).toBe(manifest('contract').dependencies?.zod);
        });

        it('is imported by the scanner and never by the contract', () => {
            expect(scanner.packages).toContain('@scanent/report');
            expect(contract.packages).not.toContain('@scanent/report');
        });
    });

    it('runs the CLI the closure was computed from, under both of its names', () => {
        // Both names are the committed launcher, and the launcher starts the
        // compiled form of the file the closure was computed from.
        expect(manifest('scanner').bin).toEqual({ scanent: './bin/scanent.js', aes: './bin/scanent.js' });
        const launcher = fs.readFileSync(path.join(REPO_ROOT, 'packages/scanner/bin/scanent.js'), 'utf8');
        expect(launcher).toContain("path.join(__dirname, '..', 'dist', 'cli.js')");
        expect(scanner.files).toContain('cli.ts');
    });
});
