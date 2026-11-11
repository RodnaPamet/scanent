// scanent's lint rules. Two jobs:
//
//   1. typescript-eslint's recommended set over every package's source and
//      tests;
//   2. the structural boundaries a type-check cannot hold: what each package
//      may import, that the `code` source reads an estate's code and never
//      runs it, and that local results are pure functions of their input.
//
// The boundary blocks were ported from the repository scanent was extracted
// from (docs/EXTRACTION.md). There the boundary was an allowlist of
// application modules; here it is the package's own declared dependencies.
import { readFileSync } from 'node:fs';
import { builtinModules } from 'node:module';

import js from '@eslint/js';
import tseslint from 'typescript-eslint';

/** A package's declared run-time dependencies, read from its manifest so the rule cannot drift from it. */
function declaredDependencies(manifestPath) {
    const manifest = JSON.parse(readFileSync(new URL(manifestPath, import.meta.url), 'utf8'));
    return Object.keys(manifest.dependencies ?? {});
}

const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');

/**
 * One `no-restricted-imports` pattern that refuses every bare specifier other
 * than a Node built-in or one of `allowed` (the package itself or a subpath).
 * Relative imports are left to `package-closure.test.ts`, which resolves them
 * and refuses one that leaves the package's `src`.
 *
 * A regex rather than a `group` with negations: gitignore semantics cannot
 * re-include a name under an excluded parent.
 */
function onlyDeclaredImports(allowed, message, { builtins: admitBuiltins = true } = {}) {
    const builtins = builtinModules.filter((m) => !m.startsWith('_')).map(escapeRegex);
    const names = allowed.map(escapeRegex);
    const admitted = [
        ...(admitBuiltins ? [`(node:)?(${builtins.join('|')})(/.*)?`] : []),
        ...(names.length > 0 ? [`(${names.join('|')})(/.*)?`] : []),
    ];
    return { regex: `^(?!\\.{1,2}(/|$))(?!(${admitted.join('|')})$)`, message };
}

const SCANNER_IMPORT_PATTERNS = [
    onlyDeclaredImports(
        declaredDependencies('./packages/scanner/package.json'),
        'The scanner runs in a client estate. It imports @scanent/contract, Node built-ins and the dependencies packages/scanner/package.json declares, and nothing else.',
    ),
];

const CONTRACT_IMPORT_PATTERNS = [
    onlyDeclaredImports(
        declaredDependencies('./packages/contract/package.json'),
        'The contract is pure: Node built-ins and the dependencies packages/contract/package.json declares, and nothing else.',
    ),
];

const REPORT_IMPORT_PATTERNS = [
    onlyDeclaredImports(
        declaredDependencies('./packages/report/package.json'),
        'Local results are pure functions: @scanent/contract and the dependencies packages/report/package.json declares, and no Node built-in.',
        { builtins: false },
    ),
];

/**
 * A module loaded at run time is an import the rules above cannot see: a
 * computed specifier names nothing a pattern can match. Neither package's
 * source loads one, so both forms are refused outright.
 */
const NO_RUNTIME_MODULE_LOADING = [
    { selector: 'ImportExpression', message: 'No module is loaded at run time: use a static import, which the import boundary checks.' },
    {
        selector: "CallExpression[callee.name='require']",
        message: 'No module is loaded at run time: use a static import, which the import boundary checks.',
    },
];

/** Modules that run code, load code or start another process. */
const CODE_RUNNING_MODULES = ['child_process', 'vm', 'worker_threads', 'module', 'cluster', 'inspector'];

export default tseslint.config(
    {
        ignores: ['**/dist/**', '**/node_modules/**', 'coverage/**', 'examples/**', '**/tests/fixtures/**'],
    },
    {
        linterOptions: { reportUnusedDisableDirectives: 'error' },
    },
    js.configs.recommended,
    ...tseslint.configs.recommended,
    {
        files: ['**/*.ts'],
        rules: {
            // A leading underscore marks a parameter or binding kept for its
            // position or its name; everything else unused is an error.
            '@typescript-eslint/no-unused-vars': [
                'error',
                { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrorsIgnorePattern: '^_', ignoreRestSiblings: true },
            ],
        },
    },
    {
        // ── What the contract may import ──
        files: ['packages/contract/src/**/*.ts'],
        rules: {
            'no-restricted-imports': ['error', { patterns: CONTRACT_IMPORT_PATTERNS }],
            'no-restricted-syntax': ['error', ...NO_RUNTIME_MODULE_LOADING],
        },
    },
    {
        // ── Local results are a function of their input ──
        //
        // Scoring, the inventory rules and (later) the renderers turn data
        // into data or text. The same scan must give the same results on any
        // machine at any time, so nothing here may reach a file, the network,
        // the process, the clock or a random source: the scanner does the
        // reading and the hashing and hands the values in. No Node built-in
        // is importable at all.
        files: ['packages/report/src/**/*.ts'],
        rules: {
            'no-restricted-imports': ['error', { patterns: REPORT_IMPORT_PATTERNS }],
            'no-restricted-syntax': [
                'error',
                ...NO_RUNTIME_MODULE_LOADING,
                {
                    selector: "NewExpression[callee.name='Date'][arguments.length=0]",
                    message: 'Local results read no clock: take the time from the scan (`asOf`).',
                },
                {
                    // `Date()` called as a function is the current time as text.
                    selector: "CallExpression[callee.name='Date']",
                    message: 'Local results read no clock: take the time from the scan (`asOf`).',
                },
                {
                    // `const D = Date; new D()` would pass the two rules above.
                    selector: "VariableDeclarator[init.name='Date'], AssignmentExpression[right.name='Date']",
                    message: 'Local results read no clock: `Date` is not given another name.',
                },
            ],
            'no-restricted-globals': [
                'error',
                // `globalThis` (and its older names) reaches every one of the others by another path.
                ...[
                    'process', 'fetch', 'Buffer', 'setTimeout', 'setInterval', 'setImmediate', 'queueMicrotask',
                    'crypto', 'performance', 'navigator', 'WebSocket', 'XMLHttpRequest', 'EventSource',
                    'globalThis', 'global', 'self', 'window',
                ].map((name) => ({
                    name,
                    message: 'Local results are pure: no process, network, buffer, timer, clock or random source.',
                })),
            ],
            'no-restricted-properties': [
                'error',
                { object: 'Date', property: 'now', message: 'Local results read no clock: take the time from the scan (`asOf`).' },
                { object: 'Math', property: 'random', message: 'Local results are deterministic.' },
            ],
        },
    },
    {
        // ── What the scanner may import ──
        //
        // The scanner runs in a CLIENT's estate, with that estate's
        // credentials and its own signing key beside it. Whatever it can
        // import is what an estate has to trust, so the set is the manifest's
        // and no wider: a new dependency is a reviewed line in
        // packages/scanner/package.json before it is an import.
        files: ['packages/scanner/src/**/*.ts'],
        rules: {
            'no-restricted-imports': ['error', { patterns: SCANNER_IMPORT_PATTERNS }],
            'no-restricted-syntax': ['error', ...NO_RUNTIME_MODULE_LOADING],
        },
    },
    {
        // ── The `code` source READS an estate's code and never runs it ──
        //
        // The LangChain, LangGraph and Agent SDK detector parses files it did
        // not write, from a repository a client controls. Loading one (a
        // `require`, a dynamic `import()`, an interpreter, `eval`) would hand
        // that repository code execution inside the scanner, beside its
        // signing key. So nothing in the source's files can reach any of them.
        // The side-effect test in packages/scanner/tests/langchain-code-source.test.ts
        // is the behavioural half.
        //
        // This block REPLACES the scanner block's `no-restricted-imports` and
        // `no-restricted-syntax` for these files, so it carries the same
        // patterns and its own, wider, syntax list.
        files: ['packages/scanner/src/sources/code/**/*.ts', 'packages/scanner/src/sources/langchain.ts'],
        rules: {
            'no-restricted-imports': [
                'error',
                {
                    paths: CODE_RUNNING_MODULES.flatMap((name) =>
                        [name, `node:${name}`].map((n) => ({
                            name: n,
                            message: 'The code source reads code and never runs it: no subprocess, VM, worker or module loader.',
                        })),
                    ),
                    patterns: SCANNER_IMPORT_PATTERNS,
                },
            ],
            'no-restricted-syntax': [
                'error',
                { selector: 'ImportExpression', message: 'The code source never loads a module at run time.' },
                { selector: "CallExpression[callee.name='require']", message: 'The code source never loads a module at run time.' },
                { selector: "CallExpression[callee.name='eval']", message: 'The code source never evaluates text.' },
                {
                    selector: "NewExpression[callee.name='Function'], CallExpression[callee.name='Function']",
                    message: 'The code source never evaluates text.',
                },
            ],
        },
    },
    {
        files: ['**/*.mjs'],
        languageOptions: { globals: { URL: 'readonly', process: 'readonly', console: 'readonly' } },
    },
    {
        // Plain Node scripts: the Jest configuration and the image's smoke check.
        files: ['**/*.js', '**/*.cjs'],
        languageOptions: {
            sourceType: 'commonjs',
            globals: { require: 'readonly', module: 'writable', process: 'readonly', __dirname: 'readonly', console: 'readonly' },
        },
        rules: { '@typescript-eslint/no-require-imports': 'off' },
    },
);
