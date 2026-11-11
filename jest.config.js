/**
 * One Jest project over every package's tests. `@scanent/contract/*` is mapped
 * to the contract's source, so the tests run without a prior build.
 */
module.exports = {
    testEnvironment: 'node',
    roots: ['<rootDir>/packages'],
    testMatch: ['**/tests/**/*.test.ts'],
    moduleNameMapper: {
        '^@scanent/contract/(.*)$': '<rootDir>/packages/contract/src/$1',
    },
    // Every source file counts, including one no test loads: a file that is
    // never imported would otherwise be absent from the denominator.
    collectCoverageFrom: ['packages/*/src/**/*.ts'],
    coverageDirectory: '<rootDir>/coverage',
    coverageReporters: ['text-summary', 'json-summary', 'lcov'],
    coverageThreshold: {
        global: { statements: 80, branches: 80, functions: 80, lines: 80 },
    },
    transform: {
        '^.+\\.ts$': ['ts-jest', { tsconfig: '<rootDir>/tsconfig.json' }],
    },
};
