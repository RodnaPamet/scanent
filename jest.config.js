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
    transform: {
        '^.+\\.ts$': ['ts-jest', { tsconfig: '<rootDir>/tsconfig.json' }],
    },
};
