/**
 * The seed of the property tests is the one asked for, or the run stops.
 *
 * `FUZZ_SEED=0` and a seed that was not a number were once both replaced by
 * the fixed seed without a word, so seed 0 could not be chosen and a mistyped
 * seed ran, green, on a seed nobody asked for.
 */
import { FIXED_SEED, forAll, FUZZ_SEED, seedFrom } from './helpers/prng';

describe('seedFrom', () => {
    it('is the fixed seed when the variable is unset or empty', () => {
        expect(seedFrom(undefined)).toBe(FIXED_SEED);
        expect(seedFrom('')).toBe(FIXED_SEED);
        expect(seedFrom('  ')).toBe(FIXED_SEED);
        expect(FIXED_SEED).toBe(0x5ca7e47);
    });

    it.each([
        ['0', 0],
        ['1', 1],
        ['97156679', 97156679],
        [' 42 ', 42],
        // A workflow run id is past 32 bits.
        ['19876543210', 19876543210],
        ['9007199254740991', Number.MAX_SAFE_INTEGER],
    ])('%s is used as given', (raw, seed) => {
        expect(seedFrom(raw)).toBe(seed);
    });

    it.each(['abc', '12abc', '-1', '1.5', '1e3', '0x10', '9007199254740992', '99999999999999999', 'NaN', '१२'])('%s stops the run', (raw) => {
        expect(() => seedFrom(raw)).toThrow(/FUZZ_SEED must be a whole number/);
    });

    it('this run is on the seed its environment names', () => {
        expect(FUZZ_SEED).toBe(seedFrom(process.env.FUZZ_SEED));
    });
});

describe('a property run on seed 0', () => {
    it('is its own sequence, not the fixed seed\'s, and is the same sequence every time', async () => {
        const drawn = async (seed: number): Promise<number[]> => {
            const values: number[] = [];
            await forAll('draw', (r) => r.int(0, 1_000_000), (v) => void values.push(v), { seed, iterations: 8 });
            return values;
        };
        const zero = await drawn(0);
        expect(zero).toEqual(await drawn(0));
        expect(zero).not.toEqual(await drawn(FIXED_SEED));
        expect(new Set(zero).size).toBeGreaterThan(1);
    });
});
