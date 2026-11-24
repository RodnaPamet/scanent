/**
 * Every probe held to its class ("No damage", defined: docs/design/
 * active-flavour.md). A probe that could touch anything but the reply fails
 * the build.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { looksLikeSecret } from '@rodnapamet/scanent-contract/harness-contract';

import {
    CANARY_FIRST,
    CANARY_PATTERN,
    CANARY_SECOND,
    LEAK_SHAPES,
    PROBES,
    PROBE_CATEGORIES,
    PROBE_SOURCES,
    canaryHalves,
    makeCanary,
    probeById,
    probesFor,
    renderProbe,
} from '../src/catalogue';
import { SCOPE_PROBE_CLASSES, SCOPE_TARGET_KINDS } from '../src/scope';

const count = (text: string, needle: string) => text.split(needle).length - 1;

/** Words for an act a probe must never ask for: a write, a delete, a payment, a send. */
const ACTS = /\b(delete|remove|drop|truncate|erase|wipe|overwrite|update|modify|transfer|pay|payment|purchase|buy|refund|send|email|e-mail|forward|post|upload|publish|wire|grant|approve|revoke|disable|shut ?down|rm|kill|execute|run the command)\b/i;

describe('the catalogue', () => {
    it('gives every probe a unique id of the form class.category.n', () => {
        const ids = PROBES.map((p) => p.id);
        expect(new Set(ids).size).toBe(ids.length);
        for (const p of PROBES) expect(p.id).toMatch(new RegExp(`^${p.class}\\.${p.category}\\.\\d+$`));
    });

    it('holds only the classes version 1 allows (decision 3), and covers each', () => {
        expect(new Set(PROBES.map((p) => p.class))).toEqual(new Set(SCOPE_PROBE_CLASSES));
    });

    it('covers every category it declares, a few probes each', () => {
        for (const category of PROBE_CATEGORIES) {
            const n = PROBES.filter((p) => p.category === category).length;
            expect([category, n >= 1 && n <= 4]).toEqual([category, true]);
        }
    });

    it('cites, for every probe, categories the design page lists for that project, and nothing else of the source', () => {
        for (const p of PROBES) {
            expect(p.cites.length).toBeGreaterThan(0);
            for (const cite of p.cites) {
                expect([p.id, (PROBE_SOURCES[cite.source].categories as readonly string[]).includes(cite.category)]).toEqual([p.id, true]);
            }
        }
    });

    it('reaches targets only through the scope\'s interfaces', () => {
        for (const p of PROBES) {
            expect(p.interfaces.length).toBeGreaterThan(0);
            for (const via of p.interfaces) expect(SCOPE_TARGET_KINDS).toContain(via);
        }
    });
});

describe('no damage: what every probe may never carry', () => {
    it.each(PROBES.map((p) => [p.id, p] as const))('%s names no URL, address, host or path', (_id, p) => {
        expect(p.text).not.toMatch(/[a-z][a-z0-9+.-]*:\/\//i);
        expect(p.text).not.toMatch(/\bwww\./i);
        expect(p.text).not.toMatch(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/);
        expect(p.text).not.toMatch(/\b\d{1,3}(\.\d{1,3}){3}\b/);
        expect(p.text).not.toMatch(/(^|\s)(\/|~\/|[A-Z]:\\)\S/);
        expect(p.text).not.toMatch(/\b[a-z0-9-]+\.(com|net|org|io|dev|internal|local)\b/i);
    });

    it.each(PROBES.map((p) => [p.id, p] as const))('%s asks for no write, delete, payment or send', (_id, p) => {
        expect(p.text).not.toMatch(ACTS);
    });

    it.each(PROBES.map((p) => [p.id, p] as const))('%s carries no secret\'s shape, so a reply that repeats it discloses nothing', (_id, p) => {
        expect(looksLikeSecret(p.text)).toBe(false);
        expect(p.text.split(/\s+/).some(looksLikeSecret)).toBe(false);
    });
});

describe('a canary probe', () => {
    const canaries = PROBES.filter((p) => p.class === 'canary');

    it.each(canaries.map((p) => [p.id, p] as const))('%s shows each half once, and never the joined marker', (_id, p) => {
        expect(count(p.text, CANARY_FIRST)).toBe(1);
        expect(count(p.text, CANARY_SECOND)).toBe(1);
        const canary = makeCanary();
        const text = renderProbe(p, canary);
        expect(text).not.toContain(canary);
        expect(text.toLowerCase()).not.toContain(canary);
        const [first, second] = canaryHalves(canary);
        expect(text).toContain(first);
        expect(text).toContain(second);
        expect(text).not.toContain('{{');
    });

    it('needs its canary to be rendered, and a canary is unique and of one shape', () => {
        expect(() => renderProbe(canaries[0])).toThrow('a canary probe needs its canary');
        const a = makeCanary();
        const b = makeCanary();
        expect(a).toMatch(CANARY_PATTERN);
        expect(a).not.toBe(b);
        expect(() => canaryHalves('scanent-short')).toThrow('not a canary');
        expect(() => makeCanary(Buffer.alloc(4))).toThrow(RangeError);
    });
});

describe('a disclosure probe', () => {
    const disclosures = PROBES.filter((p) => p.class === 'disclosure');

    it.each(disclosures.map((p) => [p.id, p] as const))('%s carries no canary, and names a leak shape', (_id, p) => {
        expect(p.text).not.toContain('{{');
        if (p.class === 'disclosure') expect(LEAK_SHAPES).toContain(p.leak);
        expect(renderProbe(p)).toBe(p.text);
    });

    it('takes no canary', () => {
        expect(() => renderProbe(disclosures[0], makeCanary())).toThrow('a disclosure probe carries no canary');
    });
});

describe('selecting probes for a scope', () => {
    it('gives only the classes the scope allows, for the interface used', () => {
        expect(probesFor(['disclosure'], 'mcp').every((p) => p.class === 'disclosure' && p.interfaces.includes('mcp'))).toBe(true);
        expect(probesFor(['canary', 'disclosure'], 'http-chat').length).toBeGreaterThan(probesFor(['canary'], 'http-chat').length);
        expect(probesFor([], 'a2a')).toEqual([]);
        expect(probeById('canary.instruction-override.1')?.class).toBe('canary');
        expect(probeById('nope')).toBeUndefined();
    });
});

describe('docs/probe-catalogue.md', () => {
    it('lists every category with its class and the number of probes the catalogue holds', () => {
        const page = readFileSync(join(__dirname, '../../../docs/probe-catalogue.md'), 'utf8');
        const rows = [...page.matchAll(/^\| `([a-z-]+)` \| (canary|disclosure) \| (\d+) \|/gm)].map((m) => [m[1], m[2], Number(m[3])]);
        const expected = PROBE_CATEGORIES.map((c) => {
            const probes = PROBES.filter((p) => p.category === c);
            return [c, probes[0]?.class, probes.length];
        });
        expect(rows).toEqual(expected);
    });
});
