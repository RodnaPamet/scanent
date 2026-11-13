/**
 * `docs/contract.md` is held to the code it describes.
 *
 * The document is prose, written by hand; its limits and its lists sit
 * between `<!-- contract:<name> -->` markers, and each block is compared here
 * with the constant the code exports. A constant that changes, or a new one,
 * fails this test until the page says the same.
 */
import { existsSync, readFileSync } from 'fs';
import { resolve } from 'path';

import * as contract from '../src/harness-contract';
import {
    HARNESS_CONTRACT_IDS,
    HARNESS_CONTRACT_V1,
    HARNESS_CONTRACT_V2,
    HARNESS_CONTRACT_V3,
    HARNESS_CONTRACT_V4,
    PAYMENT_CLIENT_LIBRARIES,
    PAYMENT_PROTOCOLS,
    SOURCE_KINDS,
    SOURCE_KINDS_V2,
    SOURCE_KINDS_V3,
} from '../src/harness-contract-rules';
import { HARNESS_FINDING_CODES } from '../src/harness-findings';
import { ALL_HARNESS_CRITERIA, HARNESS_CRITERIA, HARNESS_LEVEL_NAMES, HARNESS_LEVELS, shortfallBarFor } from '../src/harness-ladder';
import { HARNESS_MATRIX_CELL_STATES } from '../src/harness-matrix-model';
import { validV3ReportBody } from './helpers/agent-harness-fake-scanner';

const DOC = readFileSync(resolve(__dirname, '..', '..', '..', 'docs', 'contract.md'), 'utf8');

function block(name: string): string {
    const open = `<!-- contract:${name} -->`;
    const close = `<!-- /contract:${name} -->`;
    const from = DOC.indexOf(open);
    const to = DOC.indexOf(close);
    if (from < 0 || to < from) throw new Error(`docs/contract.md has no ${name} block`);
    return DOC.slice(from + open.length, to);
}

/** The rows of a block's table, as cells, without the header and the rule under it. */
function rows(name: string): string[][] {
    return block(name)
        .split('\n')
        .filter((line) => line.startsWith('|'))
        .slice(2)
        .map((line) => line.split('|').slice(1, -1).map((cell) => cell.trim()));
}

const code = (cell: string): string => cell.replace(/^`|`$/g, '');
const codesIn = (cell: string): string[] => [...cell.matchAll(/`([^`]+)`/g)].map((m) => m[1]);

describe('docs/contract.md', () => {
    it('lists every contract id, and which are accepted', () => {
        const table = rows('ids');
        expect(table.map((r) => code(r[0]))).toEqual([HARNESS_CONTRACT_V1, HARNESS_CONTRACT_V2, HARNESS_CONTRACT_V3, HARNESS_CONTRACT_V4]);
        const accepted = table.filter((r) => r[1].startsWith('Accepted')).map((r) => code(r[0]));
        expect(accepted).toEqual([...HARNESS_CONTRACT_IDS]);
        expect(table.find((r) => code(r[0]) === HARNESS_CONTRACT_V1)?.[1]).toContain('Retired');
    });

    it('lists every source kind, in order, each under the id that first carries it', () => {
        const table = rows('source-kinds');
        expect(table.map((r) => code(r[0]))).toEqual([...SOURCE_KINDS]);
        expect(table.filter((r) => code(r[1]) === '/2').map((r) => code(r[0]))).toEqual([...SOURCE_KINDS_V2]);
        expect(table.filter((r) => code(r[1]) === '/3').map((r) => code(r[0]))).toEqual(SOURCE_KINDS_V3.filter((k) => !(SOURCE_KINDS_V2 as readonly string[]).includes(k)));
    });

    it('lists the payment protocols and client libraries a /4 capability can name, in order', () => {
        const table = rows('payment-libraries');
        expect(table.map((r) => code(r[0]))).toEqual([...PAYMENT_CLIENT_LIBRARIES]);
        expect([...new Set(table.map((r) => code(r[1])))]).toEqual([...PAYMENT_PROTOCOLS]);
    });

    it('lists every incomplete reason, in order', () => {
        expect(rows('incomplete-reasons').map((r) => code(r[0]))).toEqual([...contract.INCOMPLETE_REASONS]);
    });

    it('states every limit the contract exports, with its value', () => {
        const exported = Object.entries(contract)
            .filter(([name, value]) => name.startsWith('MAX_') && typeof value === 'number')
            .map(([name, value]) => [name, (value as number).toLocaleString('en-US')]);
        expect(exported.length).toBeGreaterThanOrEqual(13);
        const stated = rows('limits').map((r) => [code(r[0]), r[1]]);
        expect([...stated].sort()).toEqual([...exported].sort());
        // Each limit is also named where the page describes the member it bounds, or in the table alone.
        for (const [name] of exported) expect(DOC).toContain(`\`${name}\``);
    });

    it('lists every refusal, in the order the verifier checks', () => {
        const table = rows('refusals');
        expect(table.map((r) => code(r[1]))).toEqual([...contract.HARNESS_REFUSALS]);
        expect(table.map((r) => r[0])).toEqual(contract.HARNESS_REFUSALS.map((_, i) => String(i + 1)));
    });

    it('the order it states is the order the verifier refuses in', () => {
        const pair = contract; // the verifier under test
        const raw = JSON.stringify({ ...validV3ReportBody() });
        // Unsigned, not an object, not JSON, too large: each is met before the one after it could be.
        expect(pair.verifyAndParseHarnessReport(raw, [])).toMatchObject({ ok: false, reason: 'UNSIGNED' });
        expect(pair.verifyAndParseHarnessReport('[]', [])).toMatchObject({ ok: false, reason: 'NOT_AN_OBJECT' });
        expect(pair.verifyAndParseHarnessReport('{', [])).toMatchObject({ ok: false, reason: 'NOT_JSON' });
        expect(pair.verifyAndParseHarnessReport(' '.repeat(contract.MAX_REPORT_BYTES + 1), [])).toMatchObject({ ok: false, reason: 'TOO_LARGE' });
        // A signature that is not the three members is refused before the signer is looked up.
        expect(pair.verifyAndParseHarnessReport(JSON.stringify({ ...validV3ReportBody(), signature: { alg: 'none' } }), [])).toMatchObject({ ok: false, reason: 'MALFORMED_SIGNATURE' });
        // A well-formed signature by a key nobody trusts is refused before the body's schema is read: the body here is not a report at all.
        const stranger = { alg: 'ed25519', signerKey: 'ab'.repeat(32), sig: 'cd'.repeat(64) };
        expect(pair.verifyAndParseHarnessReport(JSON.stringify({ contract: 'not-a-contract', signature: stranger }), [])).toMatchObject({ ok: false, reason: 'UNTRUSTED_SIGNER' });
        // The same, by a key that IS trusted: the signature is checked before the schema.
        expect(pair.verifyAndParseHarnessReport(JSON.stringify({ contract: 'not-a-contract', signature: stranger }), [stranger.signerKey])).toMatchObject({ ok: false, reason: 'BAD_SIGNATURE' });
    });

    it('lists every level with its name and exactly its criteria, in ladder order', () => {
        const table = rows('levels');
        expect(table.map((r) => code(r[0]))).toEqual([...HARNESS_LEVELS]);
        for (const [level, name, criteria] of table) {
            const id = code(level) as (typeof HARNESS_LEVELS)[number];
            expect(name).toBe(HARNESS_LEVEL_NAMES[id]);
            expect(codesIn(criteria)).toEqual([...HARNESS_CRITERIA[id]]);
        }
        expect(table.flatMap((r) => codesIn(r[2]))).toEqual([...ALL_HARNESS_CRITERIA]);
    });

    it('states the bars the ladder uses, and the version of the ladder it describes', () => {
        expect(shortfallBarFor('read-only')).toBe('H2');
        expect(shortfallBarFor('write-or-external')).toBe('H3');
        expect(shortfallBarFor('unknown')).toBe('H3');
        expect(DOC).toContain('is expected at `H3`; one that only\n  reads, at `H2`');
        expect(block('ladder-version')).toContain(`\`${contract.LADDER_VERSION}\``);
    });

    it('lists the finding codes a report may carry, and the ones a reader plans', () => {
        expect(codesIn(block('report-finding-codes'))).toEqual([...contract.FINDING_CODES]);
        expect(rows('planned-finding-codes').map((r) => code(r[0]))).toEqual([...HARNESS_FINDING_CODES]);
    });

    it('lists the seven cell states of the table, in order', () => {
        expect(codesIn(block('matrix-cell-states'))).toEqual([...HARNESS_MATRIX_CELL_STATES]);
    });

    it('names the functions it refers to, and each is one the contract exports', async () => {
        const modules = [
            contract,
            await import('../src/harness-contract-rules'),
            await import('../src/harness-findings'),
            await import('../src/harness-ladder'),
            await import('../src/canonical-json'),
            await import('../src/harness-matrix-model'),
        ];
        const exported = new Set(modules.flatMap((m) => Object.keys(m)));
        const referred = ['verifyAndParseHarnessReport', 'isScanComplete', 'looksLikeSecret', 'containsCardNumber', 'firstSecretShapedMember', 'firstSecretShapedPath', 'canonicalJson', 'scoreHarness', 'collapseVerdicts', 'levelAtLeast', 'shortfallBarFor', 'planHarnessScan', 'toolEvidenceSourcesOf', 'LADDER_VERSION', 'buildHarnessMatrix', 'harnessJudgementOf', 'compareHarnessMatrixRows'];
        for (const name of referred) {
            expect(DOC).toContain(`\`${name}\``);
            expect(exported.has(name)).toBe(true);
        }
    });

    it('holds no reference to an issue of another repository, and no path outside this one', () => {
        expect(DOC).not.toMatch(/#\d{3,}/);
        expect(DOC).not.toMatch(/src\/(lib|app-layer)\//);
        for (const path of [...DOC.matchAll(/`(packages\/[A-Za-z0-9_./-]+)`/g)].map((m) => m[1])) {
            expect([path, existsSync(resolve(__dirname, '..', '..', '..', path))]).toEqual([path, true]);
        }
    });
});
