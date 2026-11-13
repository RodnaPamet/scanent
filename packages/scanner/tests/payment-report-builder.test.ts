/**
 * `/4`'s payment capabilities through the report builder and the JavaScript
 * reader:
 *
 *   1. The member is stated exactly when a source stated it, `[]` included,
 *      and absent otherwise: "not reported" is never written as "none".
 *   2. One agent's capabilities merge once per (library, locator), in order,
 *      and past the cap the `code` read is INCOMPLETE `BYTE_CAP`, never cut
 *      silently.
 *   3. The scanner refuses to sign what the contract would refuse.
 *   4. A dynamic `import(…)` reaches the payment reader as a call named
 *      `import`, which no identifier can spell.
 */
import { generateKeyPairSync } from 'crypto';

import { MAX_PAYMENT_CAPABILITIES_PER_AGENT, verifyAndParseHarnessReport } from '@rodnapamet/scanent-contract/harness-contract';
import { buildReportBody, rawPublicKeyHex, ReportRefusedLocally, signReport } from '../src/report';
import type { Observation, ObservedPaymentCapability, SourceRead } from '../src/source';
import { readJavaScript } from '../src/sources/code/javascript';

const IDENTITY = { scanId: 'scan-pay-builder', asOf: new Date('2026-11-13T00:00:00Z'), scannerAgentId: 'agt_scanner' };
const AGENT = 'code:acme/shop/agent.ts#agent';

const cap = (line: number, library: ObservedPaymentCapability['library'] = 'x402-fetch'): ObservedPaymentCapability => ({
    protocol: 'x402',
    library,
    at: `code://acme/shop/agent.ts#L${line}`,
});

function observation(over: Partial<Observation> = {}): Observation {
    return { discoveredId: AGENT, owner: null, credentials: [], verdicts: [], ...over };
}

function read(kind: SourceRead['kind'], observations: readonly Observation[]): SourceRead {
    return { kind, status: 'COMPLETE', rows: observations.length, observations };
}

const agentOf = (body: ReturnType<typeof buildReportBody>) => body.agents.find((a) => a.discoveredId === AGENT)!;

describe('1. stated exactly when a source stated it', () => {
    it('a code read that saw a payment client carries it; one that saw none carries []', () => {
        expect(agentOf(buildReportBody(IDENTITY, [read('code', [observation({ paymentCapabilities: [cap(5)] })])])).paymentCapabilities).toEqual([cap(5)]);
        const quiet = agentOf(buildReportBody(IDENTITY, [read('code', [observation({ paymentCapabilities: [] })])]));
        expect(quiet).toHaveProperty('paymentCapabilities', []);
    });

    it('an agent no source stated it for carries no member at all', () => {
        const body = buildReportBody(IDENTITY, [read('entra-sp', [observation({ discoveredId: 'entra:sp:1' })])]);
        expect(Object.keys(body.agents[0])).not.toContain('paymentCapabilities');
        expect(body.contract).toBe('inflect-agent-harness/4');
    });
});

describe('2. merged once each, in order, and a cap is reported', () => {
    it('two observations of one agent merge by library and locator, sorted', () => {
        const body = buildReportBody(IDENTITY, [
            read('code', [observation({ paymentCapabilities: [cap(9), cap(5)] }), observation({ paymentCapabilities: [cap(5), cap(7, '@x402/fetch')] })]),
        ]);
        expect(agentOf(body).paymentCapabilities).toEqual([cap(7, '@x402/fetch'), cap(5), cap(9)]);
        expect(body.population.sources).toEqual([{ kind: 'code', status: 'COMPLETE', rows: 2 }]);
    });

    it('past the cap the code read is INCOMPLETE BYTE_CAP, and what is kept still verifies', () => {
        const many = Array.from({ length: MAX_PAYMENT_CAPABILITIES_PER_AGENT + 3 }, (_, i) => cap(i + 1));
        const body = buildReportBody(IDENTITY, [read('code', [observation({ paymentCapabilities: many })])]);
        expect(agentOf(body).paymentCapabilities).toHaveLength(MAX_PAYMENT_CAPABILITIES_PER_AGENT);
        expect(body.population.sources).toEqual([{ kind: 'code', status: 'INCOMPLETE', reason: 'BYTE_CAP', rows: 1 }]);
        expect(body.findings.map((f) => f.evidence)).toEqual(['source:code#BYTE_CAP']);
        const keys = generateKeyPairSync('ed25519');
        expect(verifyAndParseHarnessReport(signReport(body, keys), [rawPublicKeyHex(keys.publicKey)])).toMatchObject({ ok: true, complete: false });
    });
});

describe('3. what the contract refuses is never signed', () => {
    const keys = generateKeyPairSync('ed25519');

    it('a capability on an agent no code read found', () => {
        const body = buildReportBody(IDENTITY, [read('runtime', [observation({ paymentCapabilities: [cap(5)] })])]);
        expect(() => signReport(body, keys)).toThrow(ReportRefusedLocally);
    });

    it('a capability located anywhere but code, and never echoing the value', () => {
        const body = buildReportBody(IDENTITY, [read('code', [observation({ paymentCapabilities: [{ protocol: 'x402', library: 'x402-fetch', at: 'https://shop.example/pay' }] })])]);
        expect(() => signReport(body, keys)).toThrow(/paymentCapabilities/);
        expect(() => signReport(body, keys)).not.toThrow(/shop\.example/);
    });

    it('a card number written into a locator', () => {
        const pan = ['5555', '5555', '5555', '4444'].join('');
        const body = buildReportBody(IDENTITY, [read('code', [observation({ paymentCapabilities: [{ protocol: 'x402', library: 'x402-fetch', at: `code://acme/${pan}#L1` }] })])]);
        let message = '';
        try {
            signReport(body, keys);
        } catch (err) {
            message = (err as Error).message;
        }
        expect(message).toMatch(/refused to sign/);
        expect(message).not.toContain(pan);
    });
});

describe('4. a dynamic import is named, so the payment reader can hold it', () => {
    it('`import(x)` is a call of the reference `import`; an ordinary call keeps its callee', () => {
        const facts = readJavaScript('agent.ts', "const name = process.env.LIB;\nconst mod = await import(name);\nconst other = load(name);\n");
        const callees = facts.calls.map(({ call }) => (call.fn.k === 'ref' ? call.fn.name : call.fn.k));
        expect(callees).toContain('import');
        expect(callees).toContain('load');
        expect(facts.imports.has('import')).toBe(false);
    });
});
