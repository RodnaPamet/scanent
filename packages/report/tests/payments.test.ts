/**
 * Payment capabilities (`inflect-agent-harness/4`) in the local results.
 *
 *   1. The scorer keeps the report's three states per agent, never collapsed:
 *      seen calling a payment client, read and none seen, and not reported.
 *   2. SPENDING_AGENT_UNDECLARED is the planner's, for a registered agent
 *      whose code pays, and its words say what this run saw and what it could
 *      not read: never that no spending authority exists.
 *   3. The page, the spreadsheet and the comparison of two runs carry the
 *      fact, and none of them reads "none seen" as "cannot pay", or a run
 *      that did not report it as one that saw none.
 *   4. A results file holds itself to the contract's lists, and one written
 *      before the members existed still reads.
 */
import {
    HARNESS_CONTRACT_V4,
    type HarnessReportBody,
    type HarnessReportBodyV4,
} from '@rodnapamet/scanent-contract/harness-contract';
import { planHarnessScan } from '@rodnapamet/scanent-contract/harness-findings';

import {
    PAYING_AGENT_ID,
    PAYING_AGENT_PAYMENT_AT,
    SDK_AGENT_ID,
    validV3ReportBody,
    validV4ReportBody,
} from '../../contract/tests/helpers/agent-harness-fake-scanner';
import { diffResults } from '../src/diff/diff';
import { csvPaymentCapabilities, renderAgentsCsv, renderFindingsCsv } from '../src/render/csv';
import { renderDiffText } from '../src/render/diff-text';
import { renderSummaryHtml } from '../src/render/html';
import { LocalResultsSchema } from '../src/results/schema';
import { scoreReportLocally } from '../src/results/score';
import type { LocalResults } from '../src/results/types';
import { fullRow, input, inventoryOf, withSource } from './helpers/fixtures';

const ROW = 'agt_paying_row';
const SECOND_PAYER = 'code:acme/shop-bot/refunds.ts#agent';

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

/** The `/4` fixture, edited. */
function v4(edit: (b: HarnessReportBodyV4) => void = () => {}): HarnessReportBodyV4 {
    const b = clone(validV4ReportBody());
    edit(b);
    return b;
}
const payingOf = (b: HarnessReportBodyV4) => b.agents.find((a) => a.discoveredId === PAYING_AGENT_ID)!;
/** The paying agent linked to a register row, as the register source would report it. */
const registered = (b: HarnessReportBodyV4) => {
    payingOf(b).registeredAgentId = ROW;
};
const score = (body: HarnessReportBody, opts: Parameters<typeof input>[1] = {}): LocalResults => scoreReportLocally(input(body, opts));
const agentOf = (r: LocalResults, id: string) => r.agents.find((a) => a.discoveredId === id)!;
const spending = (r: LocalResults) => r.findings.filter((f) => f.code === 'SPENDING_AGENT_UNDECLARED');
/** The same results one hour later, from a body edited by `edit`. */
const later = (edit: (b: HarnessReportBodyV4) => void, opts: Parameters<typeof input>[1] = {}): LocalResults =>
    score(
        v4((b) => {
            b.scan = { ...b.scan, id: `${b.scan.id}-later`, asOf: new Date(Date.parse(b.scan.asOf) + 3_600_000).toISOString() };
            edit(b);
        }),
        opts,
    );

describe('1. three states per agent, as the report has them', () => {
    const r = score(v4());

    it('a paying agent carries each call site; an agent whose code was read and pays nothing carries []; the rest carry null', () => {
        expect(r.scan.contract).toBe(HARNESS_CONTRACT_V4);
        expect(agentOf(r, PAYING_AGENT_ID).paymentCapabilities).toEqual([{ protocol: 'x402', library: 'x402-fetch', at: PAYING_AGENT_PAYMENT_AT }]);
        expect(agentOf(r, SDK_AGENT_ID).paymentCapabilities).toEqual([]);
        const others = r.agents.filter((a) => a.discoveredId !== PAYING_AGENT_ID && a.discoveredId !== SDK_AGENT_ID);
        expect(others.length).toBeGreaterThan(0);
        for (const a of others) expect(a.paymentCapabilities).toBeNull();
        expect(r.estate.payingAgents).toEqual([PAYING_AGENT_ID]);
    });

    it('a /3 report says nothing about payment: every agent null, and no agent pays', () => {
        const old = score(validV3ReportBody());
        for (const a of old.agents) expect(a.paymentCapabilities).toBeNull();
        expect(old.estate.payingAgents).toEqual([]);
        expect(spending(old)).toEqual([]);
    });

    it('the results pass their own schema', () => {
        for (const body of [v4(), v4(registered), validV3ReportBody()]) expect(LocalResultsSchema.safeParse(score(body)).success).toBe(true);
    });
});

describe('2. SPENDING_AGENT_UNDECLARED: the planner decides, the words say what this run saw', () => {
    it('an unregistered paying agent is a shadow agent, and no spending finding is raised for it', () => {
        const r = score(v4());
        expect(spending(r)).toEqual([]);
        expect(r.estate.shadowAgents).toContain(PAYING_AGENT_ID);
    });

    it('a registered paying agent raises it once, with the planner\'s code, key and severity', () => {
        const body = v4(registered);
        const r = score(body);
        const plan = planHarnessScan(body, {
            previousLevels: new Map(),
            registeredAgentIds: new Set([...body.agents.flatMap((a) => (a.registeredAgentId === null ? [] : [a.registeredAgentId]))]),
            acceptedShortfalls: new Set(),
            intakeClaims: new Map(),
            openOrphanCredentials: new Set(),
            spendingAuthority: new Map(),
            onRecordAsAgent: new Set(),
        });
        const planned = plan.assert.filter((f) => f.code === 'SPENDING_AGENT_UNDECLARED');
        expect(planned).toHaveLength(1);
        expect(spending(r).map((f) => [f.code, f.sourceRef, f.severity, f.type])).toEqual(planned.map((f) => [f.code, f.sourceRef, f.severity, f.type]));
        expect(spending(r)[0]).toMatchObject({ sourceRef: `SPENDING_AGENT_UNDECLARED:${ROW}`, discoveredId: PAYING_AGENT_ID, severity: 'HIGH' });
    });

    it('says where the code pays and what this run could not read, and never that no authority exists', () => {
        const [f] = spending(score(v4(registered)));
        expect(f.title).toBe(`Agent ${PAYING_AGENT_ID} can pay, and this run saw no spending authority for it`);
        expect(f.description).toContain(`x402-fetch at ${PAYING_AGENT_PAYMENT_AT}`);
        expect(f.description).toContain('registered in the register');
        expect(f.description).toContain('it does not show that no authority was declared');
        expect(f.description).toContain('does not close it');
        expect(f.description).not.toContain('The register holds no spending authority');
    });

    it('a registration from the operator\'s inventory is named as such', () => {
        const r = score(v4(), { inventory: inventoryOf([fullRow(PAYING_AGENT_ID, { name: 'Shop bot' })]) });
        const [f] = spending(r);
        expect(f.sourceRef).toBe('SPENDING_AGENT_UNDECLARED:inventory:row-1');
        expect(f.description).toContain('registered in the operator\'s inventory');
        expect(LocalResultsSchema.safeParse(r).success).toBe(true);
    });

    it('raises it on an incomplete code read too: what was read is real', () => {
        const r = score(withSource(v4(registered), 'code', 'UNPARSEABLE'));
        expect(spending(r)).toHaveLength(1);
    });

    it('two paying agents on one registration: one finding, about the registration, naming both', () => {
        const body = v4((b) => {
            registered(b);
            b.agents.push({ ...clone(payingOf(b)), discoveredId: SECOND_PAYER, paymentCapabilities: [{ protocol: 'x402', library: '@x402/axios', at: 'code://acme/shop-bot/refunds.ts#L4' }] });
        });
        const r = score(body);
        expect(spending(r)).toHaveLength(1);
        const [f] = spending(r);
        expect(f.discoveredId).toBeNull();
        expect(f.description).toContain(PAYING_AGENT_ID);
        expect(f.description).toContain(SECOND_PAYER);
        expect(f.description).toContain('@x402/axios at code://acme/shop-bot/refunds.ts#L4');
        expect(r.estate.payingAgents).toEqual([PAYING_AGENT_ID, SECOND_PAYER].sort());
        expect(renderSummaryHtml(r)).toContain('One registration, several agents');
    });
});

describe('3. the page, the spreadsheet and the comparison', () => {
    it('the page counts the paying agents, tags them in the matrix and lists each call site', () => {
        const page = renderSummaryHtml(score(v4(registered)));
        expect(page).toContain('<h2 id="payments-h">Payment capabilities</h2>');
        expect(page).toContain('Can pay');
        expect(page).toContain('Code calls a payment client');
        expect(page).toContain(PAYING_AGENT_PAYMENT_AT);
        expect(page).toContain('None seen by this run');
        expect(page).toContain('It does not read any spending limit');
    });

    it('an unregistered paying agent is sent to registration first', () => {
        expect(renderSummaryHtml(score(v4()))).toContain('Register it first: it is a shadow agent');
    });

    it('with no paying agent the page never claims that none can pay', () => {
        const none = v4((b) => {
            b.agents = b.agents.filter((a) => a.discoveredId !== PAYING_AGENT_ID);
        });
        const complete = renderSummaryHtml(score(none));
        expect(complete).toContain('None seen in the code this scan read. That is not a statement that no agent can pay');
        const incomplete = renderSummaryHtml(score(withSource(none, 'code', 'TIME_BOX')));
        expect(incomplete).toContain('The code was not read in full, so this is not a statement that no agent can pay.');
        const noCode = renderSummaryHtml(
            score(
                v4((b) => {
                    b.population = { sources: b.population.sources.filter((s) => s.kind !== 'code') };
                    b.agents = b.agents.filter((a) => !(a.discoveredVia as readonly string[]).includes('code'));
                }),
            ),
        );
        expect(noCode).toContain('This scan did not read code, so this is not a statement that no agent can pay.');
        const v3 = renderSummaryHtml(score(validV3ReportBody()));
        expect(v3).toContain('carries no payment facts');
    });

    it('a results file written before the members existed has no payment section and still renders', () => {
        const r = score(v4(registered));
        const { payingAgents: _payingAgents, ...estate } = r.estate;
        const older = { ...r, estate, agents: r.agents.map(({ paymentCapabilities: _p, ...a }) => a) } as LocalResults;
        expect(LocalResultsSchema.safeParse(older).success).toBe(true);
        const page = renderSummaryHtml(older);
        expect(page).not.toContain('payments-h');
        expect(page).not.toContain('Can pay');
    });

    it('agents.csv states each of the three states in words, and findings.csv carries the finding', () => {
        const r = score(v4(registered));
        expect(csvPaymentCapabilities(agentOf(r, PAYING_AGENT_ID))).toBe(`x402-fetch at ${PAYING_AGENT_PAYMENT_AT}`);
        expect(csvPaymentCapabilities(agentOf(r, SDK_AGENT_ID))).toBe('NONE_SEEN');
        expect(csvPaymentCapabilities(r.agents.find((a) => a.paymentCapabilities === null)!)).toBe('NOT_REPORTED');
        expect(csvPaymentCapabilities({})).toBe('NOT_REPORTED');
        const agents = renderAgentsCsv(r);
        expect(agents.split('\r\n')[0]).toContain('"paymentCapabilities"');
        expect(agents).toContain(`"x402-fetch at ${PAYING_AGENT_PAYMENT_AT}"`);
        expect(agents).toContain('"NONE_SEEN"');
        expect(renderFindingsCsv(r)).toContain('"SPENDING_AGENT_UNDECLARED"');
    });

    it('a spending finding no longer reported is not closed by the later run, whatever it shows', () => {
        const before = score(v4(registered));
        for (const edit of [
            (b: HarnessReportBodyV4) => {
                registered(b);
                payingOf(b).paymentCapabilities = [];
            },
            (b: HarnessReportBodyV4) => {
                b.agents = b.agents.filter((a) => a.discoveredId !== PAYING_AGENT_ID);
            },
        ]) {
            const diff = diffResults(before, later(edit));
            const change = diff.findings.find((f) => f.code === 'SPENDING_AGENT_UNDECLARED');
            expect(change).toMatchObject({ change: 'NOT_CONCLUDED', why: 'NOT_CLOSED_BY_A_SCAN' });
            expect(diff.outcome).not.toBe('SAME');
        }
    });

    it('a payment client no longer seen is a change in what was seen, worded as such', () => {
        const before = score(v4(registered));
        const diff = diffResults(
            before,
            later((b) => {
                registered(b);
                payingOf(b).paymentCapabilities = [];
            }),
        );
        expect(diff.attributes).toContainEqual({
            discoveredId: PAYING_AGENT_ID,
            attribute: 'payment',
            from: `CAN_PAY: x402-fetch at ${PAYING_AGENT_PAYMENT_AT}`,
            to: 'NONE_SEEN',
        });
        expect(renderDiffText(diff)).toContain('not evidence that it cannot pay');
        // And the other way: a client seen where none was.
        const back = diffResults(
            score(
                v4((b) => {
                    payingOf(b).paymentCapabilities = [];
                }),
            ),
            later(() => {}),
        );
        expect(back.attributes).toContainEqual(expect.objectContaining({ discoveredId: PAYING_AGENT_ID, attribute: 'payment', from: 'NONE_SEEN' }));
        expect(back.outcome).toBe('DIFFERENT');
    });

    it('where one run did not report payment, nothing is compared, and the diff says so', () => {
        const before = score(v4());
        const notReported = later((b) => {
            delete (payingOf(b) as { paymentCapabilities?: unknown }).paymentCapabilities;
        });
        const diff = diffResults(before, notReported);
        expect(diff.attributes.filter((a) => a.attribute === 'payment')).toEqual([]);
        expect(diff.notConcluded).toContain(`PAYMENT_NOT_COMPARED:${PAYING_AGENT_ID}`);
        // A results file written before the member: the same.
        const older = { ...before, agents: before.agents.map(({ paymentCapabilities: _p, ...a }) => a) } as LocalResults;
        expect(diffResults(older, later(() => {})).notConcluded).toContain(`PAYMENT_NOT_COMPARED:${PAYING_AGENT_ID}`);
        // Two runs that both said nothing about an agent compare nothing about it, and owe no note.
        expect(diffResults(before, later(() => {})).notConcluded.some((c) => c.startsWith('PAYMENT_NOT_COMPARED'))).toBe(false);
    });
});

describe('4. a results file is held to the contract\'s lists', () => {
    const base = () => score(v4(registered));
    const withPaying = (r: LocalResults, caps: unknown): unknown => ({
        ...r,
        agents: r.agents.map((a) => (a.discoveredId === PAYING_AGENT_ID ? { ...a, paymentCapabilities: caps } : a)),
    });

    it.each<[string, (r: LocalResults) => unknown]>([
        ['a library outside the closed list', (r) => withPaying(r, [{ protocol: 'x402', library: 'card-sdk', at: PAYING_AGENT_PAYMENT_AT }])],
        ['a protocol outside the closed list', (r) => withPaying(r, [{ protocol: 'card', library: 'x402-fetch', at: PAYING_AGENT_PAYMENT_AT }])],
        ['a place that is not a code:// locator', (r) => withPaying(r, [{ protocol: 'x402', library: 'x402-fetch', at: 'https://shop.example/pay' }])],
        ['the same call site twice', (r) => withPaying(r, [agentOf(r, PAYING_AGENT_ID).paymentCapabilities![0], agentOf(r, PAYING_AGENT_ID).paymentCapabilities![0]])],
        ['a member the schema does not know', (r) => withPaying(r, [{ protocol: 'x402', library: 'x402-fetch', at: PAYING_AGENT_PAYMENT_AT, amount: '10' }])],
        ['a paying agent that is not in the list', (r) => ({ ...r, estate: { ...r.estate, payingAgents: [] } })],
        ['a listed paying agent whose facts show no payment', (r) => ({ ...r, estate: { ...r.estate, payingAgents: [PAYING_AGENT_ID, SDK_AGENT_ID] } })],
        ['a paying agent listed twice', (r) => ({ ...r, estate: { ...r.estate, payingAgents: [PAYING_AGENT_ID, PAYING_AGENT_ID] } })],
    ])('refuses %s', (_label, mutate) => {
        expect(LocalResultsSchema.safeParse(base()).success).toBe(true);
        expect(LocalResultsSchema.safeParse(mutate(base())).success).toBe(false);
    });
});
