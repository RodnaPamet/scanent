/**
 * The agent-rules evaluation corpus and the scorer: every planted rule fires,
 * nothing fires on a clean case, and the digest binds every byte.
 */
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { AGENT_RULES, runAgentRules } from '@rodnapamet/scanent-contract/agent-rules';
import { agentRulesRegressionPasses, AgentRulesEvaluationError, scoreAgentRules, type AgentRuleRun } from '@rodnapamet/scanent-contract/agent-rules-evaluation';
import { AgentRulesCorpusError, DEFAULT_CORPUS_DIR, loadAgentRulesCorpus } from '../src/agent-rules-corpus';

describe('the agent-rules corpus', () => {
    const corpus = loadAgentRulesCorpus();

    it('plants a case for a good share of the rules, beside clean ones', () => {
        const poisoned = corpus.cases.filter((c) => c.disposition === 'poisoned');
        const clean = corpus.cases.filter((c) => c.disposition === 'clean');
        expect(poisoned.length).toBeGreaterThanOrEqual(AGENT_RULES.length);
        expect(clean.length).toBeGreaterThanOrEqual(4);
        expect(corpus.digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    });

    it('scores the real rule set with every planted rule fired and nothing on clean', () => {
        const score = scoreAgentRules(corpus, runAgentRules);
        expect(score.missed).toBe(0);
        expect(score.missedRefs).toEqual([]);
        expect(score.falseOnClean).toBe(0);
        expect(score.falseRefs).toEqual([]);
        expect(score.fired).toBeGreaterThanOrEqual(AGENT_RULES.length);
        expect(agentRulesRegressionPasses(score)).toBe(true);
    });

    it('covers every rule the set declares', () => {
        const planted = new Set(corpus.cases.flatMap((c) => c.expected.map((e) => e.ruleId)));
        for (const r of AGENT_RULES) expect(planted.has(r.id)).toBe(true);
    });

    it('is a real detector: a run that fires nothing misses every planted rule (mutation proof)', () => {
        const dead: AgentRuleRun = () => [];
        const score = scoreAgentRules(corpus, dead);
        expect(score.missed).toBeGreaterThan(0);
        expect(agentRulesRegressionPasses(score)).toBe(false);
    });

    it('refuses a corpus with nothing planted', () => {
        expect(() => scoreAgentRules({ digest: corpus.digest, cases: [{ id: 'c', kind: 'mcp-tool', text: 'x', disposition: 'clean', expected: [] }] })).toThrow(
            new AgentRulesEvaluationError('EMPTY_CORPUS'),
        );
    });

    describe('on a copy', () => {
        let dir: string;
        beforeEach(() => {
            dir = mkdtempSync(join(tmpdir(), 'scanent-agent-rules-'));
            cpSync(DEFAULT_CORPUS_DIR, dir, { recursive: true });
        });
        afterEach(() => rmSync(dir, { recursive: true, force: true }));

        it('gives the same digest for the same bytes and another for a changed input', () => {
            expect(loadAgentRulesCorpus(dir).digest).toBe(corpus.digest);
            const f = join(dir, 'read-file', 'input.txt.corpus');
            writeFileSync(f, readFileSync(f, 'utf8') + ' extra');
            expect(loadAgentRulesCorpus(dir).digest).not.toBe(corpus.digest);
        });

        it('refuses a clean case that plants a rule, and an unknown rule id', () => {
            const cj = join(dir, 'read-file', 'case.json');
            writeFileSync(cj, JSON.stringify({ kind: 'mcp-tool', disposition: 'clean', expected: [{ ruleId: AGENT_RULES[0].id }] }));
            expect(() => loadAgentRulesCorpus(dir)).toThrow(/clean case plants nothing/);
            writeFileSync(cj, JSON.stringify({ kind: 'mcp-tool', disposition: 'poisoned', expected: [{ ruleId: 'cisco-mcp:no-such-rule' }] }));
            expect(() => loadAgentRulesCorpus(dir)).toThrow(/does not declare/);
        });

        it('refuses a case with an extra file, an empty input, or no case', () => {
            writeFileSync(join(dir, 'read-file', 'stray.txt'), 'x');
            expect(() => loadAgentRulesCorpus(dir)).toThrow(AgentRulesCorpusError);
            rmSync(join(dir, 'read-file', 'stray.txt'));
            writeFileSync(join(dir, 'read-file', 'input.txt.corpus'), '');
            expect(() => loadAgentRulesCorpus(dir)).toThrow(/empty/);
            const empty = mkdtempSync(join(tmpdir(), 'scanent-agent-rules-empty-'));
            try {
                expect(() => loadAgentRulesCorpus(empty)).toThrow(/no case/);
            } finally {
                rmSync(empty, { recursive: true, force: true });
            }
        });
    });
});
