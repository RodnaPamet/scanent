/**
 * The agent-rules evaluation corpus, read from disk.
 *
 * The corpus lives in `packages/scanner/evaluation/agent-rules/cases/`. Each
 * case is one subject — an MCP tool definition — written the way a server would
 * serve it: `case.json` says whether it is poisoned or clean and, when
 * poisoned, which rule ids must fire, and `input.txt.corpus` holds the text the
 * rules read (the tool's description). The `.corpus` suffix keeps the planted
 * payloads out of scanent's own secret and text scans, as the vulnerability
 * corpus does.
 *
 * The digest covers every case's `case.json` and its input, by path and
 * content, so one changed byte is another corpus.
 */
import { createHash } from 'crypto';
import { readdirSync, readFileSync, statSync } from 'fs';
import { join } from 'path';

import { canonicalJson } from '@rodnapamet/scanent-contract/canonical-json';
import { AGENT_RULES, type AgentRule } from '@rodnapamet/scanent-contract/agent-rules';
import { AGENT_RULES_SUBJECT_KINDS } from '@rodnapamet/scanent-contract/agent-rules-contract-rules';
import type { AgentRulesCase, AgentRulesCorpus } from '@rodnapamet/scanent-contract/agent-rules-evaluation';
import { z } from 'zod';

/** Where the corpus sits in a checkout or the image: beside `dist/`, in the scanner package. */
export const DEFAULT_CORPUS_DIR = join(__dirname, '..', 'evaluation', 'agent-rules', 'cases');

export const CORPUS_INPUT_FILE = 'input.txt.corpus';

const CaseFileSchema = z
    .object({
        kind: z.enum(AGENT_RULES_SUBJECT_KINDS),
        disposition: z.enum(['poisoned', 'clean']),
        expected: z.array(z.object({ ruleId: z.string().min(1) }).strict()),
    })
    .strict()
    .superRefine((c, ctx) => {
        if ((c.disposition === 'clean') !== (c.expected.length === 0)) {
            ctx.addIssue({ code: 'custom', message: 'a clean case plants nothing, and a poisoned one plants a rule', path: ['expected'] });
        }
    });

export class AgentRulesCorpusError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'AgentRulesCorpusError';
    }
}

/**
 * Read and check the corpus: every case file parses, every input is under the
 * `.corpus` name, every planted rule id is one the rule set declares, and each
 * case id is used once. Throws `AgentRulesCorpusError` naming the first problem.
 */
export function loadAgentRulesCorpus(dir: string = DEFAULT_CORPUS_DIR): AgentRulesCorpus {
    const ruleIds = new Set(AGENT_RULES.map((r: AgentRule) => r.id));
    const cases: AgentRulesCase[] = [];
    const digestParts: string[] = [];
    const seen = new Set<string>();

    for (const caseId of readdirSync(dir).sort()) {
        const caseDir = join(dir, caseId);
        if (!statSync(caseDir).isDirectory()) throw new AgentRulesCorpusError(`${caseId}: not a case directory`);
        if (!/^[a-z0-9][a-z0-9-]{0,80}$/.test(caseId)) throw new AgentRulesCorpusError(`${caseId}: a case id is lower-case, digits and hyphens`);
        if (seen.has(caseId)) throw new AgentRulesCorpusError(`${caseId}: used twice`);
        seen.add(caseId);

        const raw = readFileSync(join(caseDir, 'case.json'), 'utf8');
        const parsed = CaseFileSchema.safeParse(JSON.parse(raw));
        if (!parsed.success) throw new AgentRulesCorpusError(`${caseId}/case.json: ${parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`);
        for (const e of parsed.data.expected) {
            if (!ruleIds.has(e.ruleId)) throw new AgentRulesCorpusError(`${caseId}: plants ${e.ruleId}, which the rule set does not declare`);
        }

        const files = readdirSync(caseDir).filter((f) => f !== 'case.json');
        if (files.length !== 1 || files[0] !== CORPUS_INPUT_FILE) {
            throw new AgentRulesCorpusError(`${caseId}: a case holds exactly ${CORPUS_INPUT_FILE} beside case.json`);
        }
        const text = readFileSync(join(caseDir, CORPUS_INPUT_FILE), 'utf8');
        if (text.length === 0) throw new AgentRulesCorpusError(`${caseId}: its input is empty`);

        digestParts.push(`${caseId}/case.json\u0000${createHash('sha256').update(canonicalJson(parsed.data), 'utf8').digest('hex')}`);
        digestParts.push(`${caseId}/${CORPUS_INPUT_FILE}\u0000${createHash('sha256').update(text, 'utf8').digest('hex')}`);
        cases.push({ id: caseId, kind: parsed.data.kind, text, disposition: parsed.data.disposition, expected: parsed.data.expected });
    }
    if (cases.length === 0) throw new AgentRulesCorpusError('the corpus has no case');

    const digest = `sha256:${createHash('sha256').update(digestParts.sort().join('\n'), 'utf8').digest('hex')}`;
    return { digest, cases };
}
