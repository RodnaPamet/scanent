/**
 * A large estate for the renderer's scale tests: `n` agents cloned from the
 * standalone fixture's two shapes, with an inventory that registers a few so
 * the rest are shadow agents, and `unbound` credentials bound to no agent.
 *
 * Everything is derived from the index, so the same arguments give the same
 * results. Each agent that holds an unpinned write tool raises three findings
 * (shadow agent, unpinned write tool, shortfall), as the planner has it.
 */
import type { HarnessReportBodyV3 } from '@rodnapamet/scanent-contract/harness-contract';

import { scoreReportLocally } from '../../src/results/score';
import type { LocalResults } from '../../src/results/types';
import { fullRow, input, inventoryOf, standaloneBody } from './fixtures';

export const scaleAgentId = (i: number): string => `entra:sp:agent-${String(i).padStart(5, '0')}`;

export function scaleBody(n: number, unbound = 0): HarnessReportBodyV3 {
    const base = standaloneBody();
    const [writer, reader] = base.agents;
    return {
        ...base,
        population: { sources: base.population.sources.map((s) => ({ ...s, rows: n })) },
        agents: Array.from({ length: n }, (_, i) => {
            const shape = i % 2 === 0 ? writer : reader;
            return {
                ...shape,
                discoveredId: scaleAgentId(i),
                credentials: [
                    { ref: `entra://sp/agent-${i}/password/1`, ageDays: i % 400, expires: true, boundToAgent: true, grant: 'unknown' as const },
                    { ref: `entra://sp/agent-${i}/key/1`, ageDays: i % 90, expires: false, boundToAgent: true, grant: 'unknown' as const },
                ],
            };
        }),
        unboundCredentials: Array.from({ length: unbound }, (_, i) => ({ ref: `entra://app/unused-${i}/password/1`, sourceKind: 'entra-sp' as const })),
    };
}

/** `n` agents scored with an inventory naming `declared` of them and `absent` agents the scan did not find. */
export function scaleResults(n: number, opts: { unbound?: number; declared?: number; absent?: number } = {}): LocalResults {
    const rows = [
        ...Array.from({ length: opts.declared ?? 3 }, (_, i) => fullRow(scaleAgentId(i), { name: `Declared ${i}` })),
        ...Array.from({ length: opts.absent ?? 0 }, (_, i) => fullRow(`entra:sp:absent-${String(i).padStart(5, '0')}`, { name: `Absent ${i}` })),
    ];
    return scoreReportLocally(input(scaleBody(n, opts.unbound ?? 0), { inventory: inventoryOf(rows) }));
}
