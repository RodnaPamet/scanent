/**
 * The agent scanner's part of a delivered run, for a test whose configuration
 * names an agent source. Throws when the agent scanner did not run, so a test
 * never reads an absent agent scan as an empty one.
 */
import type { AgentScan, RunScan } from '../../src/scan';

export function agentsOf(result: { readonly scan: RunScan }): AgentScan {
    if (result.scan.agents === null) throw new Error('the agent scanner did not run in this run');
    return result.scan.agents;
}
