/**
 * WHICH READER CAN ANSWER WHICH CRITERION.
 *
 * A level is the ladder's rule over the verdicts a scan reported, and
 * unanswered counts as no. That is right, and it is also easy to misread: an
 * agent at H1 in a run with no reader for `H2.policy_card` did not fail that
 * criterion, nobody looked. This table is what lets a result say so. For each
 * criterion it names the readers that report a verdict about it (`reportedBy`)
 * and, among them, the ones that can report it MET (`metBy`).
 *
 * `metBy` is the smaller set on purpose. The `code` source reports NOT MET only
 * (code can show a control is missing, never that one works), and Okta's
 * `H2.credential_bound` verdict is always about an API token that acts as a
 * person, which is NOT MET. A reader that can only fail a criterion does not
 * make it reachable.
 *
 * `'inventory'` is the operator's inventory file: it declares the four H1
 * criteria and nothing above them.
 *
 * Exhaustive by type: a criterion added to the ladder is a compile error here
 * until somebody says who reads it. Held to the readers themselves by
 * `tests/criterion-readers.test.ts`, which reads each source's code for the
 * criteria it names and runs each source for the verdicts it reports.
 *
 * The OpenShell reader is not listed: no configuration selects it, so no run
 * can have it as a reader.
 */
import type { HarnessSourceKind } from '@scanent/contract/harness-findings';
import type { CriterionReaders, ReaderKind } from '@scanent/report/results/types';

import type { ScannerConfig } from './config';

const both = (...readers: ReaderKind[]) => ({ reportedBy: readers, metBy: readers });
const NO_READER = { reportedBy: [], metBy: [] } as const;

export const CRITERION_READERS: CriterionReaders = Object.freeze({
    'H1.registered': both('inflect-register', 'inventory'),
    'H1.owner': both('inflect-register', 'inventory'),
    'H1.axes_declared': both('inflect-register', 'inventory'),
    'H1.tier_scored_fresh': both('inflect-register', 'inventory'),

    'H2.credential_bound': {
        reportedBy: ['entra-sp', 'okta-app', 'gcp-sa', 'cicd', 'inflect-register'],
        metBy: ['entra-sp', 'gcp-sa', 'cicd', 'inflect-register'],
    },
    'H2.grant_kind_declared': both('okta-app', 'gcp-sa', 'cicd', 'inflect-register'),
    'H2.tools_allowlisted': { reportedBy: ['cicd', 'inflect-register', 'code'], metBy: ['cicd', 'inflect-register'] },
    'H2.audience_tokens': both('inflect-register'),
    'H2.policy_card': both('inflect-register'),

    'H3.manifests_pinned': both('inflect-register'),
    'H3.payloads_guarded': { reportedBy: ['inflect-register', 'code'], metBy: ['inflect-register'] },
    'H3.propose_not_commit': { reportedBy: ['inflect-register', 'code'], metBy: ['inflect-register'] },
    'H3.prior_state_reads': both('inflect-register'),
    'H3.skills_declared': { reportedBy: ['inflect-register', 'code'], metBy: ['inflect-register'] },
    'H3.delegation_narrows': both('inflect-register'),
    'H3.egress_enforced': both('inflect-register'),

    'H4.ledger_baseline': NO_READER,
    'H4.receipts': NO_READER,
    'H4.kill_switch_drilled': NO_READER,
    'H4.token_budget': NO_READER,

    'H5.asi_coverage': NO_READER,
    'H5.evidence_emitted': NO_READER,
    'H5.skills_evaluated': NO_READER,
    'H5.sample_audit': NO_READER,
    'H5.independent_audit': NO_READER,
});

/** The source kinds one configuration reads, in the order it lists them. */
export function configuredSourceKinds(config: Pick<ScannerConfig, 'sources'>): HarnessSourceKind[] {
    return config.sources.map((s) => s.kind);
}
