/**
 * The names of the files one run writes. Fixed here so the page that lists
 * them, the writer that creates them and the tests that read them agree.
 */
export const RUN_FILE_NAMES = {
    report: 'report.signed.json',
    results: 'results.json',
    agents: 'agents.csv',
    findings: 'findings.csv',
    summary: 'summary.html',
    pdf: 'report.pdf',
    manifest: 'manifest.json',
} as const;

export type RunFileName = (typeof RUN_FILE_NAMES)[keyof typeof RUN_FILE_NAMES];

/**
 * The files the integrations scanner adds to a run that configured it, and
 * only to such a run: an agents-only run writes `RUN_FILE_NAMES` and nothing
 * else, as it did before there were two scanners. The signed report's name
 * is `report.<scanner>.signed.json` (`docs/design/scanners.md`).
 */
export const INTEGRATION_RUN_FILE_NAMES = {
    report: 'report.integrations.signed.json',
    applications: 'integrations.csv',
    findings: 'integration-findings.csv',
} as const;

/**
 * The files of a run in which only the integrations scanner ran: its signed
 * report and its CSVs, and the results, page, PDF and manifest every run has.
 * No agent file: no agent scan ran, and an empty `agents.csv` would read as one
 * that found nothing.
 */
export const INTEGRATIONS_ONLY_RUN_FILE_NAMES = {
    report: INTEGRATION_RUN_FILE_NAMES.report,
    results: RUN_FILE_NAMES.results,
    applications: INTEGRATION_RUN_FILE_NAMES.applications,
    findings: INTEGRATION_RUN_FILE_NAMES.findings,
    summary: RUN_FILE_NAMES.summary,
    pdf: RUN_FILE_NAMES.pdf,
    manifest: RUN_FILE_NAMES.manifest,
} as const;
