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
