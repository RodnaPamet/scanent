/**
 * The rules of the vulnerabilities report contract that need no hashing: its
 * id, its closed lists, its severity cap and its limits.
 *
 * They live apart from `vulnerabilities-contract.ts` for the reason the
 * harness's and the integrations' do: the planner
 * (`vulnerabilities-findings.ts`) is something a browser may run, and the
 * contract verifies signatures with `crypto`. Keep this module free of Node
 * built-ins.
 *
 * The method is Cloudflare's `security-audit-skill` (MIT): reconnaissance,
 * hunting by attack class, an independent attempt to refute each candidate,
 * and a verdict. The vocabulary a finding is labelled with is the one
 * SnailSploit's `Claude-Red` (MIT) reports in: a CWE id, an OWASP Top 10 or
 * API Security Top 10 category, and a MITRE ATT&CK technique where one
 * applies. See docs/design/vulnerability-scanner.md.
 */

/**
 * The vulnerability scanner's first contract: what a static, model-assisted
 * review of a client's code found, where it rests in the code, and what was
 * not reviewed. A strict schema of its own beside `inflect-agent-harness/*`
 * and `scanent-integrations/*`, verified by the same signature and
 * canonical-JSON rules, and read by nothing that reads either of them.
 */
export const VULNERABILITIES_CONTRACT_V1 = 'scanent-vulnerabilities/1';

/** Every id the vulnerabilities verifier accepts. */
export const VULNERABILITIES_CONTRACT_IDS = [VULNERABILITIES_CONTRACT_V1] as const;
export type VulnerabilitiesContractId = (typeof VULNERABILITIES_CONTRACT_IDS)[number];

/**
 * The attack classes a review hunts by, in the order Cloudflare's
 * `ATTACK-CLASSES.md` lists them: its nine general classes, then its ten
 * companion domains. A closed list on the wire: a class the list does not
 * name is a different scanner, not a new string.
 */
export const ATTACK_CLASSES = [
    'injection',
    'access-control',
    'resource-and-file-handling',
    'cryptography-and-secrets',
    'business-logic',
    'feature-abuse-and-data-leakage',
    'chained-trust-boundaries',
    'wildcard',
    'obvious-things',
    'memory-safety-and-binary',
    'ai-and-llm',
    'web-protocol-and-auth',
    'client-side',
    'supply-chain-and-release',
    'cloud-and-deployment',
    'protocols-rpc-and-messaging',
    'resource-exhaustion-and-availability',
    'data-isolation-and-lifecycle',
    'desktop-mobile-and-local-ipc',
] as const;
export type AttackClass = (typeof ATTACK_CLASSES)[number];

/** Each class's name in words, for the outputs. */
export const ATTACK_CLASS_TITLE: Readonly<Record<AttackClass, string>> = Object.freeze({
    injection: 'Injection',
    'access-control': 'Access control',
    'resource-and-file-handling': 'Resource and file handling',
    'cryptography-and-secrets': 'Cryptography and secrets',
    'business-logic': 'Business logic',
    'feature-abuse-and-data-leakage': 'Feature abuse and data leakage',
    'chained-trust-boundaries': 'Chained vulnerabilities and trust boundaries',
    wildcard: 'Outside the standard classes',
    'obvious-things': 'Basic exposures',
    'memory-safety-and-binary': 'Memory safety and binary',
    'ai-and-llm': 'AI, LLM and agents',
    'web-protocol-and-auth': 'Web protocol and authentication',
    'client-side': 'Client side and browser',
    'supply-chain-and-release': 'Supply chain and release',
    'cloud-and-deployment': 'Cloud and deployment',
    'protocols-rpc-and-messaging': 'Protocols, RPC and messaging',
    'resource-exhaustion-and-availability': 'Resource exhaustion and availability',
    'data-isolation-and-lifecycle': 'Data isolation and lifecycle',
    'desktop-mobile-and-local-ipc': 'Desktop, mobile and local IPC',
});

/**
 * The verdicts a finding can carry. Cloudflare's third verdict, `rejected`, is
 * never a finding: a candidate the refutation broke is reported as a count
 * (`counts.rejected`), never as a record.
 */
export const VULNERABILITY_VERDICTS = ['confirmed', 'needs_validation'] as const;
export type VulnerabilityVerdict = (typeof VULNERABILITY_VERDICTS)[number];

/** Severities, lowest first. There is no CRITICAL: no model finding is ever one. */
export const VULNERABILITY_SEVERITIES = ['INFO', 'LOW', 'MEDIUM', 'HIGH'] as const;
export type VulnerabilitySeverity = (typeof VULNERABILITY_SEVERITIES)[number];

/**
 * The highest severity each verdict may carry. A `confirmed` finding, whose
 * trace resolves in the code and survived the refutation, may be HIGH: the
 * code itself shows the path. A `needs_validation` one at most MEDIUM: what
 * would make it real is a fact the review could not see. A person confirms
 * every finding either way (docs/design/vulnerability-scanner.md). A report
 * that states more is refused, not lowered: lowering is the scanner's job
 * (`capSeverity`), before it signs.
 */
export const SEVERITY_CAP: Readonly<Record<VulnerabilityVerdict, VulnerabilitySeverity>> = Object.freeze({
    confirmed: 'HIGH',
    needs_validation: 'MEDIUM',
});

const rank = (s: VulnerabilitySeverity): number => VULNERABILITY_SEVERITIES.indexOf(s);

/** Whether `severity` is within its verdict's cap. */
export function withinSeverityCap(verdict: VulnerabilityVerdict, severity: VulnerabilitySeverity): boolean {
    return rank(severity) <= rank(SEVERITY_CAP[verdict]);
}

/**
 * A model's severity, held to its verdict's cap. Anything the model says that
 * is not one of the four (CRITICAL included) is taken as the cap: a model
 * that answers higher is lowered, never trusted.
 */
export function capSeverity(verdict: VulnerabilityVerdict, answered: string): VulnerabilitySeverity {
    const cap = SEVERITY_CAP[verdict];
    const known = (VULNERABILITY_SEVERITIES as readonly string[]).includes(answered) ? (answered as VulnerabilitySeverity) : cap;
    return rank(known) <= rank(cap) ? known : cap;
}

/** The model's confidence in a finding, as Cloudflare's schema scores it. */
export const VULNERABILITY_CONFIDENCE = ['low', 'medium', 'high'] as const;
export type VulnerabilityConfidence = (typeof VULNERABILITY_CONFIDENCE)[number];

/** The kinds of step in a trace: from where untrusted input enters to where it does harm. */
export const TRACE_STEP_KINDS = ['entrypoint', 'propagation', 'sink'] as const;
export type TraceStepKind = (typeof TRACE_STEP_KINDS)[number];

/** OWASP Top 10, 2021 edition. */
export const OWASP_TOP_10_2021 = ['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10'] as const;
export const OWASP_TOP_10_2021_TITLE: Readonly<Record<(typeof OWASP_TOP_10_2021)[number], string>> = Object.freeze({
    A01: 'Broken Access Control',
    A02: 'Cryptographic Failures',
    A03: 'Injection',
    A04: 'Insecure Design',
    A05: 'Security Misconfiguration',
    A06: 'Vulnerable and Outdated Components',
    A07: 'Identification and Authentication Failures',
    A08: 'Software and Data Integrity Failures',
    A09: 'Security Logging and Monitoring Failures',
    A10: 'Server-Side Request Forgery',
});

/** OWASP API Security Top 10, 2023 edition. */
export const OWASP_API_TOP_10_2023 = ['API1', 'API2', 'API3', 'API4', 'API5', 'API6', 'API7', 'API8', 'API9', 'API10'] as const;
export const OWASP_API_TOP_10_2023_TITLE: Readonly<Record<(typeof OWASP_API_TOP_10_2023)[number], string>> = Object.freeze({
    API1: 'Broken Object Level Authorization',
    API2: 'Broken Authentication',
    API3: 'Broken Object Property Level Authorization',
    API4: 'Unrestricted Resource Consumption',
    API5: 'Broken Function Level Authorization',
    API6: 'Unrestricted Access to Sensitive Business Flows',
    API7: 'Server Side Request Forgery',
    API8: 'Security Misconfiguration',
    API9: 'Improper Inventory Management',
    API10: 'Unsafe Consumption of APIs',
});

/** A CWE id: `CWE-` and its number. */
export const CWE_ID = /^CWE-[1-9][0-9]{0,4}$/;
/** A MITRE ATT&CK technique id, with its sub-technique where there is one. */
export const ATTACK_TECHNIQUE_ID = /^T[0-9]{4}(?:\.[0-9]{3})?$/;

/**
 * A repository's label, as the `code` source names it in a locator: short,
 * lower-case, no slash.
 */
export const REPOSITORY_LABEL = /^[a-z0-9][a-z0-9._-]{0,62}$/;

/**
 * A place in the code: `code://<label>/<path>#L<start>-L<end>`. A path is
 * relative to the repository, uses `/`, and has no `.` or `..` segment. Never
 * the code itself.
 */
export const CODE_RANGE_LOCATOR =
    /^code:\/\/([a-z0-9][a-z0-9._-]{0,62})\/((?:[A-Za-z0-9_@+=,-][A-Za-z0-9._@+=,-]*\/)*[A-Za-z0-9_@+=,-][A-Za-z0-9._@+=,-]*)#L([1-9][0-9]{0,6})-L([1-9][0-9]{0,6})$/;

export interface CodeRange {
    readonly label: string;
    readonly path: string;
    readonly startLine: number;
    readonly endLine: number;
}

/** A locator's parts, or null for a string that is not one (or whose range runs backwards). */
export function parseCodeRange(locator: string): CodeRange | null {
    if (locator.length > MAX_LOCATOR_CHARS) return null;
    const m = CODE_RANGE_LOCATOR.exec(locator);
    if (m === null) return null;
    const path = m[2];
    if (path.split('/').some((seg) => seg === '.' || seg === '..')) return null;
    const startLine = Number(m[3]);
    const endLine = Number(m[4]);
    if (endLine < startLine) return null;
    return { label: m[1], path, startLine, endLine };
}

/** The locator for a range: the inverse of `parseCodeRange`. */
export function codeRangeLocator(r: CodeRange): string {
    return `code://${r.label}/${r.path}#L${r.startLine}-L${r.endLine}`;
}

/** Whether two ranges are in the same file and share at least one line. */
export function rangesOverlap(a: CodeRange, b: CodeRange): boolean {
    return a.label === b.label && a.path === b.path && a.startLine <= b.endLine && b.startLine <= a.endLine;
}

/** Where the review's model ran. `client-hosted` is the only one an air-gapped site can use. */
export const MODEL_PROVIDERS = ['client-hosted', 'anthropic', 'azure-openai', 'bedrock'] as const;
export type ModelProvider = (typeof MODEL_PROVIDERS)[number];

/** Whether the review ran, and whether it read everything it set out to. */
export const RUN_STATUSES = ['COMPLETE', 'INCOMPLETE', 'NOT_RUN'] as const;
export type RunStatus = (typeof RUN_STATUSES)[number];

/**
 * Why a review did not run. With no model configured the scanner is off, and
 * a model revision with no evaluation record, or a record below the published
 * floor, or no floor published yet, does not run either.
 */
export const NOT_RUN_REASONS = ['MODEL_NOT_CONFIGURED', 'EVALUATION_MISSING', 'EVALUATION_BELOW_FLOOR', 'FLOOR_NOT_SET', 'NO_REPOSITORY'] as const;
export type NotRunReason = (typeof NOT_RUN_REASONS)[number];

/** Why a review that ran did not finish what it set out to read. */
export const INCOMPLETE_RUN_REASONS = ['TOKEN_BUDGET', 'FILE_BUDGET', 'TIME_BOX', 'MODEL_FAILED', 'MODEL_REFUSED'] as const;
export type IncompleteRunReason = (typeof INCOMPLETE_RUN_REASONS)[number];

/**
 * Why one place selected for review was not reviewed. `SECRET_IN_EXCERPT`: the
 * excerpt failed the secret checks and was not sent.
 */
export const NOT_REVIEWED_REASONS = ['SECRET_IN_EXCERPT', 'TOKEN_BUDGET', 'FILE_BUDGET', 'TIME_BOX', 'BYTE_CAP', 'UNPARSEABLE', 'MODEL_FAILED'] as const;
export type NotReviewedReason = (typeof NOT_REVIEWED_REASONS)[number];

/** Each repository's state in the review. */
export const REPOSITORY_REVIEW_STATUSES = ['REVIEWED', 'PARTIAL', 'NOT_REVIEWED'] as const;
export type RepositoryReviewStatus = (typeof REPOSITORY_REVIEW_STATUSES)[number];

/** A finding's id: a stable fingerprint the scanner computes, never chosen by a model. */
export const FINDING_FINGERPRINT = /^[0-9a-f]{16,64}$/;

/** A model, a model revision, as their provider names them. */
export const MODEL_NAME = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,99}$/;
/** A host name: the model's endpoint, never its URL. */
export const MODEL_HOST = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export const MAX_LOCATOR_CHARS = 600;
export const MAX_REPOSITORIES = 200;
export const MAX_FINDINGS = 2000;
export const MAX_TRACE_STEPS = 12;
export const MAX_SENT_EXCERPTS = 20000;
export const MAX_NOT_REVIEWED = 20000;
export const MAX_TITLE_CHARS = 160;
export const MAX_PROSE_CHARS = 1200;
