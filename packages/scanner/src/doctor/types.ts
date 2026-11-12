/**
 * `scanent doctor` — the result model.
 *
 * Four statuses, and no default among them: every check the runner emits
 * states one. The rules that keep a preflight honest are in the TYPES where
 * they can be, and in `assertWellFormed` (which the runner calls on every
 * check it emits) where they cannot:
 *
 *   • PASS means the thing the check names was OBSERVED. It carries no cause
 *     and no fix.
 *   • SKIPPED always says why: NOT_APPLICABLE (nothing to check), BLOCKED (a
 *     prerequisite failed, so this could not be checked — never read it as a
 *     pass), or NOT_OBSERVABLE (no read the scanner declares can answer it;
 *     the detail says what to confirm by hand).
 *   • FAIL always has a class (which decides the exit code) and a fix.
 *   • WARN always has a fix.
 *
 * `detail` and `fix` are built from fixed sentences, the configuration's own
 * names, status codes, counts and role or scope names. Never a credential, a
 * response body or a URL.
 */
import { EXIT } from '../exit-codes';

export type CheckStatus = 'PASS' | 'WARN' | 'FAIL' | 'SKIPPED';
export type SkipCause = 'NOT_APPLICABLE' | 'BLOCKED' | 'NOT_OBSERVABLE';
export type FailClass = 'CONFIG' | 'CREDENTIAL' | 'NETWORK';

export type Check =
    | { readonly scope: string; readonly id: string; readonly status: 'PASS'; readonly detail: string }
    | { readonly scope: string; readonly id: string; readonly status: 'WARN'; readonly detail: string; readonly fix: string }
    | { readonly scope: string; readonly id: string; readonly status: 'FAIL'; readonly class: FailClass; readonly detail: string; readonly fix: string }
    | { readonly scope: string; readonly id: string; readonly status: 'SKIPPED'; readonly cause: SkipCause; readonly detail: string };

export const DOCTOR_SCHEMA = 'scanent-doctor/1';

export interface DoctorReport {
    readonly doctor: typeof DOCTOR_SCHEMA;
    /** The estate, or null when the configuration could not be read. */
    readonly estate: string | null;
    readonly at: string;
    readonly scanner: { readonly version: string; readonly manifestHash: string };
    /** True only with no FAIL, no WARN and no BLOCKED check. */
    readonly ready: boolean;
    readonly counts: Readonly<Record<CheckStatus, number>>;
    readonly exitCode: number;
    readonly checks: readonly Check[];
}

/** Refuse a check that breaks the model's rules. The runner calls it on everything it emits. */
export function assertWellFormed(check: Check): Check {
    const c = check as { status: string; cause?: unknown; class?: unknown; fix?: unknown; detail?: unknown };
    const has = (k: 'cause' | 'class' | 'fix') => c[k] !== undefined;
    const ok =
        typeof c.detail === 'string' &&
        (c.status === 'PASS'
            ? !has('cause') && !has('class') && !has('fix')
            : c.status === 'WARN'
                ? has('fix') && !has('cause') && !has('class')
                : c.status === 'FAIL'
                    ? has('fix') && has('class') && !has('cause')
                    : c.status === 'SKIPPED' && has('cause') && !has('class') && !has('fix'));
    if (!ok) throw new Error(`doctor produced a malformed check: ${check.scope} ${check.id}`);
    return check;
}

export function countsOf(checks: readonly Check[]): Record<CheckStatus, number> {
    const counts: Record<CheckStatus, number> = { PASS: 0, WARN: 0, FAIL: 0, SKIPPED: 0 };
    for (const c of checks) counts[c.status] += 1;
    return counts;
}

const isBlocked = (c: Check) => c.status === 'SKIPPED' && c.cause === 'BLOCKED';

/** Ready only when nothing failed, nothing warned, and nothing was left unchecked behind a failure. */
export function isReady(checks: readonly Check[]): boolean {
    return checks.length > 0 && !checks.some((c) => c.status === 'FAIL' || c.status === 'WARN' || isBlocked(c));
}

/**
 * The exit code, by the first row that applies: a CONFIG failure, a CREDENTIAL
 * failure, a NETWORK failure, then warnings or blocked checks, then 0.
 * NOT_OBSERVABLE and NOT_APPLICABLE do not change it: no rerun can turn
 * either into a PASS. They are always shown and always counted as not checked.
 */
export function doctorExitCode(checks: readonly Check[]): number {
    const failed = (cls: FailClass) => checks.some((c) => c.status === 'FAIL' && c.class === cls);
    if (failed('CONFIG')) return EXIT.CONFIG;
    if (failed('CREDENTIAL')) return EXIT.CREDENTIAL;
    if (failed('NETWORK')) return EXIT.NETWORK;
    if (checks.length === 0 || checks.some((c) => c.status === 'WARN' || isBlocked(c))) return EXIT.INCOMPLETE;
    return EXIT.OK;
}
