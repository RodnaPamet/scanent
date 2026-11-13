/**
 * THE INTEGRATIONS SCANNER'S SOURCE INTERFACE — the shape a reader of what a
 * directory has granted to applications implements.
 *
 * It is the agent source's interface (`source.ts`) with another result: the
 * same `SourceContext` (GET only, the one declared token exchange, one
 * deadline and byte budget), the same preflight, the same rule that a read
 * which went wrong is returned as INCOMPLETE with a named reason and never
 * thrown. What it returns is applications as `scanent-integrations/1` carries
 * them, not principals for the agent report: the two never merge.
 */
import type { IntegrationsReportApplication, IntegrationsSourceKind } from '@rodnapamet/scanent-contract/integrations-contract';

import type { IncompleteReason, ProbeStep, SourceContext } from './source';

/** How far a source's sign-in read got: not asked for, read in full, or stopped with a reason. */
export type SignInRead =
    | { readonly status: 'NOT_READ' }
    | { readonly status: 'COMPLETE'; readonly rows: number }
    | { readonly status: 'INCOMPLETE'; readonly reason: IncompleteReason; readonly rows: number; readonly detail?: string };

export interface IntegrationsSourceRead {
    readonly kind: IntegrationsSourceKind;
    readonly status: 'COMPLETE' | 'INCOMPLETE';
    /** Present exactly when `status` is INCOMPLETE. */
    readonly reason?: IncompleteReason;
    /** Why the read stopped, in the scanner's own fixed words. For the log and the local results only. */
    readonly detail?: string;
    /** Rows read, every listing together, whether or not each became an application. */
    readonly rows: number;
    readonly signInActivity: SignInRead;
    /** What was read of each application, including on a read that stopped: what WAS read is real. */
    readonly applications: readonly IntegrationsReportApplication[];
}

export interface IntegrationsSource {
    readonly kind: IntegrationsSourceKind;
    /** The product behind the kind, e.g. `entra`. Not reported. */
    readonly product: string;
    read(ctx: SourceContext): Promise<IntegrationsSourceRead>;
    /** The preflight (`scanent doctor`), as for an agent source: declared reads only, and it never writes. */
    preflight(ctx: SourceContext): Promise<readonly ProbeStep[]>;
}
