/**
 * THE EXIT CODES, in one table.
 *
 * 0, 1 and 2 mean what they have always meant. 3 to 6 say WHY a command did
 * not simply succeed, so a scheduler or a deployment script can tell "fix the
 * configuration" from "the network is closed" without reading a log.
 *
 * `docs/scanner.md` carries the same table; a test holds the two equal.
 */
export const EXIT = Object.freeze({
    OK: 0,
    FAILED: 1,
    USAGE: 2,
    INCOMPLETE: 3,
    CONFIG: 4,
    CREDENTIAL: 5,
    NETWORK: 6,
    SIGINT: 130,
    SIGTERM: 143,
} as const);

export type ExitName = keyof typeof EXIT;

/** Each code with what it means, in the order the documentation lists them. */
export const EXIT_CODE_TABLE: readonly { readonly code: number; readonly name: ExitName; readonly meaning: string }[] = Object.freeze([
    { code: EXIT.OK, name: 'OK', meaning: 'The command did what it was asked. scan: every output delivered. diff: no difference. doctor: ready.' },
    { code: EXIT.FAILED, name: 'FAILED', meaning: 'The command failed: an output was not delivered, the ingest refused the report, a missing signing key, or an error with no class of its own. diff: a difference.' },
    { code: EXIT.USAGE, name: 'USAGE', meaning: 'Wrong arguments, an unknown flag, nowhere to deliver, a refused overwrite. Nothing was read or written.' },
    { code: EXIT.INCOMPLETE, name: 'INCOMPLETE', meaning: 'Nothing failed, and not everything could be established. scan --strict: delivered, but a source was INCOMPLETE or the scan found no agent. diff: could not compare everything. doctor: warnings or blocked checks.' },
    { code: EXIT.CONFIG, name: 'CONFIG', meaning: 'The configuration, the answers file, the inventory or a secret file was refused; NODE_TLS_REJECT_UNAUTHORIZED=0.' },
    { code: EXIT.CREDENTIAL, name: 'CREDENTIAL', meaning: 'doctor: a credential is missing or refused.' },
    { code: EXIT.NETWORK, name: 'NETWORK', meaning: 'doctor: a host could not be resolved or reached.' },
    { code: EXIT.SIGINT, name: 'SIGINT', meaning: 'Interrupted.' },
    { code: EXIT.SIGTERM, name: 'SIGTERM', meaning: 'Terminated.' },
]);
