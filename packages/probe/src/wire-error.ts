/**
 * Why a transport got no reply: a code, never the target's own words.
 *
 * A transport throws one of these; the runner turns it into NO_REPLY for the
 * probe and keeps the FIRST code per target as an operator's note. The note is
 * not part of the signed report: it says why a target went unanswered to the
 * person running the engagement, and nothing about what the target said.
 */
export const WIRE_ERROR_CODES = [
    'UNREACHABLE',
    'TIMEOUT',
    'REDIRECT_REFUSED',
    'AUTH_FAILED',
    'HTTP_4XX',
    'HTTP_5XX',
    'NOT_JSON',
    'NO_TEXT',
    'RPC_ERROR',
    'TOOL_NOT_LISTED',
    'SESSION_FAILED',
    /** The request is not on the engagement's declared surface: refused before it was sent. */
    'OFF_SURFACE',
] as const;
export type WireErrorCode = (typeof WIRE_ERROR_CODES)[number];

export class ProbeWireError extends Error {
    constructor(readonly code: WireErrorCode) {
        super(`no reply: ${code}`);
        this.name = 'ProbeWireError';
    }
}

/** The code of a transport failure: its own when it is a ProbeWireError, UNREACHABLE for anything else. */
export function wireErrorCode(err: unknown): WireErrorCode {
    return err instanceof ProbeWireError ? err.code : 'UNREACHABLE';
}
