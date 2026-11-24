/**
 * Signing an engagement scope, as the estate's approver does.
 *
 * The approver's key is an ordinary Ed25519 key (`scanent keygen --out` makes
 * one); what makes it a scope key is that the estate registered its public
 * half with the prober in advance. The scope is signed exactly as a report is,
 * so `verifyEngagementScope` reads it through the contract's own envelope
 * check.
 */
import { createPrivateKey, createPublicKey, sign, type KeyObject } from 'node:crypto';

import { MAX_REPORT_BYTES, describeReportSchemaIssue, harnessKeyFingerprint, harnessSignedMessage } from '@rodnapamet/scanent-contract/harness-contract';

import { EngagementScopeSchema } from './scope';

/** A scope that was not signed, and why: paths and rules only, never a value. */
export class ScopeSignRefused extends Error {
    constructor(readonly issues: readonly string[]) {
        super(`the scope was not signed: ${issues.join('; ')}`);
        this.name = 'ScopeSignRefused';
    }
}

/** The raw 32-byte public key, hex: the form the scope and the verifier read. */
export function rawPublicKeyHex(publicKey: KeyObject): string {
    return publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('hex');
}

/** An Ed25519 private key from PEM, or a refusal that quotes nothing of the file. */
export function loadScopeSigningKey(pem: string): { privateKey: KeyObject; publicKey: KeyObject } {
    let privateKey: KeyObject;
    try {
        privateKey = createPrivateKey(pem);
    } catch {
        throw new ScopeSignRefused(['key: not a private key in PEM']);
    }
    if (privateKey.asymmetricKeyType !== 'ed25519') throw new ScopeSignRefused(['key: not Ed25519']);
    return { privateKey, publicKey: createPublicKey(privateKey) };
}

/**
 * Check the body against the strict schema, then sign it. Returns the signed
 * scope, serialised. Refused, and nothing signed, when the body would not
 * verify, or when the signing key is the prober's the scope names: a scope its
 * own prober signed is refused by every verifier (SIGNER_IS_PROBER), so it is
 * never made.
 */
export function signScope(body: unknown, keys: { privateKey: KeyObject; publicKey: KeyObject }): string {
    const parsed = EngagementScopeSchema.safeParse(body);
    if (!parsed.success) throw new ScopeSignRefused(parsed.error.issues.map(describeReportSchemaIssue));

    const signerKey = rawPublicKeyHex(keys.publicKey);
    if (harnessKeyFingerprint(signerKey) === harnessKeyFingerprint(parsed.data.proberKey)) {
        throw new ScopeSignRefused(['key: the prober the scope names may not sign it; the approver signs with a key of their own']);
    }

    // Sign what the wire carries, as a report is signed (packages/scanner/src/report.ts).
    const wireBody = JSON.parse(JSON.stringify(body)) as Record<string, unknown>;
    const signature = {
        alg: 'ed25519' as const,
        signerKey,
        sig: sign(null, harnessSignedMessage(wireBody), keys.privateKey).toString('hex'),
    };
    const raw = JSON.stringify({ ...wireBody, signature }, null, 2) + '\n';
    if (Buffer.byteLength(raw, 'utf8') > MAX_REPORT_BYTES) throw new ScopeSignRefused(['(scope): too large']);
    return raw;
}
