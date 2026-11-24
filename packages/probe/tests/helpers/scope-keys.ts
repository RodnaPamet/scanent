/** Keys and scopes for the engagement-scope tests. */
import { generateKeyPairSync, sign, type KeyObject } from 'node:crypto';

import { harnessSignedMessage } from '@rodnapamet/scanent-contract/harness-contract';

import { ENGAGEMENT_SCOPE_V1 } from '../../src/scope';
import { rawPublicKeyHex } from '../../src/scope-sign';

export interface TestKey {
    readonly privateKey: KeyObject;
    readonly publicKey: KeyObject;
    readonly hex: string;
    readonly base64: string;
    readonly pem: string;
}

export function makeKey(): TestKey {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const hex = rawPublicKeyHex(publicKey);
    return {
        privateKey,
        publicKey,
        hex,
        base64: Buffer.from(hex, 'hex').toString('base64'),
        pem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    };
}

export const START = '2026-12-01T09:00:00.000Z';
export const END = '2026-12-03T17:00:00.000Z';
export const START_MS = Date.parse(START);
export const END_MS = Date.parse(END);

/** The tool a test MCP target names, and the argument the probe goes in. */
export const MCP_TOOL = { name: 'search_orders', argument: 'query' } as const;
/** A chat target's request shape: an OpenAI-style body, the reply at `reply`. */
export const CHAT_REQUEST = { body: { messages: [{ role: 'user', content: '{{probe}}' }], stream: false }, replyPath: ['reply'] };

export const mcpTarget = (endpoint: string, tools: readonly { name: string; argument: string }[] = [MCP_TOOL]) => ({ kind: 'mcp', endpoint, tools });
export const chatTarget = (endpoint: string, request: unknown = CHAT_REQUEST) => ({ kind: 'http-chat', endpoint, request });
export const a2aTarget = (endpoint: string) => ({ kind: 'a2a', endpoint });

/** A valid scope body naming `prober`. */
export function scopeBody(prober: TestKey, overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
        contract: ENGAGEMENT_SCOPE_V1,
        engagementId: 'eng-2026-12-acme',
        targets: [
            mcpTarget('https://mcp.estate.example/mcp'),
            chatTarget('https://chat.estate.example/api/turn'),
        ],
        window: { start: START, end: END },
        classes: ['canary', 'disclosure'],
        approver: { name: 'Dana Approver', role: 'Head of Security' },
        killContact: 'security on-call, +44 20 0000 0000',
        ratePerMinute: 30,
        proberKey: prober.hex,
        ...overrides,
    };
}

/** Sign any body, valid or not, the way a scope is signed: for testing what the verifier refuses. */
export function signRaw(body: Record<string, unknown>, signer: TestKey): string {
    const wire = JSON.parse(JSON.stringify(body)) as Record<string, unknown>;
    return JSON.stringify({
        ...wire,
        signature: { alg: 'ed25519', signerKey: signer.hex, sig: sign(null, harnessSignedMessage(wire), signer.privateKey).toString('hex') },
    });
}
