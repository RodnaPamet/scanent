/**
 * What the output tests share: a key, a configuration over the code-only
 * example, a scan of it, and a way to read a directory tree back.
 */
import { generateKeyPairSync } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

import type { LocalResults } from '@scanent/report/results/types';

import { parseScannerConfig, type ScannerConfig } from '../../src/config';
import { scoreScanLocally } from '../../src/local-results';
import { jsonLineLog, type ScannerLog } from '../../src/log';
import { rawPublicKeyHex } from '../../src/report';
import { runScan } from '../../src/scan';

export const REPO = path.resolve(__dirname, '..', '..', '..', '..');
export const ESTATE = path.join(REPO, 'examples', 'code-only', 'estate');
export const EXAMPLE_AGENT = 'code:example/support/agent.py#support_executor';

const pair = generateKeyPairSync('ed25519');
export const PEM = pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
export const PUBLIC_HEX = rawPublicKeyHex(pair.publicKey);
export const ENV = { SCANNER_SIGNING_KEY: PEM, INFLECT_INGEST_KEY: 'ingest-key-for-tests' };

export const INFLECT = { baseUrl: 'https://inflect.example.com', tenantSlug: 'example', apiKeyEnv: 'INFLECT_INGEST_KEY' };

/** The example's configuration as plain JSON, with whatever a test changes. */
export function configJson(extra: Record<string, unknown> = {}, roots = [{ label: 'example', path: ESTATE }]): Record<string, unknown> {
    return {
        estate: 'example-code',
        scanner: { agentId: 'agt_example', signingKeyEnv: 'SCANNER_SIGNING_KEY' },
        inflect: INFLECT,
        schedule: { everyHours: 24 },
        sources: [{ kind: 'code', product: 'langchain', roots }],
        ...extra,
    };
}

export function configOf(extra: Record<string, unknown> = {}, roots = [{ label: 'example', path: ESTATE }]): ScannerConfig {
    return parseScannerConfig(configJson(extra, roots) as unknown);
}

/** A log that keeps its lines. */
export function capturedLog(): { log: ScannerLog; lines: () => Record<string, unknown>[]; text: () => string } {
    const raw: string[] = [];
    return {
        log: jsonLineLog((l) => raw.push(l)),
        lines: () => raw.map((l) => JSON.parse(l) as Record<string, unknown>),
        text: () => raw.join(''),
    };
}

/** A `fetch` that fails the test if anything calls it. */
export const noFetch = async (): Promise<Response> => {
    throw new Error('no test reaches the network');
};

/** One scan of the example at a fixed time, and its local results. */
export async function scanExample(now: number, config: ScannerConfig = configOf()): Promise<{ raw: string; results: LocalResults }> {
    const { raw, body } = await runScan({ config, env: ENV, log: jsonLineLog(() => undefined), fetchImpl: noFetch, now: () => now });
    return { raw, results: scoreScanLocally({ config, raw, body, inventory: null }) };
}

/** Every file under a directory, by its relative path, with its content. */
export function tree(dir: string): Record<string, string> {
    const out: Record<string, string> = {};
    const walk = (at: string) => {
        if (!fs.existsSync(at)) return;
        for (const entry of fs.readdirSync(at, { withFileTypes: true })) {
            const full = path.join(at, entry.name);
            if (entry.isDirectory()) walk(full);
            else out[path.relative(dir, full)] = fs.readFileSync(full, 'utf8');
        }
    };
    walk(dir);
    return out;
}

/** One canary per secret shape, built from parts so this file holds no secret-shaped literal. */
export const CANARIES: readonly (readonly [string, string])[] = [
    ['a GitHub token', ['gh', 'p_', 'A'.repeat(24)].join('')],
    ['a GitHub fine-grained token', ['github', '_pat_', 'A1'.repeat(12)].join('')],
    ['an AWS access key id', ['AK', 'IA', 'ABCDEFGHIJKLMNOP'].join('')],
    ['a Slack token', ['xo', 'xb-', '1234567890-abcdef'].join('')],
    ['an sk- key', ['s', 'k-', 'a'.repeat(24)].join('')],
    ['an sk-ant- key', ['s', 'k-ant-', 'a1b2'.repeat(6)].join('')],
    ['a private key header', ['-----BEGIN ', 'PRIVATE KEY', '-----'].join('')],
    ['a JSON web token', ['ey', 'J', 'a'.repeat(12), '.', 'b'.repeat(12), '.sig'].join('')],
    ['a URL with a password', ['https:', '//user:', 'hunter2', '@db.example'].join('')],
];
