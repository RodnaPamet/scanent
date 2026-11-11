/**
 * The package's public entry point: what an embedder imports, and that it is
 * the same code the command line runs.
 */
import { generateKeyPairSync } from 'crypto';
import { resolve } from 'path';

import { verifyAndParseHarnessReport } from '@scanent/contract/harness-contract';
import * as api from '../src/index';
import * as config from '../src/config';
import * as post from '../src/post';
import * as report from '../src/report';
import * as scan from '../src/scan';
import * as schedule from '../src/schedule';
import * as surface from '../src/scanner-surface';

const ESTATE = resolve(__dirname, '..', '..', '..', 'examples', 'code-only', 'estate');

describe('the public entry point', () => {
    it('exports exactly this surface', () => {
        expect(Object.keys(api).sort()).toEqual(
            [
                'ConfigError', 'GCP_IAM_ORIGIN', 'GCP_READ_PATHS', 'GITHUB_API_ORIGIN', 'GITHUB_READ_PATHS', 'GOOGLE_OAUTH_ORIGIN',
                'LANGSMITH_CLOUD_ORIGINS', 'LANGSMITH_READ_PATHS', 'MAX_RESPONSE_BYTES', 'MAX_SOURCE_BYTES', 'ReportRefusedLocally',
                'SCANNER_SURFACE', 'SCANNER_VERSION', 'ScannerConfigSchema', 'SourceReadError', 'addressReachable', 'analyseWorkflow',
                'assertResolvesReachable', 'azureKeyVaultSource', 'buildReportBody', 'buildSources', 'createSourceWire',
                'credentialEnvNames', 'customerOriginProblem', 'gcpServiceAccountSource', 'githubActionsSource', 'ingestUrl',
                'isDeclaredRequest', 'jsonLineLog', 'langSmithSource', 'langchainCodeSource', 'loadSigningKey', 'oktaSource',
                'parsePrivateCidrAllowlist', 'parseScannerConfig', 'postReport', 'rawPublicKeyHex', 'runOnSchedule', 'runScan',
                'scanAndPost', 'scanLangChainCode', 'scannerManifestHash', 'signReport', 'sourceCredentialEnv',
            ].sort(),
        );
    });

    it('re-exports the modules\' own members, not copies', () => {
        expect(api.parseScannerConfig).toBe(config.parseScannerConfig);
        expect(api.ConfigError).toBe(config.ConfigError);
        expect(api.postReport).toBe(post.postReport);
        expect(api.signReport).toBe(report.signReport);
        expect(api.runScan).toBe(scan.runScan);
        expect(api.scanAndPost).toBe(scan.scanAndPost);
        expect(api.runOnSchedule).toBe(schedule.runOnSchedule);
        expect(api.SCANNER_SURFACE).toBe(surface.SCANNER_SURFACE);
    });

    it('is enough to configure, scan, sign and verify without reaching past it', async () => {
        const { privateKey, publicKey } = generateKeyPairSync('ed25519');
        const parsed = api.parseScannerConfig({
            estate: 'example-code',
            scanner: { agentId: 'agt_example', signingKeyEnv: 'SCANNER_SIGNING_KEY' },
            inflect: { baseUrl: 'https://inflect.example.com', tenantSlug: 'example', apiKeyEnv: 'INFLECT_INGEST_KEY' },
            schedule: { everyHours: 24 },
            sources: [{ kind: 'code', product: 'langchain', roots: [{ label: 'example', path: ESTATE }] }],
        });
        expect(api.credentialEnvNames(parsed)).toEqual(['SCANNER_SIGNING_KEY', 'INFLECT_INGEST_KEY']);
        const lines: string[] = [];
        const { raw, body } = await api.runScan({
            config: parsed,
            env: { SCANNER_SIGNING_KEY: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() },
            log: api.jsonLineLog((l) => lines.push(l)),
            fetchImpl: async () => {
                throw new Error('the code source makes no request');
            },
        });
        expect(verifyAndParseHarnessReport(raw, [api.rawPublicKeyHex(publicKey)])).toMatchObject({ ok: true, complete: true });
        expect(body.agents.length).toBeGreaterThan(0);
        expect(body.scan.scanner.manifestHash).toBe(api.scannerManifestHash());
        expect(api.ingestUrl(parsed.inflect.baseUrl, parsed.inflect.tenantSlug)).toBe(
            'https://inflect.example.com/api/t/example/admin/agents/harness-scans',
        );
        expect(lines.length).toBeGreaterThan(0);
    });
});
