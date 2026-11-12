/**
 * The reader table, held to the readers.
 *
 * `CRITERION_READERS` says which source can answer which criterion. A result
 * uses it to tell "a source saw this fail" from "nothing in this run could
 * have seen it", so a row that is wrong makes a result say something false.
 *
 *   1. `reportedBy` is exactly the criteria each source's code names.
 *   2. `metBy` is exactly the ones its code can report MET.
 *   3. Run over their fixtures, the sources report nothing the table does not
 *      allow, and the vault and MCP sources report no verdict at all.
 *   4. The consequences a standalone result states follow from the table.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as ts from 'typescript';

import { AGENT_SDK_OPTION_CRITERIA, type HarnessSourceKind } from '@scanent/contract/harness-findings';
import { SOURCE_KINDS } from '@scanent/contract/harness-contract-rules';
import { ALL_HARNESS_CRITERIA, HARNESS_CRITERIA, isHarnessCriterionId, type CriterionVerdict, type HarnessCriterionId } from '@scanent/contract/harness-ladder';
import { CROSS_AGENT_VERDICT_SOURCE } from '@scanent/report/results/judgement';
import { coverageOf } from '@scanent/report/results/score';

import { parseScannerConfig } from '../src/config';
import { configuredSourceKinds, CRITERION_READERS } from '../src/criterion-readers';
import { createSourceWire } from '../src/http';
import type { HarnessSource, SourceRead } from '../src/source';
import { azureKeyVaultSource } from '../src/sources/azure-key-vault';
import { entraSource } from '../src/sources/entra';
import { inflectRegisterSource } from '../src/sources/inflect-register';
import { langchainCodeSource } from '../src/sources/langchain';
import { langSmithSource } from '../src/sources/langsmith';
import { mcpSource } from '../src/sources/mcp';
import { oktaSource } from '../src/sources/okta';
import { AGENT_SDK_PY, AGENT_SDK_TS, LANGCHAIN_JS, LANGCHAIN_PYTHON, LANGGRAPH, writeCodeEstate } from './helpers/agent-harness-code-fixtures';
import {
    AZURE_CLIENT_ID,
    AZURE_CLIENT_SECRET_VALUE,
    AZURE_TENANT,
    createSourceFakes,
    ENTRA_DIRECTORY_ID,
    INGEST,
    LANGSMITH_API_KEY_VALUE,
    MCP_CRM,
    MCP_TICKETS,
    MCP_TOKEN_VALUE,
    OKTA_ORG,
    OKTA_TOKEN_VALUE,
    VAULT,
} from './helpers/agent-harness-source-fakes';

const SOURCES_DIR = path.resolve(__dirname, '..', 'src', 'sources');

/** Each reader's file, and the kind it reports under. */
const SOURCE_FILES: Readonly<Record<string, HarnessSourceKind>> = {
    'azure-key-vault.ts': 'vault',
    'entra.ts': 'entra-sp',
    'gcp-service-accounts.ts': 'gcp-sa',
    'github-actions.ts': 'cicd',
    'inflect-register.ts': 'inflect-register',
    'langchain.ts': 'code',
    'langsmith.ts': 'runtime',
    'mcp.ts': 'mcp',
    'okta.ts': 'okta-app',
};
/** Readers no configuration selects: no run can have one, so the table does not list them. */
const NOT_CONFIGURABLE = ['openshell.ts'];

interface StaticVerdicts {
    /** Every criterion id the file holds as a string literal. */
    readonly named: Set<HarnessCriterionId>;
    /** Criteria in a verdict literal whose `met` is anything but the literal `false`. */
    readonly canBeMet: Set<HarnessCriterionId>;
    /** A verdict literal whose criterion is a variable and whose `met` is not `false`: any named criterion may be met. */
    readonly meetsByVariable: boolean;
}

function staticVerdictsOf(file: string): StaticVerdicts {
    const source = ts.createSourceFile(file, fs.readFileSync(file, 'utf8'), ts.ScriptTarget.ES2022, true);
    const named = new Set<HarnessCriterionId>();
    const canBeMet = new Set<HarnessCriterionId>();
    let meetsByVariable = false;
    const visit = (node: ts.Node): void => {
        if ((ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) && isHarnessCriterionId(node.text)) named.add(node.text);
        if (ts.isObjectLiteralExpression(node)) {
            const prop = (name: string) =>
                node.properties.find((p) => (ts.isPropertyAssignment(p) || ts.isShorthandPropertyAssignment(p)) && p.name.getText(source) === name);
            const criterion = prop('criterion');
            const met = prop('met');
            if (criterion !== undefined && met !== undefined) {
                const metIsFalse = ts.isPropertyAssignment(met) && met.initializer.kind === ts.SyntaxKind.FalseKeyword;
                if (!metIsFalse) {
                    if (ts.isPropertyAssignment(criterion) && ts.isStringLiteral(criterion.initializer) && isHarnessCriterionId(criterion.initializer.text)) {
                        canBeMet.add(criterion.initializer.text);
                    } else {
                        meetsByVariable = true;
                    }
                }
            }
        }
        ts.forEachChild(node, visit);
    };
    visit(source);
    return { named, canBeMet, meetsByVariable };
}

const sorted = (ids: Iterable<string>): string[] => [...ids].sort();
const kindsWith = (pick: 'reportedBy' | 'metBy', kind: string): string[] =>
    sorted(ALL_HARNESS_CRITERIA.filter((c) => (CRITERION_READERS[c][pick] as readonly string[]).includes(kind)));

describe('1. and 2. the table is what each source\'s code can report', () => {
    it('covers every reader file there is', () => {
        const files = fs.readdirSync(SOURCES_DIR).filter((name) => name.endsWith('.ts')).sort();
        expect(files).toEqual([...Object.keys(SOURCE_FILES), ...NOT_CONFIGURABLE].sort());
        // And every kind the contract has, once.
        expect(sorted(Object.values(SOURCE_FILES))).toEqual(sorted(SOURCE_KINDS));
    });

    it('leaves out only a reader no configuration can select', () => {
        const scan = fs.readFileSync(path.resolve(SOURCES_DIR, '..', 'scan.ts'), 'utf8');
        for (const file of NOT_CONFIGURABLE) expect(scan).not.toContain(`./sources/${file.replace(/\.ts$/, '')}`);
        for (const file of Object.keys(SOURCE_FILES)) expect(scan).toContain(`./sources/${file.replace(/\.ts$/, '')}`);
    });

    it.each(Object.entries(SOURCE_FILES).filter(([, kind]) => kind !== 'code'))('%s reports exactly the criteria the table gives %s', (file, kind) => {
        const { named } = staticVerdictsOf(path.join(SOURCES_DIR, file));
        expect(kindsWith('reportedBy', kind)).toEqual(sorted(named));
    });

    it.each(Object.entries(SOURCE_FILES).filter(([, kind]) => kind !== 'code'))('%s can report met exactly the criteria the table gives %s', (file, kind) => {
        const { named, canBeMet, meetsByVariable } = staticVerdictsOf(path.join(SOURCES_DIR, file));
        expect(kindsWith('metBy', kind)).toEqual(sorted(meetsByVariable ? named : canBeMet));
    });

    it('the code source names no criterion itself: its verdicts are the contract\'s option mapping, NOT MET only', () => {
        const files = ['langchain.ts', ...fs.readdirSync(path.join(SOURCES_DIR, 'code')).map((name) => `code/${name}`)];
        expect(files.length).toBeGreaterThan(3);
        for (const file of files) expect(sorted(staticVerdictsOf(path.join(SOURCES_DIR, file)).named)).toEqual([]);
        expect(kindsWith('reportedBy', 'code')).toEqual(sorted(new Set(Object.values(AGENT_SDK_OPTION_CRITERIA))));
        expect(kindsWith('metBy', 'code')).toEqual([]);
    });

    it('the static reader sees a verdict that is always NOT MET, and one that can be met', () => {
        // Okta's credential verdict is about an API token acting as a person: never met.
        const okta = staticVerdictsOf(path.join(SOURCES_DIR, 'okta.ts'));
        expect(okta.named.has('H2.credential_bound')).toBe(true);
        expect(okta.canBeMet.has('H2.credential_bound')).toBe(false);
        expect(okta.canBeMet.has('H2.grant_kind_declared')).toBe(true);
        expect(CRITERION_READERS['H2.credential_bound'].reportedBy).toContain('okta-app');
        expect(CRITERION_READERS['H2.credential_bound'].metBy).not.toContain('okta-app');
    });

    it('every criterion has a row, metBy is within reportedBy, and no reader is listed twice', () => {
        expect(sorted(Object.keys(CRITERION_READERS))).toEqual(sorted(ALL_HARNESS_CRITERIA));
        for (const criterion of ALL_HARNESS_CRITERIA) {
            const { reportedBy, metBy } = CRITERION_READERS[criterion];
            expect(metBy.every((r) => reportedBy.includes(r))).toBe(true);
            expect(new Set(reportedBy).size).toBe(reportedBy.length);
            for (const reader of reportedBy) expect([...SOURCE_KINDS, 'inventory']).toContain(reader);
        }
    });

    it('the inventory reads the four H1 criteria and nothing else', () => {
        expect(kindsWith('reportedBy', 'inventory')).toEqual(sorted(HARNESS_CRITERIA.H1));
        expect(kindsWith('metBy', 'inventory')).toEqual(sorted(HARNESS_CRITERIA.H1));
    });
});

describe('3. run over their fixtures', () => {
    const ASOF = new Date('2026-10-19T03:00:00.000Z');
    const publicDns = async () => ['203.0.113.10'];
    let reads: SourceRead[];

    beforeAll(async () => {
        const fakes = createSourceFakes();
        const codeRoot = writeCodeEstate(LANGCHAIN_PYTHON, LANGCHAIN_JS, LANGGRAPH, AGENT_SDK_TS, AGENT_SDK_PY);
        const sources: HarnessSource[] = [
            entraSource({ directoryId: ENTRA_DIRECTORY_ID, clientId: AZURE_CLIENT_ID, clientSecret: AZURE_CLIENT_SECRET_VALUE, includeThirdPartyApplications: true }),
            oktaSource({ orgUrl: OKTA_ORG, apiToken: OKTA_TOKEN_VALUE, ownerProfileKey: 'owner' }),
            azureKeyVaultSource({
                vaultUrls: [VAULT],
                directoryTenantId: AZURE_TENANT,
                clientId: AZURE_CLIENT_ID,
                clientSecret: AZURE_CLIENT_SECRET_VALUE,
                principalTag: 'inflect-principal',
                ownerTag: 'owner',
            }),
            mcpSource({
                servers: [
                    { label: 'crm', url: MCP_CRM, agents: ['entra:sp:a0000001-0000-4000-8000-000000003686'], pinnedManifestHash: null, token: null, egressPrivateCidrAllowlist: [] },
                    { label: 'tickets', url: MCP_TICKETS, agents: ['okta:app:0oaService1'], pinnedManifestHash: null, token: { value: MCP_TOKEN_VALUE }, egressPrivateCidrAllowlist: [] },
                ],
                resolveHost: publicDns,
            }),
            inflectRegisterSource({
                baseUrl: INGEST,
                tenantSlug: 'acme',
                apiKey: 'iflk_fake-ingest-key-3686',
                scannerAgentId: 'agt_scanner',
                egressProof: { met: true, evidence: 'egress:proxy:refused;direct=blocked', failed: null },
            }),
            langSmithSource({ endpoint: { cloud: 'us' }, apiKey: LANGSMITH_API_KEY_VALUE, workspaceId: null, windowDays: 7, readDeployments: true, resolveHost: publicDns }),
            langchainCodeSource({ roots: [{ label: 'acme', path: codeRoot }] }),
        ];
        reads = [];
        for (const source of sources) {
            const wire = createSourceWire({ fetchImpl: fakes.fetchImpl, deadline: ASOF.getTime() + 60_000, now: () => ASOF.getTime() });
            reads.push(await source.read({ asOf: ASOF, deadline: Number.MAX_SAFE_INTEGER, now: Date.now, ...wire }));
        }
    });

    const verdictsOf = (kind: string): CriterionVerdict[] => reads.filter((r) => r.kind === kind).flatMap((r) => r.observations.flatMap((o) => o.verdicts));

    it('every source read, and found principals', () => {
        expect(reads.map((r) => r.kind)).toEqual(['entra-sp', 'okta-app', 'vault', 'mcp', 'inflect-register', 'runtime', 'code']);
        for (const read of reads) expect([read.kind, read.observations.length > 0]).toEqual([read.kind, true]);
    });

    it('no source reports a criterion the table does not give it', () => {
        for (const read of reads) {
            for (const verdict of read.observations.flatMap((o) => o.verdicts)) {
                expect([read.kind, verdict.criterion, CRITERION_READERS[verdict.criterion].reportedBy.includes(read.kind)]).toEqual([read.kind, verdict.criterion, true]);
            }
        }
    });

    it('no source reports met a criterion the table says it cannot', () => {
        let met = 0;
        for (const read of reads) {
            for (const verdict of read.observations.flatMap((o) => o.verdicts).filter((v) => v.met)) {
                expect([read.kind, verdict.criterion, CRITERION_READERS[verdict.criterion].metBy.includes(read.kind)]).toEqual([read.kind, verdict.criterion, true]);
                met += 1;
            }
        }
        // Not vacuous: the identity sources and the register do report criteria met.
        expect(met).toBeGreaterThan(5);
        expect(verdictsOf('entra-sp').some((v) => v.met)).toBe(true);
        expect(verdictsOf('okta-app').some((v) => v.met)).toBe(true);
        expect(verdictsOf('inflect-register').some((v) => v.met)).toBe(true);
    });

    it('the code source reports verdicts, and none of them met', () => {
        expect(verdictsOf('code').length).toBeGreaterThan(0);
        expect(verdictsOf('code').filter((v) => v.met)).toEqual([]);
    });

    it('the vault and MCP sources attach to another source\'s agents and report no verdict about them', () => {
        // The premise of CROSS_AGENT_VERDICT_SOURCE: only a source that reports
        // verdicts under another source's id can lower another source's agent.
        for (const kind of ['vault', 'mcp', 'runtime']) {
            const read = reads.find((r) => r.kind === kind)!;
            expect(read.observations.length).toBeGreaterThan(0);
            expect(verdictsOf(kind)).toEqual([]);
            expect(CROSS_AGENT_VERDICT_SOURCE[kind as HarnessSourceKind]).toBe(false);
        }
        expect(reads.find((r) => r.kind === 'vault')!.observations.some((o) => o.discoveredId.startsWith('entra:sp:'))).toBe(true);
    });

    it('the register reports verdicts under ids another source discovers, which is why it alone is a cross-agent source', () => {
        const register = reads.find((r) => r.kind === 'inflect-register')!;
        expect(register.observations.some((o) => o.discoveredId.startsWith('entra:sp:') && o.verdicts.length > 0)).toBe(true);
        expect(CROSS_AGENT_VERDICT_SOURCE['inflect-register']).toBe(true);
    });
});

describe('4. what follows for a standalone result', () => {
    const everySource = SOURCE_KINDS.filter((kind) => kind !== 'inflect-register');

    it('without the register no run can state a level above H1, whatever else it reads', () => {
        expect(coverageOf(CRITERION_READERS, everySource).coverage.reachableLevel).toBe('H0');
        const { coverage } = coverageOf(CRITERION_READERS, [...everySource, 'inventory']);
        expect(coverage.reachableLevel).toBe('H1');
        // The two H2 criteria only the register reads are what stand in the way.
        const blocked = coverage.unreadable.filter((u) => u.criterion.startsWith('H2.'));
        expect(blocked).toEqual([
            { criterion: 'H2.audience_tokens', why: 'READER_NOT_CONFIGURED', readers: ['inflect-register'] },
            { criterion: 'H2.policy_card', why: 'READER_NOT_CONFIGURED', readers: ['inflect-register'] },
        ]);
    });

    it('with the register none can state a level above H3: nothing reads H4 or H5', () => {
        const { coverage } = coverageOf(CRITERION_READERS, [...SOURCE_KINDS, 'inventory']);
        expect(coverage.reachableLevel).toBe('H3');
        expect(coverage.unreadable).toEqual(
            [...HARNESS_CRITERIA.H4, ...HARNESS_CRITERIA.H5].map((criterion) => ({ criterion, why: 'NO_READER', readers: [] })),
        );
    });

    it('with code alone nothing is readable', () => {
        const { readable, coverage } = coverageOf(CRITERION_READERS, ['code']);
        expect(readable.size).toBe(0);
        expect(coverage.reachableLevel).toBe('H0');
    });

    it('reads the configured kinds off a configuration, in its order', () => {
        const config = parseScannerConfig({
            estate: 'acme',
            scanner: { agentId: 'agt_scanner', signingKeyEnv: 'SCANNER_SIGNING_KEY' },
            inflect: { baseUrl: INGEST, tenantSlug: 'acme', apiKeyEnv: 'INFLECT_INGEST_KEY' },
            schedule: { everyHours: 24 },
            sources: [
                { kind: 'code', product: 'langchain', roots: [{ label: 'acme', path: '/srv/code' }] },
                { kind: 'inflect-register' },
                { kind: 'okta-app', orgUrl: OKTA_ORG, apiTokenEnv: 'OKTA_API_TOKEN' },
            ],
        });
        expect(configuredSourceKinds(config)).toEqual(['code', 'inflect-register', 'okta-app']);
    });
});
