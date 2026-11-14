/**
 * `@scanent/scanner` — the reference harness scanner.
 * See README.md for what it reads, what it may import, and how to run it.
 */
export {
    parseScannerConfig,
    ScannerConfigSchema,
    ConfigError,
    credentialEnvNames,
    sourceCredentialEnv,
    type OutputConfig,
    type ScannerConfig,
    type ScannerConfigWithInflect,
} from './config';
export {
    addressReachable,
    assertResolvesReachable,
    customerOriginProblem,
    parsePrivateCidrAllowlist,
    type PrivateCidrAllowlist,
    type ResolveHost,
} from './customer-host';
export { createSourceWire, MAX_RESPONSE_BYTES, MAX_SOURCE_BYTES, type FetchLike, type ReadOnlyHttp, type TokenExchange } from './http';
export { configuredSourceKinds, CRITERION_READERS } from './criterion-readers';
export {
    decodeInventoryCsv,
    inventoryFormatOf,
    loadInventoryFile,
    MAX_INVENTORY_BYTES,
    type InventoryFileDeps,
} from './inventory-file';
export { DIFF_USAGE, DiffInputError, runDiff, type DiffIo } from './diff-command';
export { OutputRefusedLocally, SCAN_ID_PATTERN, writeRun, type FileOutputDeps, type WrittenRun } from './file-output';
export { loadConfiguredInventory, scoreScanLocally } from './local-results';
export {
    NOWHERE_TO_DELIVER,
    OutputsError,
    resolveOutputs,
    scanAndDeliver,
    type DeliverDeps,
    type DeliveryResult,
    type OutputKind,
} from './outputs';
export { jsonLineLog, type ScannerLog } from './log';
export { postReport, postIntegrationsReport, ingestUrl, type IngestReport, type IntegrationsPostResult, type PostResult } from './post';
export { buildReportBody, signReport, rawPublicKeyHex, ReportRefusedLocally, type ScanIdentity } from './report';
export {
    buildSources,
    ingestTarget,
    integrationsIngestTarget,
    loadSigningKey,
    postSignedIntegrationsReport,
    postSignedReport,
    runScan,
    scanAndPost,
    type Env,
    type InflectDelivery,
    type ScanDeps,
} from './scan';
export { isDeclaredRequest, scannerManifestHash, SCANNER_SURFACE, SCANNER_VERSION } from './scanner-surface';
export { runOnSchedule } from './schedule';
export {
    SourceReadError,
    type HarnessSource,
    type Observation,
    type ObservedToolUse,
    type SourceContext,
    type SourceKind,
    type SourceRead,
} from './source';
export { azureKeyVaultSource, type AzureKeyVaultSourceOptions } from './sources/azure-key-vault';
export {
    analyseWorkflow,
    githubActionsSource,
    GITHUB_API_ORIGIN,
    GITHUB_READ_PATHS,
    type GitHubActionsSourceOptions,
    type WorkflowAnalysis,
} from './sources/github-actions';
export {
    gcpServiceAccountSource,
    GCP_IAM_ORIGIN,
    GCP_READ_PATHS,
    GOOGLE_OAUTH_ORIGIN,
    type GcpServiceAccountSourceOptions,
} from './sources/gcp-service-accounts';
export { langchainCodeSource, scanLangChainCode, type LangChainCodeSourceOptions } from './sources/langchain';
export type { DetectedAgent, DetectedCredential, DetectedModel, DetectedTool } from './sources/code/recognize';
export { langSmithSource, LANGSMITH_CLOUD_ORIGINS, LANGSMITH_READ_PATHS, type LangSmithSourceOptions } from './sources/langsmith';
export { oktaSource, type OktaSourceOptions } from './sources/okta';
// Client deployment (Phase 3): exit codes, secrets from files, key generation, the hosts a
// configuration reaches, the proxy as the environment names it, the setup wizard and the preflight.
export { EXIT, EXIT_CODE_TABLE } from './exit-codes';
export { readSecretFile, resolveSecretEnv, SecretFileError, type SecretFileReason } from './secrets';
export { generateSigningKey, KeygenError } from './keygen';
export { hostsFor, renderHosts, type HostEntry, type HostsFormat } from './hosts';
export { describeProxy, isProxied } from './proxy-env';
export { ACCESS_GUIDE, accessTablesFor, renderAccessMarkdown, type AccessTable } from './init/access-guide';
export { InitError, INIT_ANSWERS_SCHEMA, parseInitAnswers, type InitAnswers } from './init/answers';
export { planInit, renderEnvTemplate, type InitPlan } from './init/plan';
export { InitRefused, writeInit, type WrittenInit } from './init/write';
export { runDoctor, type DoctorDeps } from './doctor/run';
export { renderDoctorJson, renderDoctorText } from './doctor/render';
export { DOCTOR_SCHEMA, type Check, type DoctorReport } from './doctor/types';
export type { ProbeStep, WriteObservation } from './source';
