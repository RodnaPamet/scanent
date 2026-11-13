# @rodnapamet/scanent-contract

The report contract of [scanent](https://github.com/RodnaPamet/scanent), the
Agent Estate Scanner: the reference implementation a consumer verifies and
reads a signed scan report with.

The normative description is
[docs/contract.md](https://github.com/RodnaPamet/scanent/blob/main/docs/contract.md)
in the repository. This package is the code that page is written from.

## Install

The package is on GitHub Packages, not on npmjs.com. GitHub Packages asks for
a token on every install, whether a package is public or private.

1. In the project that will depend on it, in `.npmrc` beside `package.json`:

   ```
   @rodnapamet:registry=https://npm.pkg.github.com
   ```

2. In your own `~/.npmrc`, never in the project: a GitHub personal access
   token (classic) with the `read:packages` scope.

   ```
   //npm.pkg.github.com/:_authToken=<token>
   ```

3. Depend on an exact version:

   ```
   npm install --save-exact @rodnapamet/scanent-contract@<version>
   ```

"Use the reference implementation" in the contract page has the same steps
for a GitHub Actions workflow, and how to check where a tarball came from.

## Modules

Each module is imported by its own path. There is no index module.

| Import | Holds |
|---|---|
| `@rodnapamet/scanent-contract/harness-contract` | The strict report schemas, the limits, `verifyAndParseHarnessReport`, `harnessSignedMessage`, `LADDER_VERSION` |
| `@rodnapamet/scanent-contract/harness-contract-rules` | The contract ids, the source kinds, `looksLikeSecret`, `isScanComplete` |
| `@rodnapamet/scanent-contract/harness-ladder` | The levels and their criteria, `scoreHarness`, `collapseVerdicts`, `criterionState` |
| `@rodnapamet/scanent-contract/harness-matrix-model` | The table of agents against criteria: `buildHarnessMatrix`, `HARNESS_MATRIX_CELL_STATES`, `harnessJudgementOf`, `compareHarnessMatrixRows`. Imports only the ladder at run time, so a page may use it |
| `@rodnapamet/scanent-contract/harness-findings` | `planHarnessScan`: what a scan opens and closes, and the finding codes |
| `@rodnapamet/scanent-contract/canonical-json` | `canonicalJson`: the one form a signature and a hash are made over |
| `@rodnapamet/scanent-contract/receipt-verification` | Agent-action receipts: the schema and `verifyReceiptSignature` |
| `@rodnapamet/scanent-contract/audit-redact` | `redactSensitiveFields` |
| `@rodnapamet/scanent-contract/cidr` | `parseCidr`, `parseAddress`, `inCidr` |

```ts
import { verifyAndParseHarnessReport } from '@rodnapamet/scanent-contract/harness-contract';

const result = verifyAndParseHarnessReport(rawReportText, trustedSignerKeys);
if (result.ok) {
    // result.body, result.signerKey, result.complete
} else {
    // result.reason is one of the refusals of docs/contract.md
}
```

The package is CommonJS with type declarations, for Node 22 or later. It uses
Node's `crypto`, so it runs on a server and not in a browser, except
`harness-matrix-model` and the `harness-ladder` it imports, which import
nothing else. Its one dependency is `zod`, at an exact version.

## Licence

Business Source License 1.1. `LICENSE` and `NOTICE` are in the package.
