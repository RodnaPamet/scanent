# @scanent/report

Local results for scanent: what one scan means to somebody with no Inflect
tenant. Design: `docs/design/phase-2-standalone-results.md`.

Every export is a pure function: data in, data out. Nothing here reads a file,
the network, the process or the clock, and no Node built-in is importable
(`eslint.config.mjs` holds that). The scanner reads, hashes and decodes, and
hands the values in.

| Module | Holds |
|---|---|
| `results/score` | `scoreReportLocally(input)`: a signed report body, an optional inventory and the reader table, to `LocalResults`. Each agent's row (cells, judgement, level, bar) is the contract's table model (`buildHarnessMatrix` in `harness-matrix-model`), and the findings are the contract's planner; none is re-implemented here |
| `results/types` | `LocalResults` (the content of `results.json`), `ScoreInput`, and `CriterionReaders` from the contract's table model |
| `results/schema` | `LocalResultsSchema`, the strict schema a results file is read back with |
| `results/inventory` | The operator's inventory: the strict schema, `parseInventory`, and the four H1 verdicts a matched row declares |
| `render/results-json` | `renderResultsJson`: the results as text with sorted keys, so the same results give the same bytes |
| `render/csv` | `renderAgentsCsv`, `renderFindingsCsv` and `csvCell`, the one function every cell passes through: RFC 4180, and a cell a spreadsheet would evaluate is neutralised |
| `render/html` | `renderSummaryHtml`: one self-contained page: the static sections, one JSON data block and one inline script, allowed by a hash-based CSP. Nothing loaded |
| `render/page-data` | `summaryPageData`: what the page's script and `report.pdf` show, from the shared table model (`render/matrix-of-results`) |
| `render/page-script` | The page's script, as text |
| `render/escape` | The `html` template every string enters the page through. There is no exported way to mark text as safe |
| `render/files` | The names of the files one run writes |
| `results/integrations` | `scoreIntegrationsLocally(input)`: the integrations scanner's signed report body to its section of the results, by the contract's planner |
| `render/integrations-csv` | `renderIntegrationsCsv`, `renderIntegrationFindingsCsv`: one row per application, and per integration finding |
| `render/integrations-page` | The page's and the PDF's integrations section: its static tables, its data block, its own script and style, and its comparison with the previous run |
| `diff/diff` | `diffResults(old, new)`: what changed between two runs, and what could not be compared |
| `diff/integrations-diff` | `diffIntegrations(old, new)`: the same for the integrations scanner, by the same rule |
| `diff/run-diff` | `diffRuns(old, new)`: two runs scanner by scanner. Two runs of the agent scanner alone give `diffResults`' answer, unchanged |
| `render/diff-text` | `renderDiffText`: a diff for a terminal |
| `render/run-diff-text` | `renderRunDiffText`: a run diff for a terminal, one heading per scanner |

Three rules the results keep:

- An agent whose sources were not read in full is `NOT_JUDGED`, with the
  reasons, and carries no level, bar or shortfall.
- What the operator's inventory says is `DECLARED`, never `OBSERVED`. It
  matches by exact `discoveredId` only and evidences nothing above H1.
- An empty scan is a finding (`EMPTY_SCAN`), never a clean result.

Three more the renderers and the diff keep:

- Scanned data is untrusted. In the page it is escaped wherever it lands and
  never becomes a tag, an attribute, a class or a link; in a CSV it never
  starts a formula.
- An agent that was not judged has no level in any file: the page says "Not
  judged", the CSV cells are empty.
- Absence is evidence only on a full read. `diffResults` calls an agent
  `GONE`, or a finding `CLOSED`, only when the newer run read the relevant
  source in full; otherwise `NOT_SEEN` or `NOT_CONCLUDED`, with why.

Writing the files, and the secret check over each before it is written, are
the scanner's (`packages/scanner/src/file-output.ts`).

Licence: BUSL-1.1, see the repository's `LICENSE`.
