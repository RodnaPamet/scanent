# @scanent/report

Local results for scanent: what one scan means to somebody with no Inflect
tenant. Design: `docs/design/phase-2-standalone-results.md`.

Every export is a pure function: data in, data out. Nothing here reads a file,
the network, the process or the clock, and no Node built-in is importable
(`eslint.config.mjs` holds that). The scanner reads, hashes and decodes, and
hands the values in.

| Module | Holds |
|---|---|
| `results/score` | `scoreReportLocally(input)`: a signed report body, an optional inventory and the reader table, to `LocalResults`. The level, the cell states, the bar and the findings are the contract's own functions; none is re-implemented here |
| `results/types` | `LocalResults` (the content of `results.json`), `ScoreInput`, `CriterionReaders` |
| `results/schema` | `LocalResultsSchema`, the strict schema a results file is read back with |
| `results/inventory` | The operator's inventory: the strict schema, `parseInventory`, and the four H1 verdicts a matched row declares |
| `results/judgement` | When an agent may be given a level at all (`judgementBasisOf`, `CROSS_AGENT_VERDICT_SOURCE`) |
| `render/results-json` | `renderResultsJson`: the results as text with sorted keys, so the same results give the same bytes |
| `render/csv` | `renderAgentsCsv`, `renderFindingsCsv` and `csvCell`, the one function every cell passes through: RFC 4180, and a cell a spreadsheet would evaluate is neutralised |
| `render/html` | `renderSummaryHtml`: one self-contained page. No script, nothing loaded, one style block |
| `render/escape` | The `html` template every string enters the page through. There is no exported way to mark text as safe |
| `render/files` | The names of the files one run writes |
| `diff/diff` | `diffResults(old, new)`: what changed between two runs, and what could not be compared |
| `render/diff-text` | `renderDiffText`: a diff for a terminal |

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
