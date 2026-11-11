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

Three rules the results keep:

- An agent whose sources were not read in full is `NOT_JUDGED`, with the
  reasons, and carries no level, bar or shortfall.
- What the operator's inventory says is `DECLARED`, never `OBSERVED`. It
  matches by exact `discoveredId` only and evidences nothing above H1.
- An empty scan is a finding (`EMPTY_SCAN`), never a clean result.

The output files (`results.json`, the CSVs, `summary.html`) and `scanent diff`
are not built yet.

Licence: BUSL-1.1, see the repository's `LICENSE`.
