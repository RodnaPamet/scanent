# The harness matrix: one table model

Status: implemented in `packages/contract/src/harness-matrix-model.ts`. scanent's
local results are built from it. Inflect's harness tab is to read it as well;
until it does, Inflect keeps its own table code. Where this note and the code
disagree, the code is right.

## Why it exists

scanent and Inflect both show a scan as a table: one row per agent, one column
per criterion of the harness ladder. The ladder is the same module in both, but
the tables were not. scanent split the table across its scorer, its judgement
rule, its HTML page and its CSV writer, with seven cell states. Inflect built
its own in the harness tab, with four cell states and a different row order.
Two tables of one scan could disagree about the same agent.

The owner decided on one shared table model in the contract package. Both
products read it. A product decides how a row looks. It does not decide what
the row says.

## What goes in

`buildHarnessMatrix(input)` takes one scan:

| Member | What it is |
|---|---|
| `agents` | Each agent as the findings planner gives it (`PlannedAgent` fits), with `verdicts` set to the OBSERVED verdicts alone. `null` verdicts are stored verdicts that could not be read back. |
| `sources` | The scan's sources with status and reason. `null` when they could not be read back. |
| `readers` | Optional: the criterion-reader table and the readers the run was configured with. Without it, no cell is "not readable" and no coverage is stated. |
| `declared` | Optional: declared verdicts by `discoveredId`, each with its own evidence reference (an operator's inventory). |

## What comes out

- `columns`: the criteria grouped by the level that first requires them, H1 to
  H5 (`HARNESS_MATRIX_COLUMNS`).
- `rows`: one per agent, in the order given. Each row has the agent's id, an
  optional name hint (declared or from the register, and it says which), its
  class (registered, shadow agent, unregistered identity), its registration,
  reach, model signs and payment capabilities, its judgement, `level`,
  `observedLevel`, `blockingNextRung`, `bar`, `barStatus`, `heldToBar`,
  `countsAsShortfall`, and one cell per criterion.
- `coverage`: the highest level the run could have stated and each criterion it
  could not have evidenced, with why. `null` when the readers are not known.
- `population`: agent, judged and not-judged counts, and completeness
  (`COMPLETE`, `INCOMPLETE` or `EMPTY`).

## A cell

Each cell has one of seven states, in this order (`HARNESS_MATRIX_CELL_STATES`):

| State | Meaning | Met? |
|---|---|---|
| `EVIDENCED` | A source observed it, with evidence | yes |
| `DECLARED` | Evidenced on what an operator declared; no source observed it | yes |
| `MET_UNEVIDENCED` | Reported met with no evidence reference | no |
| `NOT_MET` | A source saw it fail | no |
| `NOT_MET_DECLARED` | Not met on what an operator declared; no source saw it fail | no |
| `UNANSWERED` | A configured reader could have reported it, and none did | no |
| `NOT_READABLE` | Nothing the run was configured to read could have reported it met | no |

These are also the words `agents.csv` and `scanent diff` use. A cell also
carries the ladder's own four-state reading (`verdictState`), the basis of the
verdict that decided it (`OBSERVED` or `DECLARED`), that verdict's evidence
reference, and whether it was readable. Inflect's four states are the
`verdictState` of a table built without readers or declarations.

## The rules it holds

- **A cell is the ladder's rule**: `criterionState` over `collapseVerdicts`. A
  criterion reported twice shows its least favourable answer. A "met" with no
  evidence is not met.
- **A declaration never outvotes an observation.** Declared verdicts follow the
  observed ones into the collapse, so an observed NOT MET stands. Where both say
  the same, the observed one stands. `observedLevel` is the level with every
  declaration removed.
- **An incomplete source closes nothing.** An agent is judged only when every
  source it was discovered through, and every source that reports verdicts
  about other sources' agents (the register), was read in full
  (`harnessJudgementOf`). Otherwise it is NOT JUDGED with coded reasons, and
  `level`, `observedLevel` and `blockingNextRung` are `null`, never `H0`.
- **Zero is never complete.** A scan with no agents is `EMPTY`.
- **An unregistered automated identity is held to no bar.** `barStatus` still
  says where its level stands against the bar its reach would carry;
  `heldToBar` is false, and `countsAsShortfall` is false.

## Row order

`compareHarnessMatrixRows` puts the worst first: not judged, then below the
bar, then at the bar; within each, the lowest level first; then by id. A
surface that can show only some rows shows the first ones. scanent's page does
this above 500 agents. The comparator reads `barStatus`, not
`countsAsShortfall`, so an unregistered identity below the bar its reach would
carry sorts among the agents below theirs.

## It runs in a browser

The module has one runtime import, the ladder, which has none. Everything else
it imports is a type. A test in `packages/contract/tests` holds that, so a
client component can call the same functions the server called.

## What stays with each product

The model knows a scan and nothing about a product's records. These stay as
columns of the product's own, joined to a row by `discoveredId`:

- Inflect: the register name and link, the acceptance and its affordance, the
  level a later-received scan read, drift between scans, and the row cap and
  "rows unread" flag of a partial read.
- scanent: the declared owner and purpose, the observed owner, the counts of
  credentials and tools, and the results file's own fields.
