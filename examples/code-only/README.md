# Example: a code-only estate

`estate/` holds one LangChain agent definition and one agent skill
(`support/skills/order-lookup/`: a `SKILL.md` and the script it runs). The
`code` source reads both from disk and makes no network request, so a scan of
it works offline: the agent goes into the agent report, and the skill is read by
the agent-surface rules, whose report is the second one a scan prints. Neither
the skill nor its script fires a rule. The repository's README has the
commands.

| File | What it is |
|---|---|
| `estate/` | The code that is scanned |
| `config.template.json` | A configuration that names an Inflect tenant. Replace `__REPO__` with the checkout's absolute path. `scan --dry-run` prints the signed report; without `--dry-run` it is posted to the tenant |
| `config.local.template.json` | The same estate with no tenant at all: no `inflect` block, and the inventory below. Run it with `--out <dir>` to write the results locally |
| `inventory.example.json` | An operator's inventory. It declares the example agent (owner, purpose, the four axes and a risk tier), and one agent the estate does not contain |

The inventory's `riskAssessedOn` is a fixed date. A declared risk tier counts
as fresh for 365 days, so a scan taken more than a year after that date reports
`H1.tier_scored_fresh` as not met and the agent at H0. Change the date to see
it at H1.
