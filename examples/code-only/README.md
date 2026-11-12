# Example: a code-only estate

`estate/` holds one LangChain agent definition. The `code` source reads it from
disk and makes no network request, so a scan of it works offline. The
repository's README has the commands.

| File | What it is |
|---|---|
| `estate/` | The code that is scanned |
| `config.template.json` | A configuration that names an Inflect tenant. Replace `__REPO__` with the checkout's absolute path. `scan --dry-run` prints the signed report; without `--dry-run` it is posted to the tenant |
| `config.local.template.json` | The same estate with no tenant at all: no `inflect` block, and the inventory below. Run it with `--out <dir>` to write the results locally |
| `inventory.example.json` | An operator's inventory. It declares the example agent (owner, purpose, the three axes and a risk tier), and one agent the estate does not contain |

The inventory's `riskAssessedOn` is a fixed date. A risk tier counts as fresh
for 365 days, so a scan taken more than a year after that date reports
`H1.tier_scored_fresh` as not met and the agent at H0. Change the date to see
it at H1.
