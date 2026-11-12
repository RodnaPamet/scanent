# Compatibility fixtures

One directory per version; from the first release on, one per released
version. No version has been released yet. Each holds what that version wrote and
read, made once from a checkout of that version, and never changed afterwards.
`../../compat.test.ts` reads every directory here with the current code.

| File | What it is |
|---|---|
| `out/latest.json`, `out/runs/<scanId>/` | One run of the offline example (`examples/code-only`, with its inventory), as `scan --dry-run --out` wrote it: the six files |
| `public-key.txt` | The raw public key of the key that run was signed with. The private key was discarded |
| `doctor.json` | `doctor --json` for the same configuration. The directory names in its text were replaced by `/srv/scanent` after the fact; nothing else was |
| `inventory.example.json`, `inventory.example.csv` | The example inventory, and the same rows as CSV. That version scored both the same. A later version may have retired the schema they are written in; it then refuses both and says what changed, and the test holds it to that |
| `configs/` | Every example configuration and answers file of that version (`deploy/examples`, `examples/code-only`) |

`0.12.0` was made from commit `190f3fb`, an earlier commit of the current,
unreleased version: the last one before the results file
gained `toolEvidenceSources`. It is the proof that the member is an addition.

Its inventory is `scanent-inventory/1`, which the current code refuses:
`scanent-inventory/2` took the axis names, their values and the risk tiers of
Inflect's agent register. No version was released with `/1`, so the files are
kept as what that commit read and are not converted. The comparison of that
commit's run with a run by the current code uses the current example inventory
(`examples/code-only/inventory.example.json`), which declares the same agents.

A release adds a directory. None is removed while that version is supported
(`docs/release-checklist.md`).
