# Compatibility fixtures

One directory per released version. Each holds what that version wrote and
read, made once from a checkout of that version, and never changed afterwards.
`../../compat.test.ts` reads every directory here with the current code.

| File | What it is |
|---|---|
| `out/latest.json`, `out/runs/<scanId>/` | One run of the offline example (`examples/code-only`, with its inventory), as `scan --dry-run --out` wrote it: the six files |
| `public-key.txt` | The raw public key of the key that run was signed with. The private key was discarded |
| `doctor.json` | `doctor --json` for the same configuration. The directory names in its text were replaced by `/srv/scanent` after the fact; nothing else was |
| `inventory.example.json`, `inventory.example.csv` | The example inventory, and the same rows as CSV. That version scored both the same |
| `configs/` | Every example configuration and answers file of that version (`deploy/examples`, `examples/code-only`) |

`0.12.0` was made from commit `190f3fb`, the last one before the results file
gained `toolEvidenceSources`. It is the proof that the member is an addition.

A release adds a directory. None is removed while that version is supported
(`docs/release-checklist.md`).
