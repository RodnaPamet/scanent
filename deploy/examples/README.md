# Example configurations

One per common shape of estate. Each is what `scanent init` writes for the
answers file beside it, and a test holds the three files to each other.

| Example | Sources | Credentials it names |
|---|---|---|
| `code-only` | Agent code in local directories | The signing key |
| `cloud-identities` | Entra, Azure Key Vault, Okta | The signing key and three more |
| `ci-and-cloud` | GitHub Actions, Google Cloud service accounts | The signing key and two more |
| `everything` | All eight sources a person can choose | The signing key and seven more |

For each `<name>`:

| File | What it is |
|---|---|
| `<name>.answers.json` | The answers. `scanent init --answers <file>` reads it |
| `<name>.json` | The configuration `init` writes from them |
| `<name>.env` | The env template `init` writes: credential NAMES with nothing after the `=`, or a file's path |

The identifiers are placeholders: replace the directory id, the client id, the
organisation URL, the repositories and the project with your own. No file here
holds a credential, and none should: a value goes in your copy of the env file,
or in your secret store.

To make your own from an example:

```bash
scanent init --dir ./scanent --answers deploy/examples/ci-and-cloud.answers.json
```

After changing an answers file, `npm run build && npm run docs:examples`
rewrites the other two.
