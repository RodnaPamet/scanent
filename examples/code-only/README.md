# Example: a code-only estate

`estate/` holds one LangChain agent definition. The `code` source reads it from
disk and makes no network request, so `scan --dry-run` over it works offline.
The repository's README has the commands.
