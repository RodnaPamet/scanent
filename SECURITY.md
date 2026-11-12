# Security policy

scanent runs inside an estate and holds read credentials for it. A defect that
lets it write, leak a credential, or report something false as true matters,
and we want to hear about it privately first.

## Reporting a vulnerability

Report it through GitHub's private vulnerability reporting for this
repository: the **Security** tab, then **Report a vulnerability**
(<https://github.com/RodnaPamet/scanent/security/advisories/new>). The report
is visible only to you and the maintainers.

Please do not open a public issue, a pull request or a discussion for a
vulnerability, and do not include a real credential, a real report or a real
estate's data in a report. A synthetic example is enough.

What helps:

- the version (`scanent help` does not print it; the image tag, or
  `SCANNER_VERSION` in `packages/scanner/src/scanner-surface.ts`), and how it
  was run (the image, the chart, Compose, from source);
- what you did, what happened, and what you expected;
- the smallest configuration or input that shows it, with names replaced;
- the impact you see: what could be read, written, forged or hidden.

`scanent support-bundle` (`docs/operations.md`) describes a deployment without
its credentials and with its names replaced; attach its output if it helps.

## What to expect

- An acknowledgement within 5 working days.
- An assessment, and whether we accept it as a vulnerability, within
  15 working days.
- A fix in a new release for an accepted vulnerability, with an advisory that
  credits you unless you ask otherwise. We will agree a disclosure date with
  you, and aim for no more than 90 days from the report.

This is a small project. If the times above cannot be met for a report, we
will say so in the advisory thread, not go quiet.

## In scope

- The scanner (`packages/scanner`), the report contract (`packages/contract`)
  and the local results (`packages/report`).
- The container image, the Helm chart, the Compose files and the air-gapped
  bundle under `deploy/`.
- The release workflow and what it signs.

Of particular interest:

- any request that is not a read, or that is not declared in
  `packages/scanner/src/scanner-surface.ts`
  (`docs/network-and-permissions.md` lists them all);
- a credential, a token or a secret value reaching a log, a report, a results
  file or an error message;
- a request, with a credential, sent to a host the configuration does not name
  (server-side request forgery, a followed redirect, DNS rebinding);
- an input (a provider's response, a repository's contents, an inventory, a
  configuration) that makes the scanner execute code, read outside a
  configured root, or hang past its time box;
- a report that verifies but was not produced by the holder of the signing
  key, or a source reported as read in full when it was not;
- a way out of the egress proxy.

## Out of scope

- A credential that was given more than read access. The scanner asks for
  read-only access (`docs/access.md`); what a credential can do is set where it
  is issued.
- Findings about the services the scanner reads (a provider's API, an MCP
  server): report those to their owners.
- A compromised machine, or a user who can already read the scanner's
  configuration and credentials.
- Reports from automated tools with no demonstrated impact.

`docs/threat-model.md` says what the scanner defends against, how, and what it
does not.

## Supported versions

The latest released version receives security fixes. Before version 1.0 there
are no maintenance branches: a fix is a new release, and the release notes say
whether a configuration that scanned before needs to change.

## Verifying what you run

Releases are signed, with an SBOM and build provenance:
`docs/verify-a-release.md`.
