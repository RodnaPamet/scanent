# Security intake pack

For a security reviewer deciding whether scanent may run in an estate. This
folder is an index and a set of summaries. The detailed documents it points
to stay where they are; nothing here repeats them.

**Read [Assurance status](assurance-status.md) first.** scanent has been
tested and hardened in development. It has not been run against a real
estate, has had no external penetration test, and has no published signed
release. That page lists what has and has not been done.

## What is in the pack

| Question | Read |
|---|---|
| What is it, and how is it built? | [Architecture](architecture.md): components, data flows, trust boundaries, one diagram |
| Which controls exist, where is each enforced, and which test proves it? | [Controls](controls.md) |
| What has been tested, and what has not? | [Assurance status](assurance-status.md) |
| What is in it, and under which licences? | [SBOM and licences](sbom-and-licences.md) |
| Who fixes what, and how does it change? | [Support and maintenance](support-and-maintenance.md) |

## The detailed documents

| Question | Read |
|---|---|
| What does it defend against, how, and what is left? | [Threat model](../threat-model.md): STRIDE by trust boundary, 15 residual risks |
| Exactly which requests can it make, and which grants does it ask for? | [Network and permissions](../network-and-permissions.md), generated from the code and checked against it |
| Which read-only grant does each source need? | [Access the scanner needs](../access.md), generated from the code |
| What personal data does it touch? Is there a DPIA template? | [Data protection](../data-protection.md) |
| How do I check a release's signature, SBOM and provenance? | [Verify a release](../verify-a-release.md) |
| What does the signed report contain, and how is it verified? | [The report contract](../contract.md) |
| How is it deployed and hardened at run time? | [Deployment](../deployment.md) |
| What does it log, and what do its exit codes mean? | [Operating scanent](../operations.md) |
| How do I report a vulnerability? | [Security policy](../../SECURITY.md) |
| What is not in this version? | [Roadmap](../roadmap.md) |

For the people arranging a scan, not reviewing the software, there is the
[engagement kit](../engagement/README.md).

## Five facts to hold on to

1. **It reads and does not write.** A source is handed an HTTP client whose
   only verb is GET. Every request the scanner can make is declared in one
   file, and the hash of that declaration is in every signed report.
2. **It does not ask for secret values.** Credentials are reported by
   reference. One listing that carries secret values (LangSmith deployments)
   is off by default; see the threat model, residual risk 10.
3. **It sends nothing by default.** Results are files in a directory the
   operator chooses. Posting to a tenant is optional. There is no telemetry.
4. **A partial read is reported as partial.** A source that could not be read
   in full is `INCOMPLETE` with a reason, and nothing about it is reported as
   resolved.
5. **It is not open source.** It is source-available under the Business
   Source License 1.1; the licensor is Inflect Ltd.

## How this pack is kept honest

A test, `packages/scanner/tests/security-pack.test.ts`, runs with the unit
tests on every change. It fails when:

- a file path cited in this folder, in the engagement kit or in the roadmap
  does not exist, or a function cited beside a file is not in that file;
- a relative link does not resolve, or points at a heading that is not there;
- the dependency table in [SBOM and licences](sbom-and-licences.md) differs
  from the production set of the lockfile;
- a page uses the words "open source" without saying the product is not, or
  [Assurance status](assurance-status.md) stops naming what has not been done.

The test checks that citations resolve. It cannot check that a sentence is
true. Read the code a row cites before relying on the row.
