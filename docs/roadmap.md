# Roadmap: what is not in this version

What scanent does not do today, taken from the code and from the open issues
of the repository. These are open items. None is a promise, none has a date,
and none should be offered to a client as coming.

"This version" is the scanner at version 0.13.2.

## Sources that are not usable

### NVIDIA OpenShell gateway

A reader for the OpenShell gateway is in the source tree
(`packages/scanner/src/sources/openshell.ts`) and is tested against an
imitation of the gateway. **It cannot be used.** The gateway speaks gRPC, and
this version carries no gRPC transport: the wire in
`packages/scanner/src/http.ts` answers "not built into this scanner". The
configuration schema has no entry that selects the source, so no scan can
make such a call.

Its five read calls are still part of the declared request surface, and so of
the manifest hash in every report, which is why
[Network and permissions](network-and-permissions.md#declared-and-not-reachable-from-a-configuration)
lists them. Making it usable needs a decision on a gRPC dependency in the
image, then the transport, a configuration entry and an end-to-end test
(issue 8).

### Cloud agent platforms

No source reads any of these:

- **AWS**: IAM roles, Bedrock agents.
- **Azure AI Foundry** agents.
- **Google Vertex AI** agents.

What exists nearby, so that it is not mistaken for coverage:

- Google Cloud **service accounts and their keys** are read (`gcp-sa`). That
  is identity, not Vertex agents.
- Microsoft Entra **service principals** are read (`entra-sp`). That is
  identity, not Azure AI Foundry.
- The `code` source recognises Bedrock and Vertex **model classes** in
  LangChain code, and a model call that is given tools on the Bedrock runtime
  SDK or the Gemini SDK, and reports the model endpoint an agent's code names.
  It reads source files, not the cloud platform.

Each would be a new source, and where it is a new source kind, a new report
contract id. The steps are in
[Support and maintenance](security-pack/support-and-maintenance.md#how-a-new-source-is-added).

### Other products under the existing kinds

Each kind is read from one product today:

| Kind | Read today | Not read |
|---|---|---|
| `cicd` | GitHub Actions | Any other CI system |
| `vault` | Azure Key Vault | Any other secret store |
| `runtime` | LangSmith | Any other tracing or agent runtime (OpenShell: see above) |
| `code` | LangChain, LangGraph and the Claude Agent SDK, and agents built directly on the Anthropic, OpenAI and Azure OpenAI, Google Gemini or AWS Bedrock SDK, in Python, JavaScript and TypeScript | Any other agent framework, any other provider's SDK, any other language. An agent written with one of those is not found. On a provider's SDK an agent is a model call that is given tools: one that is given none is not reported, and one built in a way the reader cannot follow (a request assembled in another file) is reported with what it could read, or named as a place it could not |

## Levels the scanner cannot evidence

The ladder has six levels, H0 to H5. What a scan can show is limited by what
its sources read (`packages/scanner/src/criterion-readers.ts`):

- **H4 and H5: no source reports any of their nine criteria.** No agent can
  be shown at H4 or H5 by this version, whatever its real state. The criteria
  are a baseline ledger, receipts, a drilled kill switch and a token budget
  (H4), and coverage, emitted evidence, evaluated skills, a sample audit and
  an independent audit (H5).
- **H2 and H3 need an Inflect tenant's register.** Nine of their twelve
  criteria can be reported as met by the register source only, two of the
  five on H2 and all seven on H3. So without a register no agent is shown
  above H1, and with one none is shown above H3.
- **H1 needs the register or an operator's inventory file.** With neither, no
  agent is shown above H0.

The results say this per criterion ("No reader in scanent reports this
criterion"), so a missing reader is not mistaken for a failed check. Whether
to add sources that evidence H4 and H5 is an open product decision (issue 15).

## Other scanners

scanent scans agents only. An integrations scanner, a vulnerability scanner
and a static adversarial reviewer of agent code are proposed in
[Several scanners in one scanent](design/scanners.md), which lists the
decisions they need. None is built.

## Packaging and distribution

- **One release.** The image is public (owner decision, 2026-11-12, issue 19).
  0.13.2 is the first complete release: a public, signed
  image with SBOM and provenance, a signed air-gapped bundle, and the
  contract package on GitHub Packages as `@rodnapamet/scanent-contract`
  (issue 7). Installing that package needs a token, even when the package is
  public (`docs/contract.md`).
  `@scanent/report` and `@scanent/scanner` are private workspace packages and
  are not published.
- **The originating application carries its own copy of the contract.** The
  two were identical at extraction and nothing keeps them so until that
  application depends on the package (issue 7; `docs/EXTRACTION.md` lists
  what remains for it to do).
- **The Helm chart writes to a volume only.** There is no object-store output
  (issue 19).

## Known gaps in what a scan reports

- **The scanner cannot tell which automated identities run a model.** On the
  first pilot's estate 34 of 40 principals were on no list: CI workflows that
  hold a credential, service accounts and service principals. Since 0.13.0 a
  principal that shows no sign of a model is reported as an unregistered
  automated identity, at MEDIUM, and is not held to the agent bar (issue 25).
  The signs are where it was found and whether it lists a tool or a model.
  A workflow that calls a model through a key it holds shows none of them,
  and is reported as an identity. There is no way yet for an operator to
  record "this is automation, not an agent, and this is its owner": the only
  way to clear the finding is to declare it an agent in the inventory.
- **Okta API tokens of other users may not be seen**, and the report does not
  say so. Unconfirmed against a live Okta organisation (issue 16; threat
  model, residual risk 3).
- **Tool call counts are not reported.** The contract has a member for them;
  the scanner does not fill it (`packages/scanner/src/source.ts`).
- **Write-access checks are partial.** `doctor` can tell that a credential
  can write for Entra (from the roles in its token) and for a GitHub classic
  token. For Okta, Azure Key Vault, Google Cloud, LangSmith and MCP servers
  it reports the check as not observable. For Okta, Key Vault and Google,
  seeing the grant would need one more declared read or a request that is not
  a read (issue 19).
- **An incomplete scan exits 0 by default.** `--strict` opts in to a non-zero
  exit. Changing the default is an open decision (issue 19).

## Hardening follow-ups

From the internal hardening review (issue 20). Four of its five follow-ups
were acted on in 0.13.0. What is left of each:

- **The egress proxy is bounded, not defended.** It closes a silent
  connection after two minutes and holds at most 256. A peer that can reach
  its port can still use them all
  ([threat model](threat-model.md#residual-risks), risk 14).
- **A secret file is checked by its own mode.** One that its group or every
  user can write is refused. Its directory and its owner are not checked
  (risk 12).
- **A model name is held to the shape of one.** A literal that is not shaped
  like a model name is reported as not known. A credential that happens to be
  shaped like a short name, with separators, would still be reported.
- The grant of each token exchange is inside the hashed request surface.
  Nothing is left of that one.

The provenance of a release was checked on 0.13.2: `gh attestation verify`
passed for the bundle and the image manifest (issue 20, item 4).

## Assurance work

Not features, but the largest open items. They need people or time, not
code (issue 21):

- pilots at clients, and on the providers the first pilot did not cover
  (Okta, Azure Key Vault, LangSmith, MCP), with false positives and false
  negatives recorded per source;
- a 72-hour soak, required before 1.0 (a 75-minute one has been run);
- an external penetration test and code review;
- the verification commands run by somebody other than the maker, against a
  release they downloaded themselves (0.13.2 has been checked once, by its
  maker).

[Assurance status](security-pack/assurance-status.md) has the detail.

## Where this list comes from

The open issues of the repository are the authority, and they move faster
than this page. An issue may be partly addressed in code and still open. For
each item above, the cited file or document is where to check what is true
today.
