# Software bill of materials and licences

What scanent is made of, under which licences, how the bill of materials
(SBOM) is produced, and what the Business Source License means in plain
words.

This page is not legal advice. The [LICENSE](../../LICENSE) file is the
licence; where this page and that file differ, the file is right.

## Production dependencies

These are the packages that ship in the image, read from `package-lock.json`:
every entry that is not a development dependency. A test
(`packages/scanner/tests/security-pack.test.ts`) fails when this table differs
from the lockfile or from the licence each installed package states, so the
table is updated in the same change as any dependency.

<!-- deps:production -->
| Package | Version | Licence | What it is used for |
|---|---|---|---|
| `typescript` | 5.9.3 | Apache-2.0 | Its parser reads JavaScript and TypeScript source as text, for the `code` source. Nothing is compiled or run at run time |
| `zod` | 4.6.7 | MIT | Strict schemas for the report, the configuration and every other input |
| `@rodnapamet/scanent-contract` | 0.13.0 | BUSL-1.1 | scanent's own package: the report contract |
| `@scanent/report` | 0.0.0 | BUSL-1.1 | scanent's own package: local results |
| `@scanent/scanner` | 0.0.0 | BUSL-1.1 | scanent's own package: the scanner and its command line |
| `argparse` | 3.0.4 | PSF-2.0 | A dependency of `js-yaml` |
| `js-yaml` | 5.5.0 | MIT | Reads GitHub Actions workflow files, which are YAML |
<!-- /deps:production -->

Four third-party packages, each pinned to an exact version, each with an
integrity hash in the lockfile. Development dependencies (the test runner,
the linter, type definitions) are not in the image and are not listed here.

`@scanent/report` and `@scanent/scanner` show version `0.0.0` because they
are never published. `@rodnapamet/scanent-contract` is the one package a
release publishes, to GitHub Packages, and it carries the scanner's version;
no version of it has been published yet. The scanner's version is a constant
in the code (`packages/scanner/src/scanner-surface.ts`, `SCANNER_VERSION`),
currently
0.13.0.

### What else is in the image

The table above is the npm packages. The image also holds its base: Node.js,
the C library, the certificate-authority bundle and time-zone data, from a
distroless Debian base pinned by digest in `deploy/Dockerfile`. The base
holds no shell and no package manager. The base's own packages are not listed
on this page; the release SBOM lists them (below).

### The licence gate

`scripts/check-licences.js` runs in CI on every push and pull request. It
fails when a production package states no licence, states one that is not on
the allowlist, or states a different one from the lockfile's copy. The
allowlist is exact identifiers, with no expression evaluated:

`0BSD`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `BlueOak-1.0.0`, `ISC`,
`MIT`, `PSF-2.0`, `Python-2.0`.

scanent's own packages must state `BUSL-1.1`. To print the list yourself,
after `npm ci`:

```bash
node scripts/check-licences.js
```

### Attribution

[NOTICE](../../NOTICE) carries the third-party attribution: the four
run-time packages above, and the receipt format the contract verifies
(the Apache-2.0 core format of pipelock; no pipelock code is included or
depended on). The image holds `LICENSE` and `NOTICE` under `/app`, and each
third-party package travels with its own licence file.

## How the SBOM is produced

**No SBOM has been produced by the release pipeline yet, because no release
exists.** What follows describes what `.github/workflows/release.yml` is
written to do on the first version tag. It has never run. See
[Assurance status](assurance-status.md).

At a release, for each architecture (amd64 and arm64):

1. The image is built and smoke-tested, and scanned with Trivy and Grype.
2. Syft reads the **built image** and writes a CycloneDX JSON document. It
   lists what is in the image, operating-system packages and npm packages
   alike, not what a manifest says should be there.
3. The workflow refuses an SBOM that names no component, or that does not
   list `zod`, `js-yaml` and `typescript`.
4. After the image is pushed, the SBOM is attached to it as a signed
   attestation.
5. The same document is attached to the GitHub release as
   `scanent-<version>-linux-<arch>.cdx.json`, and placed in the air-gapped
   bundle under `sbom/`.

How to fetch and check an SBOM once a release exists is in
[Verify a release](../verify-a-release.md#the-sbom).

Until then, the table on this page and `node scripts/check-licences.js` are
the bill of materials for the npm packages, and `deploy/Dockerfile` names the
base image by digest. To produce an SBOM of an image you built yourself, run
an SBOM tool of your choice against it; a bundle you build yourself holds
none unless you supply one.

## The Business Source License 1.1, in plain words

scanent is licensed under the **Business Source License 1.1** (BUSL-1.1). The
licensor is **Inflect Ltd.**

**It is not an open-source licence.** The source code is public and you may
read it, but the right to use it in production comes with a condition. Call
it "source-available".

| Question | Answer, in plain words | In the licence |
|---|---|---|
| May I read, copy and modify the code? | Yes | Terms, first paragraph |
| May I use it for testing, evaluation and development? | Yes. Non-production use is allowed | Terms, first paragraph |
| May I use it in production inside my own organisation? | Yes. Running it for your own organisation's, and your affiliates', internal compliance programme is permitted | Additional Use Grant |
| May a consultant or service provider run it for me? | Yes, when they act solely on your behalf | Additional Use Grant |
| What may I not do? | Use it to offer third parties a hosted, managed, embedded or software-as-a-service product or service that competes with a product or service of the licensor. The licence names compliance, governance, risk and audit-management products as examples | Additional Use Grant |
| What if my use does not fit? | You need a commercial licence from the licensor, or you must not use it | Terms, third paragraph |
| Does it ever become open source? | Each version converts to the Apache License 2.0 on its Change Date. For the first version that is 11 November 2030. The licence sets the date separately for each version: four years after that version was first made public, or the stated Change Date, whichever comes first | Change Date, Change License |
| Must I keep the licence with copies? | Yes. Every copy, original or modified, must display the licence | Terms |
| Does it grant trademark rights? | No | Terms |
| Is there a warranty? | No. The work is provided "as is" | The licence's disclaimer |

### Commercial terms

Anything outside the grant above (for example, offering scanent to others as
part of a competing service, or terms with a warranty or support commitment)
is a matter for a commercial licence. **Commercial terms come from the
licensor, Inflect Ltd., and from nobody else.** The contact for alternative
licensing is given in the [LICENSE](../../LICENSE) file. Nothing in this
repository's documents is an offer of commercial terms.

### For an engagement team

If you run scanent for a client, on the client's behalf and for the client's
own internal programme, the licence's grant covers that use. If you plan to
build scanent into a service you offer to many clients, read the Additional
Use Grant with your legal team and ask the licensor first.
