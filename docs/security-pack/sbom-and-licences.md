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
| `@noble/ciphers` | 1.3.0 | MIT | Part of `pdfkit`'s tree (`report.pdf`): ciphers for PDF encryption, which scanent does not use |
| `@noble/hashes` | 1.8.0 | MIT | Part of `pdfkit`'s tree (`report.pdf`): the hash of the document's identifier |
| `@swc/helpers` | 0.5.24 | Apache-2.0 | Part of `pdfkit`'s tree (`report.pdf`): compiled-code helpers of `fontkit` |
| `base64-js` | 1.5.1 | MIT | Part of `pdfkit`'s tree (`report.pdf`): a dependency of `brotli` |
| `brotli` | 1.3.3 | MIT | Part of `pdfkit`'s tree (`report.pdf`): a dependency of `fontkit` |
| `clone` | 2.1.2 | MIT | Part of `pdfkit`'s tree (`report.pdf`): a dependency of `fontkit` |
| `dfa` | 1.2.0 | MIT | Part of `pdfkit`'s tree (`report.pdf`): a dependency of `fontkit` |
| `fast-deep-equal` | 3.1.3 | MIT | Part of `pdfkit`'s tree (`report.pdf`): a dependency of `fontkit` |
| `fflate` | 0.8.3 | MIT | Part of `pdfkit`'s tree (`report.pdf`): compresses the PDF's streams |
| `fontkit` | 2.0.4 | MIT | Part of `pdfkit`'s tree (`report.pdf`): font handling; scanent uses only the standard fonts, which embed nothing |
| `linebreak` | 1.1.0 | MIT | Part of `pdfkit`'s tree (`report.pdf`): where a line of text may break |
| `base64-js` | 0.0.8 | MIT | Part of `pdfkit`'s tree (`report.pdf`): a dependency of `linebreak` |
| `pako` | 0.2.9 | MIT | Part of `pdfkit`'s tree (`report.pdf`): a dependency of `unicode-trie` |
| `pdfkit` | 0.20.2 | MIT | Writes `report.pdf`, in the scanner's own process. See "The PDF library" below |
| `png-js` | 2.0.0 | MIT | Part of `pdfkit`'s tree (`report.pdf`). Its manifest states no licence; its LICENSE file is the MIT License, which the licence gate reads (below) |
| `restructure` | 3.0.2 | MIT | Part of `pdfkit`'s tree (`report.pdf`): a dependency of `fontkit` |
| `tiny-inflate` | 1.0.3 | MIT | Part of `pdfkit`'s tree (`report.pdf`): a dependency of `fontkit` |
| `typescript` | 5.9.3 | Apache-2.0 | Its parser reads JavaScript and TypeScript source as text, for the `code` source. Nothing is compiled or run at run time |
| `unicode-properties` | 1.4.1 | MIT | Part of `pdfkit`'s tree (`report.pdf`): a dependency of `fontkit` |
| `unicode-trie` | 2.0.0 | MIT | Part of `pdfkit`'s tree (`report.pdf`): a dependency of `fontkit` and `linebreak` |
| `zod` | 4.6.7 | MIT | Strict schemas for the report, the configuration and every other input |
| `@rodnapamet/scanent-contract` | 0.16.0 | BUSL-1.1 | scanent's own package: the report contract |
| `@scanent/report` | 0.0.0 | BUSL-1.1 | scanent's own package: local results |
| `@scanent/scanner` | 0.0.0 | BUSL-1.1 | scanent's own package: the scanner and its command line |
| `argparse` | 3.0.4 | PSF-2.0 | A dependency of `js-yaml` |
| `js-yaml` | 5.5.0 | MIT | Reads GitHub Actions workflow files, which are YAML |
<!-- /deps:production -->

Twenty-three third-party packages: the four the scanner has always carried,
and `pdfkit` with the eighteen it brings, which write `report.pdf`. Each is
pinned to an exact version with an integrity hash in the lockfile.
Development dependencies (the test runner, the linter, type definitions) are
not in the image and are not listed here.

### The PDF library

`report.pdf` is written in the scanner's own process by **pdfkit** 0.20.2: a
JavaScript library, with no native module, no headless browser and nothing it
fetches, so it runs in the distroless image as it runs in a test. It was
chosen over the other pure-JavaScript PDF writers on four counts:

| | pdfkit 0.20.2 | pdf-lib 1.17.1 | jsPDF 4.2.1 |
|---|---|---|---|
| Licence of the library | MIT | MIT | MIT |
| Licences of what it brings | MIT and Apache-2.0; one manifest states none (`png-js`, MIT by its file) | `pako`: the expression `(MIT AND Zlib)`, which the gate does not evaluate | `pako` as for pdf-lib, and four optional packages npm installs by default (`canvg`, `core-js`, `dompurify`, `html2canvas`) |
| Packages installed | 19 | 5 | 23, with its optional ones |
| Size on disk (npm install, 2026-11-13) | 26 MB | 26 MB | 59 MB |
| Maintained | Released September 2026 | Last release May 2022 | Released March 2026 |

pdf-lib is the smallest tree, and it is unmaintained: a defect found in it
would stay in an image that runs in a client's estate. jsPDF installs browser
rendering packages scanent has no use for. pdfkit is maintained, its tree is
all permissive, and its output is the same bytes for the same input once its
dates are set, which the tests rely on: the document's creation and
modification dates are the scan's own time, and its identifier is pdfkit's
hash of those fields.

No font is embedded. The PDF uses the standard Helvetica and Courier, which
every PDF viewer supplies, so its text is real text a reader selects and
searches, and no font licence applies. Those fonts cover Latin-1 and the
Windows-1252 punctuation; any other character is written as a visible
`\u{…}` escape, and `summary.html` and the CSV files hold it as it was.

`@scanent/report` and `@scanent/scanner` show version `0.0.0` because they
are never published. `@rodnapamet/scanent-contract` is the one package a
release publishes, to GitHub Packages, and it carries the scanner's version;
no version of it has been published yet. The scanner's version is a constant
in the code (`packages/scanner/src/scanner-surface.ts`, `SCANNER_VERSION`),
currently
0.16.0.

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

scanent's own packages must state `BUSL-1.1`.

One package's manifest states no licence: `png-js` 2.0.0, which pdfkit
uses. Its LICENSE file is the MIT License. The gate does not assume it: an
entry in `LICENCE_READ_FROM_FILE` names that exact version, the file, and the
words it must hold, and the gate reads the installed package's file and
accepts MIT only when the words are there. Another version of `png-js` is not
covered, and fails the gate until somebody reads its file again.

To print the list yourself, after `npm ci`:

```bash
node scripts/check-licences.js
```

### Attribution

[NOTICE](../../NOTICE) carries the third-party attribution: the
run-time packages above, and the receipt format the contract verifies
(the Apache-2.0 core format of pipelock; no pipelock code is included or
depended on). The image holds `LICENSE` and `NOTICE` under `/app`, and each
third-party package travels with its own licence file.

## How the SBOM is produced

**The release pipeline first produced SBOMs for 0.13.2** (2026-11-13): one
per image, attached to the release and attested to each image, and checked
with `cosign verify-attestation` from outside GitHub (1,307 and 1,306
components). What follows describes what `.github/workflows/release.yml` does
for a version tag. See
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
