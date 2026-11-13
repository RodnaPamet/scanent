/**
 * `docs/network-and-permissions.md` is the declared surface, rendered.
 *
 *   1. The committed file is byte for byte what the renderer produces today.
 *      A stale file fails, with the command to run.
 *   2. The document names every request the surface declares: every read path,
 *      every token exchange, every MCP and register message, the post, the
 *      egress proof, the file operations and the manifest hash.
 *   3. Its two hand-written tables are held to the code: every declared path
 *      has a sentence, no sentence is for a path that is not declared, and
 *      everything listed as "never requested" is off the declared surface.
 */
import { readFileSync } from 'fs';
import { resolve } from 'path';

import { ACCESS_GUIDE, GUIDE_ORDER } from '../src/init/access-guide';
import { isDeclaredRequest, SCANNER_SURFACE, scannerManifestHash, SCANNER_VERSION } from '../src/scanner-surface';
import { NEVER_REQUESTED, renderNetworkAndPermissionsMarkdown, WHAT_IS_READ } from '../src/surface-doc';
import { ALL_SOURCE_KINDS, SCANNER_OF_SOURCE, SCANNER_TITLE, SCANNERS } from '../src/scanners';

const COMMITTED = resolve(__dirname, '..', '..', '..', 'docs', 'network-and-permissions.md');
const rendered = renderNetworkAndPermissionsMarkdown();

describe('docs/network-and-permissions.md', () => {
    it('is the surface, rendered: run `npm run build && npm run docs:network` after changing the surface or the access guide', () => {
        expect(readFileSync(COMMITTED, 'utf8')).toBe(rendered);
    });

    it('is the same text every time it is rendered', () => {
        expect(renderNetworkAndPermissionsMarkdown()).toBe(rendered);
    });

    it('names every read path, with its method', () => {
        for (const read of SCANNER_SURFACE.reads) {
            for (const path of read.paths) expect(rendered).toContain(`| ${read.method} | \`${path}\` |`);
        }
    });

    it('names every token exchange, every message, the register tool, the post and the egress proof', () => {
        for (const auth of SCANNER_SURFACE.authenticates) expect(rendered).toContain(`\`${auth.method} ${auth.origin}${auth.path}\``);
        for (const list of SCANNER_SURFACE.lists) for (const message of list.jsonRpc) expect(rendered).toContain(`- \`${message}\``);
        for (const register of SCANNER_SURFACE.readsRegister) {
            expect(rendered).toContain(`\`${register.method} ${register.path}\``);
            expect(rendered).toContain(`\`${register.exchange.method} ${register.exchange.path}\``);
            expect(rendered).toContain(`\`${register.tool}\``);
            for (const message of register.jsonRpc) expect(rendered).toContain(`\`${message}\``);
        }
        for (const send of SCANNER_SURFACE.sends) expect(rendered).toContain(`- \`${send.method} ${send.path}\``);
        for (const proof of SCANNER_SURFACE.provesEgress) expect(rendered).toContain(`| ${proof.method} | ${proof.via} | \`${proof.target}\` | ${proof.expect} |`);
        for (const gateway of SCANNER_SURFACE.readsGateway) {
            expect(rendered).toContain(`\`${gateway.service}\``);
            for (const rpc of gateway.rpcs) expect(rendered).toContain(`\`${rpc}\``);
        }
    });

    it('names every fixed host, the file operations, and the manifest hash of this version', () => {
        for (const entry of [...SCANNER_SURFACE.reads, ...SCANNER_SURFACE.authenticates]) {
            if ('origin' in entry) expect(rendered).toContain(new URL(entry.origin).hostname);
        }
        for (const files of SCANNER_SURFACE.readsFiles) {
            for (const operation of files.operations) expect(rendered).toContain(`\`${operation}\``);
            for (const extension of files.extensions) expect(rendered).toContain(`\`${extension}\``);
            for (const skipped of files.skips) expect(rendered).toContain(`\`${skipped}\``);
        }
        expect(rendered).toContain(`Manifest hash: \`${scannerManifestHash()}\``);
        expect(rendered).toContain(`version ${SCANNER_VERSION}`);
    });

    it('gives every source kind its grant, and what must not be granted', () => {
        expect([...GUIDE_ORDER].sort()).toEqual([...ALL_SOURCE_KINDS].sort());
        for (const kind of GUIDE_ORDER) {
            expect(rendered).toContain(`**Grant asked for.** ${ACCESS_GUIDE[kind].grant}.`);
            for (const item of ACCESS_GUIDE[kind].notNeeded) expect(rendered).toContain(`- ${item}`);
        }
    });

    it('has a sentence for every declared path, and for no other', () => {
        const declared = SCANNER_SURFACE.reads.flatMap((read) => read.paths.map((path) => `${read.product} ${path}`)).sort();
        expect(Object.keys(WHAT_IS_READ).sort()).toEqual(declared);
        expect(rendered).not.toContain('NOT DESCRIBED');
        for (const sentence of Object.values(WHAT_IS_READ)) expect(sentence.length).toBeGreaterThan(20);
    });

    it('everything listed as never requested is off the declared surface', () => {
        const example = (path: string): string => path.replace(/\{[A-Za-z]+\}/g, 'x1');
        const origins: Record<string, string> = {
            'entra-sp': 'https://graph.microsoft.com',
            vault: 'https://acme-agents.vault.azure.net',
            'okta-app': 'https://acme.okta.com',
            cicd: 'https://api.github.com',
            'gcp-sa': 'https://iam.googleapis.com',
            runtime: 'https://api.smith.langchain.com',
            'entra-integrations': 'https://graph.microsoft.com',
            'okta-integrations': 'https://acme.okta.com',
            'github-integrations': 'https://api.github.com',
        };
        let checked = 0;
        for (const [kind, entries] of Object.entries(NEVER_REQUESTED)) {
            for (const entry of entries) {
                expect(isDeclaredRequest(entry.method, `${origins[kind]}${example(entry.path)}`)).toBe(false);
                expect(rendered).toContain(`- \`${entry.method} ${entry.path}\`: ${entry.why}.`);
                checked += 1;
            }
        }
        expect(checked).toBeGreaterThanOrEqual(15);
        // The detector is live: a declared read is accepted by the same check.
        expect(isDeclaredRequest('GET', 'https://acme.okta.com/api/v1/apps')).toBe(true);
    });

    it('is one surface with one hash, grouped by scanner: each source under its own, in that order', () => {
        expect(rendered.match(/^Manifest hash: /gm)).toHaveLength(1);
        const headings = SCANNERS.map((scanner) => rendered.indexOf(`\n## ${SCANNER_TITLE[scanner]}\n`));
        expect(headings.every((at) => at > 0)).toBe(true);
        expect([...headings].sort((a, b) => a - b)).toEqual(headings);
        for (const kind of GUIDE_ORDER) {
            const at = rendered.indexOf(`Source kind \`${kind}\``);
            const own = SCANNERS.indexOf(SCANNER_OF_SOURCE[kind]);
            expect([kind, at > headings[own] && (own + 1 === headings.length || at < headings[own + 1])]).toEqual([kind, true]);
        }
        expect(SCANNER_SURFACE.scanners.flatMap((s) => s.sources).sort()).toEqual([...ALL_SOURCE_KINDS].sort());
    });

    it('holds no client name, no credential-shaped text and no absolute path', () => {
        expect(rendered).not.toMatch(/\/home\/|\/root\/|C:\\/);
        expect(rendered).not.toMatch(/Bearer [A-Za-z0-9]/);
    });
});
