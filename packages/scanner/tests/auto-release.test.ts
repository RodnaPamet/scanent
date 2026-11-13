/**
 * The release is made by a change of version, not by a person with a tag.
 *
 * `.github/workflows/auto-release.yml` runs when CI completes on main, and
 * `scripts/auto-release.sh` decides whether main's head is a release: if its
 * version has no tag, has its notes, is still main's head and passed CI, the
 * script makes the annotated tag, pushes it and dispatches release.yml on it.
 *
 * The workflow is held here as text and YAML. The script is RUN, in real git
 * repositories: a bare repository as `origin`, a clone of it, and a stand-in
 * `gh` on the path that records every call and answers the CI query with
 * runs this file chooses, through the real `jq` filter the script gives it.
 */
import { execFileSync, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import * as yaml from 'js-yaml';

jest.setTimeout(60_000);

const REPO_ROOT = path.resolve(__dirname, '../../..');
const read = (rel: string): string => fs.readFileSync(path.join(REPO_ROOT, rel), 'utf8');
const SCRIPT = path.join(REPO_ROOT, 'scripts/auto-release.sh');

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

const BOT_NAME = 'github-actions[bot]';
const BOT_EMAIL = '41898282+github-actions[bot]@users.noreply.github.com';
const GH_REPO = 'example-owner/example-repo';

// ───────────────────────────── the workflow ─────────────────────────────

describe('.github/workflows/auto-release.yml', () => {
    const text = read('.github/workflows/auto-release.yml');
    const wf = yaml.load(text) as Json;
    const release = yaml.load(read('.github/workflows/release.yml')) as Json;
    const ci = yaml.load(read('.github/workflows/ci.yml')) as Json;
    const job = wf.jobs.tag as Json;
    const steps = job.steps as Json[];

    it('runs when CI completes on main, or by hand as a retry', () => {
        // js-yaml reads the bare key `on` as the boolean true.
        const on = (wf.on ?? wf.true) as Json;
        expect(Object.keys(on).sort()).toEqual(['workflow_dispatch', 'workflow_run']);
        // The workflow it follows is CI, by the name ci.yml gives itself.
        expect(ci.name).toBe('CI');
        expect(on.workflow_run).toEqual({ workflows: ['CI'], types: ['completed'], branches: ['main'] });
        expect(on.workflow_dispatch).toBeNull();
        expect(Object.keys(wf.jobs)).toEqual(['tag']);
    });

    it('acts on a CI run that a push to main started and that passed, or on a retry started on main, and on nothing else', () => {
        const condition = String(job.if).replace(/\s+/g, ' ').trim();
        expect(condition).toBe(
            "(github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main') || " +
                "(github.event_name == 'workflow_run' && github.event.workflow_run.conclusion == 'success' && " +
                "github.event.workflow_run.event == 'push' && github.event.workflow_run.head_branch == 'main')",
        );
    });

    it('may read the repository, and its one job may push a tag and dispatch a workflow, and nothing else', () => {
        expect(wf.permissions).toEqual({ contents: 'read' });
        expect(job.permissions).toEqual({ contents: 'write', actions: 'write' });
        expect(text).not.toMatch(/id-token|packages:|attestations:|\$\{\{\s*secrets\./);
        expect(job['runs-on']).toBe('ubuntu-24.04');
        expect(job['timeout-minutes']).toBeGreaterThan(0);
        expect(job['timeout-minutes']).toBeLessThanOrEqual(15);
        // Two runs never race: one group, and a run in it is never cancelled half-way through a tag.
        expect(wf.concurrency).toEqual({ group: 'auto-release', 'cancel-in-progress': false });
    });

    it('checks out the commit CI passed, by the SHA release.yml pins, with the whole history, and runs the script and nothing else', () => {
        expect(steps).toHaveLength(2);
        const checkout = steps[0];
        expect(String(checkout.uses)).toMatch(/^actions\/checkout@[0-9a-f]{40}$/);
        const pinned = (release.jobs.gates.steps as Json[])[0].uses;
        expect(checkout.uses).toBe(pinned);
        expect(checkout.with).toEqual({ ref: '${{ github.event.workflow_run.head_sha || github.sha }}', 'fetch-depth': 0, 'persist-credentials': true });
        const decide = steps[1];
        expect(decide.run).toBe('bash scripts/auto-release.sh');
        // The commit it decides on is the one it checked out; the token reaches `gh` through the environment.
        expect(decide.env).toEqual({ RELEASE_SHA: checkout.with.ref, GH_REPO: '${{ github.repository }}', GH_TOKEN: '${{ github.token }}' });
        // Nothing is installed and no action but the checkout runs while the credential is in the checkout.
        expect(text).not.toMatch(/npm (ci|install|run)|setup-node/);
    });

    it('reads the version with the sed release.yml\'s Version step uses', () => {
        const versionStep = (release.jobs.build.steps as Json[]).find((s) => s.name === 'Version') as Json;
        const sed = /sed -n "s\/\^export const SCANNER_VERSION[^"]*"/.exec(String(versionStep.run));
        expect(sed).not.toBeNull();
        expect(read('scripts/auto-release.sh')).toContain(`sed -n ${(sed as RegExpExecArray)[0].slice('sed -n '.length)}`);
    });
});

// ───────────────────────────── the script, run ─────────────────────────────

const SURFACE = (version: string): string => `// The declared surface.\nexport const SCANNER_VERSION = '${version}';\n`;

interface World {
    dir: string;
    origin: string;
    work: string;
    ghLog: string;
    ciRuns: string;
    releaseRuns: string;
    env: NodeJS.ProcessEnv;
    git: (cwd: string, ...args: string[]) => string;
    commit: (files: Record<string, string | null>, message: string) => string;
    setCi: (runs: Array<{ head_sha: string; event: string; head_branch: string; conclusion: string | null }>) => void;
    setReleaseRuns: (runs: Array<{ head_branch: string; status: string; conclusion: string | null }>) => void;
    ghCalls: () => string[][];
    run: (sha: string, extra?: NodeJS.ProcessEnv) => { status: number | null; stdout: string; stderr: string };
    tagsOnOrigin: () => string[];
}

/**
 * A bare repository as `origin`, a clone of it on main, and a `gh` stand-in on the path. Git reads no
 * configuration of the machine's: a signing or hook setting there must not decide what this test sees.
 */
function makeWorld(): World {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scanent-auto-release-'));
    const origin = path.join(dir, 'origin.git');
    const work = path.join(dir, 'work');
    const bin = path.join(dir, 'bin');
    const home = path.join(dir, 'home');
    const ghLog = path.join(dir, 'gh.log');
    const ciRuns = path.join(dir, 'ci-runs.json');
    const releaseRuns = path.join(dir, 'release-runs.json');
    fs.mkdirSync(bin);
    fs.mkdirSync(home);
    fs.writeFileSync(ghLog, '');
    fs.writeFileSync(ciRuns, JSON.stringify({ total_count: 0, workflow_runs: [] }));
    fs.writeFileSync(releaseRuns, JSON.stringify({ total_count: 0, workflow_runs: [] }));
    // Each call is one line: its arguments, each ended by a unit separator. `api` answers with the runs of the workflow
    // its path names (ci.yml or release.yml), through the caller's own `--jq` filter and the real jq.
    fs.writeFileSync(
        path.join(bin, 'gh'),
        [
            '#!/usr/bin/env bash',
            'set -euo pipefail',
            '{ printf \'%s\\037\' "$@"; printf \'\\n\'; } >> "$FAKE_GH_LOG"',
            'if [ "$1" = workflow ] && [ -n "${FAKE_GH_DISPATCH_FAILS:-}" ]; then echo "gh: HTTP 500" >&2; exit 1; fi',
            'if [ "$1" = api ]; then',
            '    [ -z "${FAKE_GH_API_FAILS:-}" ] || { echo "gh: HTTP 502" >&2; exit 1; }',
            '    filter=""',
            '    runs=""',
            '    while [ "$#" -gt 0 ]; do',
            '        case "$1" in',
            '            --jq) filter="$2"; shift ;;',
            '            */actions/workflows/ci.yml/runs*) runs="$FAKE_CI_RUNS" ;;',
            '            */actions/workflows/release.yml/runs*) runs="$FAKE_RELEASE_RUNS" ;;',
            '        esac',
            '        shift',
            '    done',
            '    [ -n "$runs" ] || { echo "gh: HTTP 404" >&2; exit 1; }',
            '    jq -r "$filter" "$runs"',
            'fi',
            '',
        ].join('\n'),
        { mode: 0o755 },
    );
    const env: NodeJS.ProcessEnv = {
        PATH: `${bin}${path.delimiter}${process.env.PATH ?? ''}`,
        HOME: home,
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_CONFIG_GLOBAL: '/dev/null',
        GIT_TERMINAL_PROMPT: '0',
        FAKE_GH_LOG: ghLog,
        FAKE_CI_RUNS: ciRuns,
        FAKE_RELEASE_RUNS: releaseRuns,
    };
    const git = (cwd: string, ...args: string[]): string =>
        execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false', ...args], { cwd, encoding: 'utf8', env, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
    git(dir, 'init', '-q', '--bare', '-b', 'main', origin);
    git(dir, 'clone', '-q', origin, work);
    git(work, 'checkout', '-q', '-B', 'main');
    const commit = (files: Record<string, string | null>, message: string): string => {
        for (const [rel, content] of Object.entries(files)) {
            const at = path.join(work, rel);
            if (content === null) {
                fs.rmSync(at, { force: true });
            } else {
                fs.mkdirSync(path.dirname(at), { recursive: true });
                fs.writeFileSync(at, content);
            }
        }
        git(work, 'add', '-A');
        git(work, 'commit', '-q', '--allow-empty', '-m', message);
        git(work, 'push', '-q', 'origin', 'HEAD:refs/heads/main');
        return git(work, 'rev-parse', 'HEAD');
    };
    return {
        dir,
        origin,
        work,
        ghLog,
        ciRuns,
        releaseRuns,
        env,
        git,
        commit,
        setCi: (runs) => fs.writeFileSync(ciRuns, JSON.stringify({ total_count: runs.length, workflow_runs: runs })),
        setReleaseRuns: (runs) => fs.writeFileSync(releaseRuns, JSON.stringify({ total_count: runs.length, workflow_runs: runs })),
        ghCalls: () =>
            fs
                .readFileSync(ghLog, 'utf8')
                .split('\n')
                .filter((line) => line !== '')
                .map((line) => line.split('\x1f').slice(0, -1)),
        run: (sha, extra = {}) => {
            const r = spawnSync('bash', [SCRIPT], { cwd: work, encoding: 'utf8', env: { ...env, RELEASE_SHA: sha, GH_REPO, GH_TOKEN: 'not-a-token', ...extra } });
            return { status: r.status, stdout: r.stdout, stderr: r.stderr };
        },
        tagsOnOrigin: () => git(origin, 'tag', '--list').split('\n').filter((t) => t !== ''),
    };
}

const passed = (sha: string) => ({ head_sha: sha, event: 'push', head_branch: 'main', conclusion: 'success' });

describe('scripts/auto-release.sh, run against a real repository', () => {
    let world: World;
    beforeEach(() => {
        world = makeWorld();
    });
    afterEach(() => {
        fs.rmSync(world.dir, { recursive: true, force: true });
    });

    /** Nothing was tagged anywhere, and release.yml was not dispatched. */
    const nothingDone = (): void => {
        expect(world.tagsOnOrigin()).toEqual([]);
        expect(world.git(world.work, 'tag', '--list')).toBe('');
        expect(world.ghCalls().filter((call) => call[0] === 'workflow')).toEqual([]);
    };

    it('tags main\'s head with an annotated tag as GitHub Actions, pushes it, dispatches release.yml on it, and stops the next time', () => {
        world.commit({ 'README.md': 'one\n' }, 'one');
        const sha = world.commit({ 'packages/scanner/src/scanner-surface.ts': SURFACE('9.9.9'), 'docs/releases/9.9.9.md': '# scanent 9.9.9\n' }, 'version 9.9.9');
        world.setCi([passed(sha)]);

        const first = world.run(sha);
        // git's own account of the push goes to stderr; no fault does.
        expect(first.stderr).not.toContain('auto-release:');
        expect(first.stderr).toContain('[new tag]');
        expect(first.status).toBe(0);
        expect(first.stdout).toContain('dispatched release.yml on v9.9.9');

        // On origin: one tag, annotated, on that commit, made by the bot, with the message the checklist gives.
        expect(world.tagsOnOrigin()).toEqual(['v9.9.9']);
        expect(world.git(world.origin, 'cat-file', '-t', 'refs/tags/v9.9.9')).toBe('tag');
        expect(world.git(world.origin, 'rev-parse', 'v9.9.9^{commit}')).toBe(sha);
        const tagObject = world.git(world.origin, 'cat-file', 'tag', 'refs/tags/v9.9.9');
        expect(tagObject).toMatch(new RegExp(`^tagger ${BOT_NAME.replace(/[[\]]/g, '\\$&')} <${BOT_EMAIL.replace(/[[\].+]/g, '\\$&')}> `, 'm'));
        expect(tagObject).toMatch(/\n\nscanent 9\.9\.9\n?$/);
        expect(tagObject).not.toContain('BEGIN PGP SIGNATURE');

        // Two calls: CI's runs of this commit, then the dispatch on the tag's ref.
        const calls = world.ghCalls();
        expect(calls).toHaveLength(2);
        expect(calls[0].slice(0, 2)).toEqual(['api', `repos/${GH_REPO}/actions/workflows/ci.yml/runs?head_sha=${sha}&event=push&branch=main&status=success&per_page=100`]);
        expect(calls[1]).toEqual(['workflow', 'run', 'release.yml', '--ref', 'v9.9.9', '--repo', GH_REPO]);

        // The release started: the next CI run on the same commit finds the tag at this commit and the Release run on
        // it, and stops without a tag or a dispatch.
        world.setReleaseRuns([{ head_branch: 'v9.9.9', status: 'in_progress', conclusion: null }]);
        const tagBefore = world.git(world.origin, 'rev-parse', 'refs/tags/v9.9.9');
        const second = world.run(sha);
        expect(second.status).toBe(0);
        expect(second.stdout).toBe(`nothing to release: the tag v9.9.9 already exists on origin at ${sha}, and release.yml has a run on it\n`);
        expect(world.ghCalls().filter((call) => call[0] === 'workflow')).toHaveLength(1);
        expect(world.git(world.origin, 'rev-parse', 'refs/tags/v9.9.9')).toBe(tagBefore);
        expect(world.tagsOnOrigin()).toEqual(['v9.9.9']);
    });

    it('stops when the tag exists on origin at another commit, made by anybody, and leaves it where it is', () => {
        const first = world.commit({ 'packages/scanner/src/scanner-surface.ts': SURFACE('9.9.9'), 'docs/releases/9.9.9.md': '# scanent 9.9.9\n' }, 'version');
        world.git(world.origin, 'tag', 'v9.9.9', first);
        const sha = world.commit({ 'README.md': 'later\n' }, 'a later commit of the same version');
        world.setCi([passed(sha)]);
        const r = world.run(sha);
        expect(r.status).toBe(0);
        expect(r.stdout).toBe(`nothing to release: the tag v9.9.9 already exists on origin, at ${first}\n`);
        expect(world.git(world.origin, 'rev-parse', 'v9.9.9')).toBe(first);
        expect(world.ghCalls()).toEqual([]);
        // An annotated tag is read through to its commit: still the other commit, still a stop.
        world.git(world.origin, 'tag', '-d', 'v9.9.9');
        world.git(world.origin, 'tag', '-a', 'v9.9.9', '-m', 'scanent 9.9.9', first);
        expect(world.run(sha).stdout).toBe(`nothing to release: the tag v9.9.9 already exists on origin, at ${first}\n`);
        expect(world.ghCalls()).toEqual([]);
    });

    it('recovers a tag that was pushed and never released: with the tag at this commit and no Release run on it, it dispatches, and makes no tag', () => {
        const sha = world.commit({ 'packages/scanner/src/scanner-surface.ts': SURFACE('9.9.9'), 'docs/releases/9.9.9.md': '# scanent 9.9.9\n' }, 'version');
        world.setCi([passed(sha)]);
        // The first run pushes the tag, and the dispatch fails: a fault, and no Release run exists.
        const stuck = world.run(sha, { FAKE_GH_DISPATCH_FAILS: '1' });
        expect(stuck.status).not.toBe(0);
        expect(world.tagsOnOrigin()).toEqual(['v9.9.9']);
        const tagObject = world.git(world.origin, 'rev-parse', 'refs/tags/v9.9.9');
        // Release runs on other refs are not runs on this tag.
        world.setReleaseRuns([
            { head_branch: 'main', status: 'completed', conclusion: 'success' },
            { head_branch: 'v9.9.8', status: 'completed', conclusion: 'success' },
            { head_branch: 'v9.9.9-rc', status: 'completed', conclusion: 'success' },
        ]);
        const before = world.ghCalls().length;

        const retry = world.run(sha);
        expect(retry.stderr).toBe('');
        expect(retry.status).toBe(0);
        expect(retry.stdout).toBe(`dispatched release.yml on v9.9.9: the tag exists on origin at ${sha}, and release.yml had no run on it\n`);
        const calls = world.ghCalls().slice(before);
        // CI is still asked first, then the Release runs (every page), then the dispatch on the tag's ref.
        expect(calls.map((call) => call.slice(0, 3))).toEqual([
            ['api', `repos/${GH_REPO}/actions/workflows/ci.yml/runs?head_sha=${sha}&event=push&branch=main&status=success&per_page=100`, '--jq'],
            ['api', '--paginate', `repos/${GH_REPO}/actions/workflows/release.yml/runs?per_page=100`],
            ['workflow', 'run', 'release.yml'],
        ]);
        expect(calls[2]).toEqual(['workflow', 'run', 'release.yml', '--ref', 'v9.9.9', '--repo', GH_REPO]);
        // No tag was made or moved.
        expect(world.tagsOnOrigin()).toEqual(['v9.9.9']);
        expect(world.git(world.origin, 'rev-parse', 'refs/tags/v9.9.9')).toBe(tagObject);

        // The same holds for a lightweight tag on this commit, pushed by anybody.
        world.git(world.origin, 'tag', '-d', 'v9.9.9');
        world.git(world.origin, 'tag', 'v9.9.9', sha);
        world.setReleaseRuns([]);
        expect(world.run(sha).stdout).toBe(`dispatched release.yml on v9.9.9: the tag exists on origin at ${sha}, and release.yml had no run on it\n`);
        expect(world.git(world.origin, 'rev-parse', 'refs/tags/v9.9.9')).toBe(sha);
    });

    it('with the tag at this commit, does not dispatch when a Release run on it exists, whatever its status', () => {
        const sha = world.commit({ 'packages/scanner/src/scanner-surface.ts': SURFACE('9.9.9'), 'docs/releases/9.9.9.md': '# scanent 9.9.9\n' }, 'version');
        world.git(world.origin, 'tag', '-a', 'v9.9.9', '-m', 'scanent 9.9.9', sha);
        world.setCi([passed(sha)]);
        for (const [status, conclusion] of [['queued', null], ['in_progress', null], ['completed', 'failure'], ['completed', 'cancelled'], ['completed', 'success']] as const) {
            world.setReleaseRuns([{ head_branch: 'main', status: 'completed', conclusion: 'success' }, { head_branch: 'v9.9.9', status, conclusion }]);
            const r = world.run(sha);
            expect([status, conclusion, r.status, r.stdout]).toEqual([status, conclusion, 0, `nothing to release: the tag v9.9.9 already exists on origin at ${sha}, and release.yml has a run on it\n`]);
        }
        expect(world.ghCalls().filter((call) => call[0] === 'workflow')).toEqual([]);
        expect(world.tagsOnOrigin()).toEqual(['v9.9.9']);
    });

    it('with the tag at this commit, still holds the dispatch to the notes, main\'s head and a green CI, and fails when the Release runs cannot be read', () => {
        const sha = world.commit({ 'packages/scanner/src/scanner-surface.ts': SURFACE('9.9.9'), 'docs/releases/9.9.9.md': '# scanent 9.9.9\n' }, 'version');
        world.git(world.origin, 'tag', '-a', 'v9.9.9', '-m', 'scanent 9.9.9', sha);
        const dispatched = (): string[][] => world.ghCalls().filter((call) => call[0] === 'workflow');
        // No green CI.
        world.setCi([{ ...passed(sha), conclusion: 'failure' }]);
        expect(world.run(sha).stdout).toBe(`nothing to release: no CI run on ${sha}, pushed to main, concluded success\n`);
        // The Release runs cannot be read: a fault, never a dispatch.
        world.setCi([passed(sha)]);
        fs.rmSync(world.releaseRuns);
        const blind = world.run(sha);
        expect(blind.status).toBe(1);
        expect(blind.stderr).toContain('auto-release: the Release runs of v9.9.9 could not be read\n');
        // No longer main's head.
        world.setReleaseRuns([]);
        const later = world.commit({ 'README.md': 'later\n' }, 'later');
        world.setCi([passed(sha), passed(later)]);
        expect(world.run(sha).stdout).toBe(`nothing to release: ${sha} is no longer the head of main (${later} is)\n`);
        expect(dispatched()).toEqual([]);
    });

    it('stops when the version has no release notes at the commit, or empty ones', () => {
        const none = world.commit({ 'packages/scanner/src/scanner-surface.ts': SURFACE('9.9.9'), 'docs/releases/9.9.8.md': '# another version\n' }, 'no notes');
        world.setCi([passed(none)]);
        const missing = world.run(none);
        expect(missing.status).toBe(0);
        expect(missing.stdout).toBe(`nothing to release: docs/releases/9.9.9.md is missing or empty at ${none}\n`);
        nothingDone();

        const empty = world.commit({ 'docs/releases/9.9.9.md': '' }, 'empty notes');
        world.setCi([passed(empty)]);
        const emptyRun = world.run(empty);
        expect(emptyRun.status).toBe(0);
        expect(emptyRun.stdout).toBe(`nothing to release: docs/releases/9.9.9.md is missing or empty at ${empty}\n`);
        nothingDone();

        // A directory of that name is not a page.
        const dir = world.commit({ 'docs/releases/9.9.9.md': null, 'docs/releases/9.9.9.md/x': 'x\n' }, 'a directory');
        world.setCi([passed(dir)]);
        expect(world.run(dir).stdout).toBe(`nothing to release: docs/releases/9.9.9.md is missing or empty at ${dir}\n`);
        nothingDone();
    });

    it('stops when the commit is no longer the head of main', () => {
        const sha = world.commit({ 'packages/scanner/src/scanner-surface.ts': SURFACE('9.9.9'), 'docs/releases/9.9.9.md': '# scanent 9.9.9\n' }, 'version');
        const later = world.commit({ 'README.md': 'later\n' }, 'later');
        world.setCi([passed(sha), passed(later)]);
        const r = world.run(sha);
        expect(r.status).toBe(0);
        expect(r.stdout).toBe(`nothing to release: ${sha} is no longer the head of main (${later} is)\n`);
        nothingDone();
    });

    it('stops unless a CI run on that exact commit, pushed to main, concluded success', () => {
        world.commit({ 'README.md': 'one\n' }, 'one');
        const other = world.git(world.work, 'rev-parse', 'HEAD');
        const sha = world.commit({ 'packages/scanner/src/scanner-surface.ts': SURFACE('9.9.9'), 'docs/releases/9.9.9.md': '# scanent 9.9.9\n' }, 'version');
        const refused = [
            [],
            [{ ...passed(sha), conclusion: 'failure' }],
            [{ ...passed(sha), conclusion: null }],
            [passed(other)],
            [{ ...passed(sha), event: 'pull_request' }],
            [{ ...passed(sha), head_branch: 'side' }],
            // A SHA that holds this one's is not this one, nor is a run that says more than it passed.
            [{ ...passed(sha), head_sha: `${sha}0` }],
            [{ ...passed(sha), head_sha: `0${sha}` }],
            [{ ...passed(sha), conclusion: 'success-ish' }],
        ];
        for (const runs of refused) {
            world.setCi(runs);
            const r = world.run(sha);
            expect([JSON.stringify(runs), r.status, r.stdout]).toEqual([JSON.stringify(runs), 0, `nothing to release: no CI run on ${sha}, pushed to main, concluded success\n`]);
            nothingDone();
        }
        // The question was asked of the API every time.
        expect(world.ghCalls().filter((call) => call[0] === 'api')).toHaveLength(refused.length);
        // Among other runs, the one that passed is found.
        world.setCi([{ ...passed(sha), conclusion: 'failure' }, passed(other), passed(sha)]);
        expect(world.run(sha).status).toBe(0);
        expect(world.tagsOnOrigin()).toEqual(['v9.9.9']);
    });

    it('fails, and tags nothing, when it cannot find out: no version, an API that does not answer, a remote that does not', () => {
        const noVersion = world.commit({ 'packages/scanner/src/scanner-surface.ts': "export const SCANNER_VERSION = '9.9';\n", 'docs/releases/9.9.md': '# x\n' }, 'no version');
        world.setCi([passed(noVersion)]);
        const r1 = world.run(noVersion);
        expect(r1.status).toBe(1);
        expect(r1.stderr).toBe(`auto-release: SCANNER_VERSION was not found in scanner-surface.ts at ${noVersion}\n`);
        nothingDone();

        const sha = world.commit({ 'packages/scanner/src/scanner-surface.ts': SURFACE('9.9.9'), 'docs/releases/9.9.9.md': '# scanent 9.9.9\n' }, 'version');
        world.setCi([passed(sha)]);
        const r2 = world.run(sha, { FAKE_GH_API_FAILS: '1' });
        expect(r2.status).toBe(1);
        expect(r2.stderr).toContain(`auto-release: the CI runs of ${sha} could not be read\n`);
        nothingDone();

        const r3 = world.run(sha, { REMOTE: 'nowhere' });
        expect(r3.status).toBe(1);
        expect(r3.stderr).toContain('auto-release: the tags of nowhere could not be read\n');
        nothingDone();

        const r4 = world.run('0'.repeat(40));
        expect(r4.status).toBe(1);
        expect(r4.stderr).toBe(`auto-release: ${'0'.repeat(40)} is not a commit of this checkout\n`);
        nothingDone();
    });
});
