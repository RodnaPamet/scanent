// A real-time soak: one scanner process, left running, scanning on a short
// cadence for hours. It answers what no single run can: does memory grow, does
// a run get missed, does anything fail the hundredth time.
//
//   npm run build
//   npm run soak -- --hours 72 --every-seconds 60
//
// What it runs is the scanner's own schedule loop and delivery
// (`runOnSchedule`, `scanAndDeliver`, from the built package) over the offline
// example: the `code` source, a file output with retention, the real clock and
// the real file system. It reaches no network. A network source is not soaked
// here: every host the scanner reads is fixed by kind or refused when it is
// loopback, so there is nothing local it could be pointed at.
//
// One JSON line per run goes to stdout:
//
//   { run, startedAt, lateMs, durationMs, ok, rssBytes, heapUsedBytes, outputBytes, kept }
//
// and the process exits 1, saying why on stderr, when
//
//   - a run fails or is not delivered;
//   - a run starts more than one period late (a missed run);
//   - resident memory, after a warm-up, grows past `--rss-growth-mib` over its
//     level at the end of the warm-up;
//   - the output directory holds more runs than retention allows.
//
// Exit 0 means every run of the period was made and none of those happened.
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { setTimeout: sleepFor } = require('node:timers/promises');

const USAGE = 'usage: node scripts/soak.js [--hours <n>] [--every-seconds <n>] [--out <dir>] [--retain <n>] [--warm-up <runs>] [--rss-growth-mib <n>]';

function parseArgs(argv) {
    const opts = { hours: 1, everySeconds: 60, out: null, retain: 10, warmUp: 10, rssGrowthMib: 64 };
    const names = { '--hours': 'hours', '--every-seconds': 'everySeconds', '--retain': 'retain', '--warm-up': 'warmUp', '--rss-growth-mib': 'rssGrowthMib' };
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        if (a === '--out') {
            opts.out = argv[++i] ?? null;
            if (opts.out === null) return null;
        } else if (Object.prototype.hasOwnProperty.call(names, a)) {
            const n = Number(argv[++i]);
            if (!Number.isFinite(n) || n <= 0) return null;
            opts[names[a]] = n;
        } else {
            return null;
        }
    }
    return opts;
}

/** The bytes under a directory, and how many run directories it holds. */
function measure(dir) {
    let bytes = 0;
    const walk = (at) => {
        for (const entry of fs.readdirSync(at, { withFileTypes: true })) {
            const full = path.join(at, entry.name);
            if (entry.isDirectory()) walk(full);
            else bytes += fs.statSync(full).size;
        }
    };
    walk(dir);
    const runs = path.join(dir, 'runs');
    return { bytes, kept: fs.existsSync(runs) ? fs.readdirSync(runs).length : 0 };
}

async function main() {
    const opts = parseArgs(process.argv.slice(2));
    if (opts === null) {
        process.stderr.write(`${USAGE}\n`);
        return 2;
    }
    const compiled = path.join(__dirname, '..', 'packages', 'scanner', 'dist', 'index.js');
    if (!fs.existsSync(compiled)) {
        process.stderr.write('scanent is not built yet: run `npm run build` first.\n');
        return 2;
    }
    const { parseScannerConfig, runOnSchedule, scanAndDeliver } = require(compiled);

    const out = opts.out === null ? fs.mkdtempSync(path.join(os.tmpdir(), 'scanent-soak-')) : path.resolve(opts.out);
    fs.mkdirSync(out, { recursive: true, mode: 0o700 });
    const outputs = [{ kind: 'file', dir: out, retainRuns: opts.retain }];
    const config = parseScannerConfig({
        estate: 'soak',
        scanner: { agentId: 'agt_soak', signingKeyEnv: 'SCANNER_SIGNING_KEY' },
        outputs,
        schedule: { everyHours: 1 },
        sources: [{ kind: 'code', product: 'langchain', roots: [{ label: 'example', path: path.join(__dirname, '..', 'examples', 'code-only', 'estate') }] }],
    });
    // A key made for this soak and held in memory: nothing is signed for anybody.
    const env = { SCANNER_SIGNING_KEY: crypto.generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() };
    const quiet = { info: () => undefined, warn: () => undefined, error: () => undefined };

    const periodMs = opts.everySeconds * 1000;
    const runs = Math.max(1, Math.floor((opts.hours * 3_600_000) / periodMs));
    const problems = [];
    let run = 0;
    let due = Date.now();
    let warmRss = null;
    process.stderr.write(`soak: ${runs} runs, one every ${opts.everySeconds} s, into ${out}\n`);

    // The loop has no way to be stopped from inside a run, by design: a failed
    // scan must not end a scanner's schedule. The soak ends at its first
    // problem all the same, by refusing to sleep: what follows a problem would
    // only repeat it, for as many hours as were asked.
    const STOP = new Error('soak stopped');
    await runOnSchedule({
        everyHours: periodMs / 3_600_000,
        log: quiet,
        maxRuns: runs,
        sleep: (ms) => (problems.length > 0 ? Promise.reject(STOP) : sleepFor(ms)),
        run: async () => {
            if (problems.length > 0) return;
            const startedAt = Date.now();
            const lateMs = startedAt - due;
            due = startedAt + periodMs;
            run += 1;
            let ok = false;
            try {
                ok = (await scanAndDeliver({ config, env, log: quiet, outputs })).ok;
            } catch (err) {
                problems.push(`run ${run}: ${err instanceof Error ? err.name : 'error'}`);
            } finally {
                const durationMs = Date.now() - startedAt;
                const { rss, heapUsed } = process.memoryUsage();
                const { bytes, kept } = measure(out);
                process.stdout.write(`${JSON.stringify({ run, startedAt: new Date(startedAt).toISOString(), lateMs, durationMs, ok, rssBytes: rss, heapUsedBytes: heapUsed, outputBytes: bytes, kept })}\n`);
                if (!ok) problems.push(`run ${run}: not delivered`);
                if (run > 1 && lateMs > periodMs) problems.push(`run ${run}: started ${lateMs} ms late, more than one period: a run was missed`);
                if (kept > opts.retain) problems.push(`run ${run}: ${kept} runs kept, retention is ${opts.retain}`);
                if (run === opts.warmUp) warmRss = rss;
                if (warmRss !== null && rss - warmRss > opts.rssGrowthMib * 1024 * 1024) {
                    problems.push(`run ${run}: resident memory grew ${Math.round((rss - warmRss) / (1024 * 1024))} MiB since run ${opts.warmUp}, over the ${opts.rssGrowthMib} MiB allowed`);
                }
            }
        },
    }).catch((err) => {
        if (err !== STOP) throw err;
    });

    if (opts.out === null) fs.rmSync(out, { recursive: true, force: true });
    if (problems.length > 0 || run < runs) {
        for (const problem of problems) process.stderr.write(`soak: ${problem}\n`);
        if (run < runs) process.stderr.write(`soak: stopped after ${run} of ${runs} runs\n`);
        return 1;
    }
    process.stderr.write(`soak: ${runs} runs, none failed, none missed, memory within ${opts.rssGrowthMib} MiB of its level after warm-up\n`);
    return 0;
}

main().then(
    (code) => process.exit(code),
    (err) => {
        process.stderr.write(`soak: ${err instanceof Error ? err.name : 'error'}\n`);
        process.exit(1);
    },
);
