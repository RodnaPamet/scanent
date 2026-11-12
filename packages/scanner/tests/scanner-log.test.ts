/**
 * The scanner's log: one JSON line per event, and nothing secret-shaped in it.
 */
import { jsonLineLog } from '../src/log';

const ghToken = ['gh', 'p_', 'Z'.repeat(36)].join('');
const bearerJwt = ['eyJ', 'a'.repeat(12), '.', 'b'.repeat(12), '.', 'c'.repeat(8)].join('');

function capture() {
    const lines: string[] = [];
    const log = jsonLineLog((l) => lines.push(l));
    const parsed = () => lines.map((l) => JSON.parse(l) as Record<string, unknown>);
    return { lines, log, parsed };
}

describe('the JSON line log', () => {
    it('writes one newline-terminated JSON object per event, with its level and a timestamp', () => {
        const { lines, log, parsed } = capture();
        log.info('source read', { source: 'code', rows: 3, complete: true, reason: null });
        log.warn('source incomplete');
        log.error('report refused', { status: 400 });

        expect(lines).toHaveLength(3);
        for (const line of lines) expect(line.endsWith('\n') && line.indexOf('\n') === line.length - 1).toBe(true);
        const [info, warn, error] = parsed();
        expect(info).toMatchObject({ level: 'info', msg: 'source read', source: 'code', rows: 3, complete: true, reason: null });
        expect(warn).toMatchObject({ level: 'warn', msg: 'source incomplete' });
        expect(Object.keys(warn).sort()).toEqual(['level', 'msg', 'ts']);
        expect(error).toMatchObject({ level: 'error', status: 400 });
        expect(new Date(info.ts as string).toISOString()).toBe(info.ts);
    });

    it('replaces a secret-shaped string field, and leaves the others as they were', () => {
        const { lines, log, parsed } = capture();
        log.error('request failed', { error: `401 for Authorization: Bearer ${ghToken}`, source: 'cicd', rows: 0 });
        expect(parsed()[0]).toMatchObject({ error: '[redacted]', source: 'cicd', rows: 0 });
        expect(lines.join('')).not.toContain(ghToken);
    });

    it('replaces a secret-shaped message too', () => {
        const { lines, log, parsed } = capture();
        log.warn(`token ${bearerJwt} was rejected`, { attempt: 2 });
        expect(parsed()[0]).toMatchObject({ level: 'warn', msg: '[redacted]', attempt: 2 });
        expect(lines.join('')).not.toContain(bearerJwt);
    });

    it('scrubs every shape the contract knows, in any field', () => {
        const shapes = [
            ghToken,
            ['AKIA', 'A'.repeat(16)].join(''),
            ['sk-', 'a'.repeat(24)].join(''),
            ['-----BEGIN ', 'PRIVATE KEY-----'].join(''),
            ['https://user:', 'hunter2', '@db.example.com/x'].join(''),
        ];
        const { lines, log, parsed } = capture();
        shapes.forEach((value, i) => log.info('event', { [`f${i}`]: value }));
        parsed().forEach((line, i) => expect(line[`f${i}`]).toBe('[redacted]'));
        for (const value of shapes) expect(lines.join('')).not.toContain(value);
    });

    it('does not mistake a number, a boolean or null for a string to scrub', () => {
        const { log, parsed } = capture();
        log.info('counts', { agents: 12, complete: false, reason: null, label: 'a plain label' });
        expect(parsed()[0]).toMatchObject({ agents: 12, complete: false, reason: null, label: 'a plain label' });
    });

    it('a field cannot overwrite the level, but the event keeps its own message and time first', () => {
        const { log, parsed } = capture();
        log.info('event', { n: 1 });
        expect(Object.keys(parsed()[0])).toEqual(['ts', 'level', 'msg', 'n']);
    });

    it('writes to stderr by default, never to stdout where a dry run prints the report', () => {
        const stderr = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
        const stdout = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
        try {
            jsonLineLog().info('to stderr', { n: 1 });
            expect(stdout).not.toHaveBeenCalled();
            expect(stderr).toHaveBeenCalledTimes(1);
            expect(JSON.parse(String(stderr.mock.calls[0][0]))).toMatchObject({ level: 'info', msg: 'to stderr', n: 1 });
        } finally {
            stderr.mockRestore();
            stdout.mockRestore();
        }
    });
});
