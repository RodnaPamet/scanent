/**
 * THE AGENT SKILLS UNDER A CODE ROOT, AS THE AGENT-SURFACE RULES READ THEM.
 *
 * A skill is a directory holding a `SKILL.md`: front matter (its name, its
 * description, the tools it is allowed) and instructions the model follows,
 * and beside them the scripts the model may run. The rules
 * (`runAgentRules`) read both, here, where the text is held; only a finding —
 * a code, the rule that fired, the subject and a locator — leaves.
 *
 *   skill       one per `SKILL.md`: the rules read its front matter
 *               (`frontMatter`) and the body after it (`instructions`)
 *   skill-file  one per script in the skill's directory, at any depth below it
 *               and above the next `SKILL.md`: the rules read its `content`.
 *               A script is a file whose extension is in `SKILL_SCRIPT_EXTENSIONS`
 *
 * The walk is the code source's (`files.ts`): sorted, depth-first, read-only
 * (`lstat`, `readdir`, `readFile`), never following a symbolic link, not
 * entering a dependency or build directory, within the scan's deadline. Each
 * root is an ORIGIN, `code:<root label>`: a consumer closes a finding only
 * against a root read in full. A root is read in part when anything under it
 * could not be read — a directory, a `SKILL.md`, a script — because a skill
 * may be anywhere below it:
 *
 *   • a file over `MAX_FILE_BYTES`, or past the file-count or total-size
 *     limit, or a directory past the depth limit → BYTE_CAP;
 *   • the deadline → TIME_BOX, for this root and every root after it;
 *   • a missing or unreadable root or entry → UNREACHABLE (AUTH_FAILED when
 *     the operating system refused); a symbolic link → UNREACHABLE;
 *   • a UTF-16 or UTF-32 file → UNPARSEABLE.
 *
 * What was read is real: findings from a root read in part are kept.
 */
import { createHash } from 'crypto';

import { runAgentRules } from '@rodnapamet/scanent-contract/agent-rules';
import { looksLikeSecret } from '@rodnapamet/scanent-contract/harness-contract-rules';

import type { IncompleteReason, RuleFinding, RuleOrigin } from '../../source';
import {
    joinPath,
    MAX_DIR_DEPTH,
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_TOTAL_BYTES,
    reasonOf,
    SKIPPED_DIRECTORIES,
    startsWithWideByteOrderMark,
    type CodeFs,
    type CodeRoot,
} from './files';

/** The file that makes a directory a skill. Exactly this name, as the format spells it. */
export const SKILL_FILE_NAME = 'SKILL.md';

/** The extensions of a script bundled with a skill: what a model may be told to run. */
export const SKILL_SCRIPT_EXTENSIONS: readonly string[] = [
    '.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd',
    '.py', '.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.rb', '.pl', '.php',
];

/** Room for `skill-file:` and `#instructions` around a ref, inside the contract's 480. */
const MAX_RULE_REF_CHARS = 400;

/** The order a root's problems are reported in: the first present is the root's reason. */
const REASON_ORDER: readonly IncompleteReason[] = ['AUTH_FAILED', 'UNREACHABLE', 'TIME_BOX', 'BYTE_CAP', 'UNPARSEABLE'];

const sha256 = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

/** A ref as a report may carry it: as written, or a digest when long, spaced or shaped like a secret. */
function reportable(full: string, digestOf: string, suffix: string): string {
    if (full.length <= MAX_RULE_REF_CHARS && !/\s/.test(full) && !looksLikeSecret(full)) return full;
    return `code:sha256-${sha256(digestOf).slice(0, 32)}${suffix}`;
}

/** A code root as an origin: `code:<root label>`, the same in every scan. The path is never in it. */
export function codeOriginRef(label: string): string {
    return reportable(`code:${label}`, label, '');
}

/** A skill, or a file bundled with one, as a subject: `code:<root label>/<path>`. */
export function skillSubjectRef(label: string, path: string): string {
    return reportable(`code:${label}/${path}`, `${label}\u0000${path}`, path.endsWith(SKILL_FILE_NAME) ? ':skill' : ':file');
}

/**
 * Split a `SKILL.md` into its front matter and its instructions. Front matter
 * is the block between a first line of `---` and the next line of `---`; a
 * file with none is all instructions. Nothing is parsed: the rules read text.
 */
export function splitSkillMarkdown(text: string): { frontMatter: string; instructions: string } {
    const normalised = text.startsWith('﻿') ? text.slice(1) : text;
    const m = /^---[ \t]*\r?\n([\s\S]*?)\r?\n---[ \t]*(\r?\n|$)/.exec(normalised);
    if (m === null) return { frontMatter: '', instructions: normalised };
    return { frontMatter: m[1], instructions: normalised.slice(m[0].length) };
}

export interface SkillRuleRead {
    readonly findings: readonly RuleFinding[];
    readonly origins: readonly RuleOrigin[];
    readonly skills: number;
    readonly files: number;
}

function isScript(name: string): boolean {
    const lower = name.toLowerCase();
    return SKILL_SCRIPT_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

/**
 * Read every skill under the roots and run the rules over it. One origin per
 * root, in the roots' order; a root not reached before the deadline is an
 * origin read in part, never left out.
 */
export async function readSkills(
    roots: readonly CodeRoot[],
    fs: CodeFs,
    opts: { readonly deadline: number; readonly now: () => number },
): Promise<SkillRuleRead> {
    const findings: RuleFinding[] = [];
    const origins: RuleOrigin[] = [];
    let skills = 0;
    let files = 0;
    let filesRead = 0;
    let bytes = 0;
    // An object, so the closures' writes are seen where it is read.
    const state: { stopped: IncompleteReason | null } = { stopped: null };

    for (const root of roots) {
        const originRef = codeOriginRef(root.label);
        const problems = new Set<IncompleteReason>();
        let subjects = 0;
        const problem = (reason: IncompleteReason) => problems.add(reason);
        const halt = (reason: IncompleteReason) => {
            state.stopped = reason;
        };
        const timedOut = (): boolean => {
            if (opts.now() > opts.deadline) halt('TIME_BOX');
            return state.stopped !== null;
        };

        /** Read one file whole, or say why not. */
        const readText = async (abs: string, size: number): Promise<string | null> => {
            filesRead += 1;
            if (filesRead > MAX_FILES || bytes + size > MAX_TOTAL_BYTES) {
                halt('BYTE_CAP');
                return null;
            }
            if (size > MAX_FILE_BYTES) {
                problem('BYTE_CAP');
                return null;
            }
            let buf: Buffer;
            try {
                buf = await fs.readFile(abs);
            } catch (err) {
                problem(reasonOf(err));
                return null;
            }
            // It grew after it was measured: what was read is a cut of it.
            if (buf.length > MAX_FILE_BYTES) {
                problem('BYTE_CAP');
                return null;
            }
            bytes += buf.length;
            if (startsWithWideByteOrderMark(buf)) {
                problem('UNPARSEABLE');
                return null;
            }
            return buf.toString('utf8');
        };

        const fire = (kind: 'skill' | 'skill-file', subjectRef: string, field: string, text: string) => {
            for (const m of runAgentRules(text, kind)) {
                findings.push({ code: m.code, ruleId: m.ruleId, severity: m.severity, subjectKind: kind, subjectRef, originRef, locator: `${kind}:${subjectRef}#${field}` });
            }
        };

        /**
         * One directory. A directory holding `SKILL.md` is a skill: its
         * `SKILL.md` is read, and every script in it and below it is one of its
         * files (`inSkill`), down to the next directory that is a skill of its own.
         */
        const walk = async (abs: string, rel: string, depth: number, inSkill: boolean): Promise<void> => {
            if (timedOut()) return;
            if (depth > MAX_DIR_DEPTH) {
                problem('BYTE_CAP');
                return;
            }
            let entries: string[];
            try {
                entries = [...(await fs.readdir(abs))].sort();
            } catch (err) {
                problem(reasonOf(err));
                return;
            }
            const at = (name: string) => (rel === '' ? name : `${rel}/${name}`);
            const stats = new Map<string, Awaited<ReturnType<CodeFs['lstat']>>>();
            for (const name of entries) {
                if (timedOut()) return;
                try {
                    stats.set(name, await fs.lstat(joinPath(abs, name)));
                } catch (err) {
                    problem(reasonOf(err));
                }
            }

            const skillStat = stats.get(SKILL_FILE_NAME);
            const isSkill = skillStat !== undefined && !skillStat.isSymbolicLink() && skillStat.isFile();
            if (isSkill) {
                const text = await readText(joinPath(abs, SKILL_FILE_NAME), skillStat.size);
                if (text !== null) {
                    const ref = skillSubjectRef(root.label, at(SKILL_FILE_NAME));
                    skills += 1;
                    subjects += 1;
                    const { frontMatter, instructions } = splitSkillMarkdown(text);
                    if (frontMatter !== '') fire('skill', ref, 'frontMatter', frontMatter);
                    if (instructions !== '') fire('skill', ref, 'instructions', instructions);
                }
            }
            const scripts = isSkill || inSkill;
            for (const name of entries) {
                if (timedOut()) return;
                const st = stats.get(name);
                if (st === undefined || (isSkill && name === SKILL_FILE_NAME)) continue;
                if (st.isSymbolicLink()) {
                    problem('UNREACHABLE');
                    continue;
                }
                if (st.isDirectory()) {
                    if (!SKIPPED_DIRECTORIES.includes(name)) await walk(joinPath(abs, name), at(name), depth + 1, scripts);
                    continue;
                }
                if (!scripts || !st.isFile() || !isScript(name)) continue;
                const text = await readText(joinPath(abs, name), st.size);
                if (text === null) continue;
                files += 1;
                subjects += 1;
                if (text !== '') fire('skill-file', skillSubjectRef(root.label, at(name)), 'content', text);
            }
        };

        if (state.stopped === null) {
            try {
                const st = await fs.lstat(root.path);
                if (st.isSymbolicLink() || !st.isDirectory()) problem('UNREACHABLE');
                else await walk(root.path, '', 0, false);
            } catch (err) {
                problem(reasonOf(err));
            }
        }
        if (state.stopped !== null) problem(state.stopped);
        const reason = REASON_ORDER.find((r) => problems.has(r));
        origins.push(reason === undefined ? { ref: originRef, status: 'COMPLETE', subjects } : { ref: originRef, status: 'INCOMPLETE', reason, subjects });
    }
    return { findings, origins, skills, files };
}
