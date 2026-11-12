/**
 * THE WIZARD'S OWN SECRET SHAPES — beside the contract's, never instead of it.
 *
 * `looksLikeSecret` (the contract) is what the ingest refuses in a report, and
 * it is deliberately short. `init` is where a person is most likely to paste a
 * credential into the wrong field, and the credentials it tells them to create
 * are mostly ones that list does not know: an Okta API token, a LangSmith key,
 * an Inflect key, an Entra client secret. Widening the contract's list would
 * change what a tenant accepts in a report; so the extra shapes live here and
 * are asked only of what `init` is given (the prompts and `--answers`).
 *
 *   • `looksLikeCredential` — the contract's shapes plus the credentials this
 *     scanner takes. Asked of EVERY answer.
 *   • `looksLikeBareToken` — a long run of letters and digits with nothing to
 *     read in it. Asked only of the fields that hold a NAME somebody chose
 *     (the estate, a label, the agent id, the tenant slug): a directory id is
 *     32 hexadecimal digits too, and is not refused for it.
 *
 * A false refusal costs one re-typed answer; a false acceptance writes a
 * credential into `config.json` and, for the estate and the agent id, into
 * every report.
 */
import { looksLikeSecret } from '@scanent/contract/harness-contract';

const TOKEN_CHAR = 'A-Za-z0-9_-';

const WIZARD_SECRET_SHAPES: readonly RegExp[] = [
    // Okta API token (SSWS): `00` and forty URL-safe characters, as a whole token.
    new RegExp(`(?<![${TOKEN_CHAR}])00[${TOKEN_CHAR}]{40}(?![${TOKEN_CHAR}])`),
    // LangSmith personal and service keys.
    /lsv2_(?:pt|sk)_[A-Za-z0-9_]{8,}/,
    // Inflect API keys, exchanged tokens and peer credentials.
    /ifl[kp]_[A-Za-z0-9_-]{8,}/,
    /ifxt_[A-Za-z0-9_-]{8,}/,
    // Google API key.
    /AIza[0-9A-Za-z_-]{35}/,
];

/** Microsoft Entra client secret: a whole token of 34 to 40 characters holding a `~`, a letter and a digit. */
function holdsEntraClientSecret(value: string): boolean {
    for (const token of value.split(/[^A-Za-z0-9._~-]+/)) {
        if (token.length >= 34 && token.length <= 40 && token.includes('~') && /[0-9]/.test(token) && /[A-Za-z]/.test(token)) return true;
    }
    return false;
}

/** A credential by its shape: the contract's list, or one of the credentials this scanner is given. */
export function looksLikeCredential(value: string): boolean {
    return looksLikeSecret(value) || WIZARD_SECRET_SHAPES.some((re) => re.test(value)) || holdsEntraClientSecret(value);
}

/** The longest run of letters and digits a NAME may hold before it stops reading as a name. */
export const MAX_NAME_RUN = 20;

/**
 * A name that reads as a token: 32 or more characters of letters, digits,
 * hyphens and underscores, with letters AND digits, and an unbroken run of
 * more than `MAX_NAME_RUN` letters and digits. `acme-production-eu-west-1` is a
 * name; forty hexadecimal digits are not.
 */
export function looksLikeBareToken(value: string): boolean {
    if (value.length < 32 || !/^[A-Za-z0-9_-]+$/.test(value)) return false;
    if (!/[0-9]/.test(value) || !/[A-Za-z]/.test(value)) return false;
    return value.split(/[-_]/).some((run) => run.length > MAX_NAME_RUN);
}

const isRecord = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);

/**
 * The path of the first string in an answers document that `init` refuses as a
 * credential, or null: any string by `looksLikeCredential`, and the name
 * fields by `looksLikeBareToken`. A key is never part of the path's proof: a
 * credential-shaped key is rendered `<key>`.
 */
export function firstCredentialInAnswers(json: unknown): string | null {
    const keyOf = (k: string) => (looksLikeCredential(k) || looksLikeBareToken(k) ? '<key>' : k);
    const walk = (node: unknown, path: string): string | null => {
        if (typeof node === 'string') return looksLikeCredential(node) ? path || '(root)' : null;
        if (Array.isArray(node)) {
            for (let i = 0; i < node.length; i++) {
                const hit = walk(node[i], `${path}[${i}]`);
                if (hit !== null) return hit;
            }
            return null;
        }
        if (isRecord(node)) {
            for (const [k, v] of Object.entries(node)) {
                if (looksLikeCredential(k) || looksLikeBareToken(k)) return path ? `${path}.<key>` : '<key>';
                const hit = walk(v, path ? `${path}.${keyOf(k)}` : keyOf(k));
                if (hit !== null) return hit;
            }
        }
        return null;
    };
    const anywhere = walk(json, '');
    if (anywhere !== null) return anywhere;
    if (!isRecord(json)) return null;

    const name = (v: unknown, path: string): string | null => (typeof v === 'string' && looksLikeBareToken(v) ? path : null);
    const hits: (string | null)[] = [name(json.estate, 'estate')];
    if (isRecord(json.inflect)) hits.push(name(json.inflect.agentId, 'inflect.agentId'), name(json.inflect.tenantSlug, 'inflect.tenantSlug'));
    if (Array.isArray(json.sources)) {
        json.sources.forEach((source: unknown, i) => {
            if (!isRecord(source)) return;
            for (const list of ['servers', 'roots'] as const) {
                const entries = source[list];
                if (!Array.isArray(entries)) continue;
                entries.forEach((entry: unknown, j) => {
                    if (isRecord(entry)) hits.push(name(entry.label, `sources[${i}].${list}[${j}].label`));
                });
            }
        });
    }
    return hits.find((h) => h !== null) ?? null;
}
