/**
 * HTML ESCAPING — the one way a string enters `summary.html`.
 *
 * Everything a scan reports is untrusted input: a discovered id, an evidence
 * reference, a tool's server, an owner, and everything the operator's
 * inventory declares. The page is built by one tagged template, `html`, and
 * every value interpolated into it is escaped unless it is itself the result
 * of an `html` call. There is no exported way to mark a string as safe: the
 * set of safe fragments is private to this module, so a renderer cannot be
 * handed markup it did not build from escaped parts.
 */

/** A fragment built by `html`. Opaque: only this module can make one. */
export interface SafeHtml {
    readonly __safeHtml: true;
}

const FRAGMENTS = new WeakMap<SafeHtml, string>();

function fragment(text: string): SafeHtml {
    const f: SafeHtml = Object.freeze({ __safeHtml: true as const });
    FRAGMENTS.set(f, text);
    return f;
}

const ESCAPES: Readonly<Record<string, string>> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
    '`': '&#96;',
};

/**
 * The Unicode bidirectional controls: marks, embeddings, overrides and
 * isolates. They execute nothing, but one in a scanned id reorders the text
 * shown beside it, so an id can be made to read as another. None is written
 * to any output.
 */
export function isBidiControl(code: number): boolean {
    return code === 0x061c || code === 0x200e || code === 0x200f || (code >= 0x202a && code <= 0x202e) || (code >= 0x2066 && code <= 0x2069);
}

/** C0, DEL, C1, the two Unicode line separators and the bidirectional controls. */
function isUnprintable(code: number): boolean {
    return code < 0x20 || (code >= 0x7f && code <= 0x9f) || code === 0x2028 || code === 0x2029 || isBidiControl(code);
}

/**
 * One line of plain text for a terminal: every control character, line
 * separator and bidirectional control becomes a visible `\u{..}`. A scanned
 * string can therefore neither start a new line nor send an escape sequence,
 * and what was there can still be read.
 */
export function terminalLine(value: string): string {
    let out = '';
    for (const ch of value) {
        const code = ch.codePointAt(0) as number;
        out += isUnprintable(code) ? `\\u{${code.toString(16)}}` : ch;
    }
    return out;
}

/**
 * JSON text for a terminal. `JSON.stringify` escapes C0 only; DEL, C1 (U+009B
 * is a control sequence introducer), the line separators and the bidirectional
 * controls are escaped here. They can occur only inside a string, where a
 * `\uXXXX` escape is the same value.
 */
export function terminalJson(json: string): string {
    let out = '';
    for (const ch of json) {
        const code = ch.codePointAt(0) as number;
        out += code >= 0x20 && isUnprintable(code) ? `\\u${code.toString(16).padStart(4, '0')}` : ch;
    }
    return out;
}

/**
 * Escape text for an element's content or a quoted attribute value. Control
 * characters other than tab and line feed are replaced, and so is every
 * bidirectional control: none of them belongs in a report, and some end a
 * line, or reorder one, where a reader does not expect it.
 */
export function escapeHtml(value: string): string {
    let out = '';
    for (const ch of value) {
        const code = ch.codePointAt(0) as number;
        if (ESCAPES[ch] !== undefined) out += ESCAPES[ch];
        else if (isUnprintable(code) && ch !== '\n' && ch !== '\t') out += '\ufffd';
        else out += ch;
    }
    return out;
}

export type HtmlValue = SafeHtml | string | number | readonly HtmlValue[];

function render(value: HtmlValue): string {
    if (typeof value === 'string') return escapeHtml(value);
    if (typeof value === 'number') return escapeHtml(String(value));
    if (Array.isArray(value)) return value.map(render).join('');
    // Anything else is escaped as text unless this module built it.
    return FRAGMENTS.get(value as SafeHtml) ?? escapeHtml(String(value));
}

/** The tagged template: the literal parts are markup, every interpolated value is escaped. */
export function html(parts: TemplateStringsArray, ...values: readonly HtmlValue[]): SafeHtml {
    let out = parts[0];
    for (let i = 0; i < values.length; i++) out += render(values[i]) + parts[i + 1];
    return fragment(out);
}

/** Join fragments (or values, which are escaped) with nothing between them. */
export function joinHtml(values: readonly HtmlValue[]): SafeHtml {
    return fragment(values.map(render).join(''));
}

/** The text of a fragment: the last step, when the page is written. */
export function htmlText(value: SafeHtml): string {
    const text = FRAGMENTS.get(value);
    if (text === undefined) throw new Error('not a fragment built by html');
    return text;
}
