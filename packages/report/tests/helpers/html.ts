/**
 * A page with every `<script>` element removed: what a reader with no script
 * sees. Done by index, in one pass and in any letter case, rather than with a
 * regular expression: a regex for this is either slow on input built to make
 * it slow or blind to `<SCRIPT>`, and the page is the scanner's own output
 * built from untrusted strings. An element left unclosed is removed to the end.
 */
export function withoutScriptElements(page: string): string {
    const lower = page.toLowerCase();
    let out = '';
    let at = 0;
    for (;;) {
        const open = lower.indexOf('<script', at);
        if (open < 0) return out + page.slice(at);
        out += page.slice(at, open);
        const close = lower.indexOf('</script', open);
        if (close < 0) return out;
        const end = lower.indexOf('>', close);
        at = end < 0 ? page.length : end + 1;
    }
}
