/**
 * The catalogue's digest: SHA-256 over the canonical JSON of every probe's id,
 * class, category, leak, interfaces and text. A change to any probe changes
 * it, so two reports or two surfaces with one digest ran the same list.
 */
import { createHash } from 'node:crypto';

import { canonicalJson } from '@rodnapamet/scanent-contract/canonical-json';

import { PROBES, type Probe } from './catalogue';

export function catalogueDigestOf(probes: readonly Probe[] = PROBES): string {
    const shape = probes.map((p) => ({
        id: p.id,
        class: p.class,
        category: p.category,
        leak: p.class === 'disclosure' ? p.leak : null,
        interfaces: [...p.interfaces],
        text: p.text,
    }));
    return `sha256:${createHash('sha256').update(canonicalJson(shape), 'utf8').digest('hex')}`;
}
