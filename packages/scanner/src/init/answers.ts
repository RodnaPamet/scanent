/**
 * THE WIZARD'S ANSWERS — one object, whether a person typed them at the
 * prompts or a file supplied them (`--answers`).
 *
 * The object holds facts about the estate (a directory id, an org URL, a
 * repository) and NEVER a credential: no field can hold one, a secret-shaped
 * string anywhere is refused by path before anything else is looked at, and
 * the names of the variables credentials go in are assigned by the planner.
 *
 * A source here is the configuration's source without `product` (each kind
 * has one) and without its `…Env` name (defaulted). Its other fields carry the
 * configuration's own names and are validated by the configuration's own
 * schema, in the planner: there is no second copy of those rules here.
 */
import { z } from 'zod';

import { firstCredentialInAnswers } from './secret-shapes';

export const INIT_ANSWERS_SCHEMA = 'scanent-init-answers/1';

/** The kinds a person may choose. The register source comes only from `inflect.readRegister`. */
export const ANSWERABLE_KINDS = ['entra-sp', 'vault', 'okta-app', 'cicd', 'gcp-sa', 'runtime', 'mcp', 'code'] as const;
export type AnswerableKind = (typeof ANSWERABLE_KINDS)[number];

const envName = z.string().regex(/^[A-Z][A-Z0-9_]{0,63}$/);

const SourceAnswerSchema = z.looseObject({ kind: z.enum(ANSWERABLE_KINDS) });

export const InitAnswersSchema = z
    .object({
        answers: z.literal(INIT_ANSWERS_SCHEMA),
        estate: z.string(),
        everyHours: z.number().optional(),
        outputDir: z.string().optional(),
        retainRuns: z.number().optional(),
        inventoryPath: z.string().optional(),
        /** Override the signing key's variable name. */
        signingKeyEnv: envName.optional(),
        sources: z.array(SourceAnswerSchema).min(1).max(ANSWERABLE_KINDS.length),
        inflect: z
            .object({
                baseUrl: z.string(),
                tenantSlug: z.string(),
                agentId: z.string(),
                readRegister: z.boolean().optional(),
                apiKeyEnv: envName.optional(),
            })
            .strict()
            .nullable()
            .optional(),
    })
    .strict();

export type InitAnswers = z.infer<typeof InitAnswersSchema>;
export type SourceAnswer = InitAnswers['sources'][number];

/** Answers that were refused: the paths and rules, never a value. */
export class InitError extends Error {
    constructor(readonly issues: readonly string[]) {
        super(`invalid init answers: ${issues.join('; ')}`);
        this.name = 'InitError';
    }
}

/**
 * Parse an answers document. Refuses a credential-shaped string anywhere, and a
 * token-shaped name, before the schema runs (`secret-shapes.ts`).
 */
export function parseInitAnswers(json: unknown): InitAnswers {
    const secretAt = firstCredentialInAnswers(json);
    if (secretAt !== null) {
        throw new InitError([`${secretAt}: a credential value in the answers; scanent never takes one. If it was real, rotate it`]);
    }
    const parsed = InitAnswersSchema.safeParse(json);
    if (!parsed.success) throw new InitError(parsed.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.code}`));
    return parsed.data;
}
