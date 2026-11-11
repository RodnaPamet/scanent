/**
 * The JavaScript and TypeScript reader, shape by shape (#3737).
 *
 *   1. Every dialect is one code path: `.js`, `.cjs`, `.jsx`, `.ts`, `.mts`,
 *      `.tsx`, each parsed as what its extension says it is.
 *   2. An expression is lowered to the small IR; a wrapper that changes no
 *      value is seen through, and what the reader does not model is `opaque`,
 *      never a guess.
 *   3. Imports: ES forms and `require` forms name a module, and nothing is
 *      loaded.
 *   4. Bindings: a variable, a dotted assignment, a class property.
 *   5. Calls: every call once, outermost first, including those inside the
 *      function bodies of an argument.
 *   6. A class that extends a LangChain tool class is a tool declaration.
 */
import { JavaScriptReadError, readJavaScript } from '../src/sources/code/javascript';
import type { Expr, FileFacts } from '../src/sources/code/ir';

/** An IR node as compact text, so an expectation reads like the source it came from. */
const show = (e: Expr): string => {
    switch (e.k) {
        case 'ref':
            return e.name;
        case 'attr':
            return `${show(e.obj)}.${e.name}`;
        case 'str':
            return e.template ? `\`${e.value}…\`` : JSON.stringify(e.value);
        case 'call':
            return `${show(e.fn)}(${[...e.args.map(show), ...(e.spread ? ['…'] : [])].join(', ')})`;
        case 'list':
            return `[${e.items.map(show).join(', ')}]`;
        case 'dict':
            return `{${[...e.entries.map(([k, v]) => `${k ?? '?'}: ${show(v)}`), ...(e.spread ? ['…'] : [])].join(', ')}}`;
        case 'sub':
            return `${show(e.obj)}[${show(e.key)}]`;
        case 'concat':
            return e.parts.map(show).join(' + ');
        default:
            return `<${e.k}>`;
    }
};
const bound = (facts: FileFacts, name: string) => (facts.bindings.get(name) ?? []).map((b) => show(b.expr));
const valueOf = (expression: string, file = 'x.ts') => bound(readJavaScript(file, `const v = ${expression};\n`), 'v')[0];
const calls = (facts: FileFacts) => facts.calls.map(({ call, boundTo }) => [show(call), boundTo]);

describe('1. every dialect', () => {
    it('reads TypeScript-only syntax in .ts, .mts and .cts, and refuses it in .js', () => {
        const src = 'const v = <Model>make() as unknown as Model;\ninterface Model { name: string }\n';
        for (const file of ['a.ts', 'a.mts', 'a.cts', 'A.TS']) expect(bound(readJavaScript(file, src), 'v')).toEqual(['make()']);
        for (const file of ['a.js', 'a.mjs', 'a.cjs']) expect(() => readJavaScript(file, src)).toThrow(JavaScriptReadError);
    });

    it('reads JSX in .tsx and .jsx, where an angle bracket is an element and not a cast', () => {
        const src = 'const agent = createAgent({ tools: [] });\nexport const View = () => <div title="x">{agent.name}</div>;\n';
        for (const file of ['view.tsx', 'view.jsx']) expect(calls(readJavaScript(file, src))).toEqual([['createAgent({tools: []})', 'agent']]);
        expect(() => readJavaScript('view.ts', src)).toThrow(JavaScriptReadError);
    });

    it('a refusal names the line of the first error', () => {
        const refused = () => readJavaScript('agent.js', 'const a = 1;\nconst b = 2;\nconst c = ;\n');
        expect(refused).toThrow('line 3: the file does not parse');
        try {
            refused();
        } catch (err) {
            expect(err).toMatchObject({ name: 'JavaScriptReadError', line: 3 });
        }
    });

    it('an empty file is read, and holds nothing', () => {
        const facts = readJavaScript('empty.js', '');
        expect(facts.language).toBe('javascript');
        expect([facts.imports.size, facts.bindings.size, facts.toolDeclarations.size, facts.calls.length]).toEqual([0, 0, 0, 0]);
    });
});

describe('2. lowering an expression', () => {
    it.each([
        ['parentheses', '((llm))', 'llm'],
        ['an `as` cast', 'llm as ChatModel', 'llm'],
        ['a non-null assertion', 'llm!', 'llm'],
        ['`satisfies`', 'llm satisfies ChatModel', 'llm'],
        ['an angle-bracket assertion', '<ChatModel>llm', 'llm'],
        ['`await`', 'await llm', 'llm'],
        ['all of them at once', '((<ChatModel>(llm!)) as ChatModel) satisfies ChatModel', 'llm'],
    ])('sees through %s', (_label, expression, expected) => {
        expect(valueOf(expression)).toBe(expected);
    });

    it.each([
        ['a name', 'llm', 'llm'],
        ['`this`', 'this', 'this'],
        ['a member', 'config.models.fast', 'config.models.fast'],
        ['a member of `this`', 'this.llm', 'this.llm'],
        ['a subscript', 'models[name]', 'models[name]'],
        ['a subscript by a string', 'models["fast"].id', 'models["fast"].id'],
        ['a string', '"gpt-4o"', '"gpt-4o"'],
        ['a single-quoted string', "'gpt-4o'", '"gpt-4o"'],
        ['a template with no substitution', '`gpt-4o`', '"gpt-4o"'],
        ['a template with a substitution: only its head, marked', '`gpt-${version}-mini`', '`gpt-…`'],
        ['a concatenation', '"sk-" + suffix', '"sk-" + suffix'],
        ['a longer concatenation', 'a + b + "c"', 'a + b + "c"'],
        ['a list', '[search, "x", lookup]', '[search, "x", lookup]'],
        ['a list with a spread: its items, the spread among them', '[search, ...more]', '[search, more]'],
        ['an empty list', '[]', '[]'],
        ['an arrow function', '(x) => x', '<func>'],
        ['a function expression', 'function named() { return 1; }', '<func>'],
        ['a class expression', 'class {}', '<func>'],
    ])('reads %s', (_label, expression, expected) => {
        expect(valueOf(expression)).toBe(expected);
    });

    it.each([
        ['a number', '42'],
        ['a boolean', 'true'],
        ['null', 'null'],
        ['a conditional', 'prod ? a : b'],
        ['a logical or', 'a || b'],
        ['a subtraction', 'a - b'],
        ['a nullish default', 'process.env.MODEL ?? "gpt-4o"'],
        ['a tagged template', 'tag`text`'],
        ['a regular expression', '/re/'],
        ['a private member', 'this.#llm'],
        ['a negation', '!flag'],
        ['a `typeof`', 'typeof x'],
    ])('does not guess at %s: it is opaque', (_label, expression) => {
        const src = expression.includes('#') ? `class C { #llm = 1; m() { const v = ${expression}; } }\n` : `const v = ${expression};\n`;
        expect(bound(readJavaScript('x.ts', src), 'v')).toEqual(['<opaque>']);
    });

    it('reads a call and a `new`, with or without arguments', () => {
        expect(valueOf('createAgent(llm, tools)')).toBe('createAgent(llm, tools)');
        expect(valueOf('new ChatOpenAI({ model: "gpt-4o" })')).toBe('ChatOpenAI({model: "gpt-4o"})');
        expect(valueOf('new ChatOpenAI')).toBe('ChatOpenAI()');
        expect(valueOf('builder.withTools(tools).build()')).toBe('builder.withTools(tools).build()');
    });

    it('marks an argument list it cannot see whole', () => {
        const facts = readJavaScript('x.js', 'const v = createAgent(llm, ...rest);\nconst w = createAgent(llm, tools);\n');
        const [v, w] = facts.calls.map((c) => c.call);
        expect([v.spread, show(v)]).toEqual([true, 'createAgent(llm, rest, …)']);
        expect(w.spread).toBe(false);
        // Options are a dict argument in JavaScript: there are no keyword arguments.
        expect(v.kwargs.size).toBe(0);
    });

    it('reads an object literal key by key, and says when it cannot see it whole', () => {
        const facts = readJavaScript(
            'x.js',
            'const v = { model: "gpt-4o", "api-key": key, tools, run() {}, [computed]: x, 7: y, get g() { return 1; } };\nconst w = { ...base, model: "m" };\n',
        );
        expect(bound(facts, 'v')).toEqual(['{model: "gpt-4o", api-key: key, tools: tools, run: <func>, ?: x, ?: y}']);
        expect(bound(facts, 'w')).toEqual(['{model: "m", …}']);
        const v = facts.bindings.get('v')![0].expr;
        expect(v.k === 'dict' && v.spread).toBe(false);
    });

    it('stops at a stated depth rather than recursing without bound', () => {
        const deep = `${'('.repeat(80)}llm${')'.repeat(80)}`;
        expect(valueOf(deep)).toBe('<opaque>');
        const shallow = `${'('.repeat(40)}llm${')'.repeat(40)}`;
        expect(valueOf(shallow)).toBe('llm');
    });

    it('carries the line of each node', () => {
        const facts = readJavaScript('x.js', '\n\nconst v = make(\n  inner()\n);\n');
        expect(facts.bindings.get('v')![0].line).toBe(3);
        expect(facts.calls.map((c) => c.call.line)).toEqual([3, 4]);
    });
});

describe('3. imports', () => {
    it('reads every ES import form, and ignores an import that binds nothing', () => {
        const facts = readJavaScript(
            'x.ts',
            `import Default, { tool, DynamicTool as DT } from "@langchain/core/tools";
import * as agents from "langchain/agents";
import onlyDefault from "langgraph";
import type { Runnable } from "@langchain/core/runnables";
import "dotenv/config";
`,
        );
        expect(Object.fromEntries(facts.imports)).toEqual({
            Default: { module: '@langchain/core/tools', path: ['default'] },
            tool: { module: '@langchain/core/tools', path: ['tool'] },
            DT: { module: '@langchain/core/tools', path: ['DynamicTool'] },
            agents: { module: 'langchain/agents', path: [] },
            onlyDefault: { module: 'langgraph', path: ['default'] },
            Runnable: { module: '@langchain/core/runnables', path: ['Runnable'] },
        });
    });

    it('reads `require` as text naming a module: whole, destructured, renamed, awaited', () => {
        const facts = readJavaScript(
            'x.cjs',
            `const prebuilt = require("@langchain/langgraph/prebuilt");
const { ChatOpenAI, ChatAnthropic: Claude, nested: { deep }, ...others } = require("@langchain/openai");
async function load() {
    const awaited = await (require("langchain/agents"));
}
var legacy = require('langchain');
`,
        );
        expect(Object.fromEntries(facts.imports)).toEqual({
            prebuilt: { module: '@langchain/langgraph/prebuilt', path: [] },
            ChatOpenAI: { module: '@langchain/openai', path: ['ChatOpenAI'] },
            Claude: { module: '@langchain/openai', path: ['ChatAnthropic'] },
            others: { module: '@langchain/openai', path: ['others'] },
            awaited: { module: 'langchain/agents', path: [] },
            legacy: { module: 'langchain', path: [] },
        });
        // An import is not a binding to follow.
        expect(facts.bindings.size).toBe(0);
    });

    it.each([
        ['a computed module name', 'const m = require(name);'],
        ['a concatenated module name', 'const m = require("lang" + "chain");'],
        ['a template module name', 'const m = require(`langchain`);'],
        ['two arguments', 'const m = require("langchain", extra);'],
        ['no argument', 'const m = require();'],
        ['a method called require', 'const m = loader.require("langchain");'],
        ['a member of what was required', 'const m = require("langchain").agents;'],
    ])('%s imports nothing: it is an ordinary binding', (_label, src) => {
        const facts = readJavaScript('x.cjs', `${src}\n`);
        expect(facts.imports.size).toBe(0);
        expect(facts.bindings.has('m')).toBe(true);
    });

    it('an array pattern over a require is neither an import nor a binding', () => {
        const facts = readJavaScript('x.cjs', 'const [first] = require("langchain");\nconst [second] = other();\n');
        expect(facts.imports.size).toBe(0);
        expect(facts.bindings.size).toBe(0);
        expect(calls(facts)).toEqual([
            ['require("langchain")', null],
            ['other()', null],
        ]);
    });
});

describe('4. bindings', () => {
    it('keeps every binding of a name, in source order', () => {
        const facts = readJavaScript('x.js', 'let llm = first();\nllm = second();\nllm = "a string";\nlet later;\n');
        expect(bound(facts, 'llm')).toEqual(['first()', 'second()', '"a string"']);
        expect(facts.bindings.get('llm')!.map((b) => b.line)).toEqual([1, 2, 3]);
        expect(facts.bindings.has('later')).toBe(false);
    });

    it('binds a dotted assignment under its dotted name, and `this.x` under `this.x`', () => {
        const facts = readJavaScript(
            'x.ts',
            `config.models.fast = new ChatOpenAI({ model: "gpt-4o-mini" });
class Service {
    constructor() {
        this.llm = new ChatOpenAI({ model: "gpt-4o" });
    }
}
`,
        );
        expect(bound(facts, 'config.models.fast')).toEqual(['ChatOpenAI({model: "gpt-4o-mini"})']);
        expect(bound(facts, 'this.llm')).toEqual(['ChatOpenAI({model: "gpt-4o"})']);
        expect(calls(facts)).toEqual([
            ['ChatOpenAI({model: "gpt-4o-mini"})', 'config.models.fast'],
            ['ChatOpenAI({model: "gpt-4o"})', 'this.llm'],
        ]);
    });

    it('binds a class property as `this.<name>`, typed or not, and skips one with no value or a computed name', () => {
        const facts = readJavaScript(
            'x.ts',
            `class Service {
    llm = new ChatOpenAI({ model: "gpt-4o" });
    private readonly name: string = "support";
    declared: string;
    ["computed"] = make();
    static tools = [search];
}
`,
        );
        expect([...facts.bindings.keys()]).toEqual(['this.llm', 'this.name', 'this.tools']);
        expect(bound(facts, 'this.llm')).toEqual(['ChatOpenAI({model: "gpt-4o"})']);
        expect(bound(facts, 'this.tools')).toEqual(['[search]']);
        expect(calls(facts)).toEqual([
            ['ChatOpenAI({model: "gpt-4o"})', 'this.llm'],
            ['make()', null],
        ]);
    });

    it('an assignment to something that is not a dotted name binds nothing, but its calls are still read', () => {
        const facts = readJavaScript('x.js', 'registry[name] = build();\nfactory().llm = make();\nthis["llm"] = other();\ncount += bump();\n');
        expect(facts.bindings.size).toBe(0);
        expect(calls(facts).map(([c]) => c)).toEqual(['build()', 'factory()', 'make()', 'other()', 'bump()']);
    });

    it('a call is bound to a name only when it is the whole value', () => {
        const facts = readJavaScript('x.js', 'const whole = make(inner());\nconst part = [make()];\nconst member = make().field;\n');
        expect(calls(facts)).toEqual([
            ['make(inner())', 'whole'],
            ['inner()', null],
            ['make()', null],
            ['make()', null],
        ]);
    });
});

describe('5. calls', () => {
    it('reads a call statement, its arguments and the callee chain, outermost first', () => {
        const facts = readJavaScript('x.js', 'graph.addNode("agent", callModel(llm)).compile({ checkpointer: saver() });\n');
        expect(calls(facts).map(([c]) => c)).toEqual([
            'graph.addNode("agent", callModel(llm)).compile({checkpointer: saver()})',
            'graph.addNode("agent", callModel(llm))',
            'callModel(llm)',
            'saver()',
        ]);
    });

    it('reads the statements inside a function passed as an argument, once each', () => {
        const facts = readJavaScript(
            'x.ts',
            `const agent = wrap(async () => {
    const llm = new ChatOpenAI({ model: "gpt-4o" });
    return run(llm);
}, function () { second(); }, class { field = third(); });
`,
        );
        expect(calls(facts)).toEqual([
            ['wrap(<func>, <func>, <func>)', 'agent'],
            ['ChatOpenAI({model: "gpt-4o"})', 'llm'],
            ['run(llm)', null],
            ['second()', null],
            ['third()', 'this.field'],
        ]);
        expect(bound(facts, 'llm')).toEqual(['ChatOpenAI({model: "gpt-4o"})']);
    });

    it('reads calls in declarations it does not lower: functions, methods, control flow', () => {
        const facts = readJavaScript(
            'x.ts',
            `export async function main() {
    if (ready()) {
        for (const t of tools()) use(t);
    }
}
class Service {
    start() {
        return boot();
    }
}
export default defineAgent({ name: "x" });
`,
        );
        expect(calls(facts).map(([c]) => c)).toEqual(['ready()', 'tools()', 'use(t)', 'boot()', 'defineAgent({name: "x"})']);
    });

    it('text in a string, a template or a comment is never a call', () => {
        const facts = readJavaScript('x.js', 'const a = "make()";\nconst b = `make()`;\n// make()\n/* make() */\nconst c = real();\n');
        expect(calls(facts)).toEqual([['real()', 'c']]);
    });
});

describe('6. tool declarations', () => {
    const declared = (src: string) => Object.fromEntries(readJavaScript('tools.ts', src).toolDeclarations);

    it('a class extending a LangChain tool class is a tool, named by its `name` property', () => {
        expect(
            declared(`import { StructuredTool, Tool, DynamicTool, DynamicStructuredTool } from "@langchain/core/tools";
class Lookup extends StructuredTool {
    name = "lookup_order";
    async _call() { return ""; }
}
class Refund extends Tool {
    name = \`refund_order\`;
}
class Unnamed extends DynamicTool {}
export class Computed extends DynamicStructuredTool {
    name = prefix + "computed";
}
`),
        ).toEqual({
            Lookup: { line: 2, toolName: 'lookup_order' },
            Refund: { line: 6, toolName: 'refund_order' },
            // No literal name to read: the class's own name stands in.
            Unnamed: { line: 9, toolName: 'Unnamed' },
            Computed: { line: 10, toolName: 'Computed' },
        });
    });

    it('resolves the base class through a namespace import, an alias, and the legacy `langchain/tools` path', () => {
        expect(
            Object.keys(
                declared(`import * as tools from "@langchain/core/tools";
import { StructuredTool as Base } from "langchain/tools";
const legacy = require("langchain/tools");
class A extends tools.Tool {}
class B extends Base {}
class C extends legacy.DynamicTool {}
`),
            ),
        ).toEqual(['A', 'B', 'C']);
    });

    it('a class declared above the import that makes it a tool still resolves', () => {
        expect(declared('class Early extends Tool { name = "early"; }\nimport { Tool } from "@langchain/core/tools";\n')).toEqual({
            Early: { line: 1, toolName: 'early' },
        });
    });

    it.each([
        ['a base class from another package', 'import { Tool } from "some-other-sdk";\nclass X extends Tool {}'],
        ['a base class nobody imported', 'class X extends Tool {}'],
        ['a LangChain class that is not a tool', 'import { BaseChatModel } from "@langchain/core/language_models";\nclass X extends BaseChatModel {}'],
        ['a default import, which names no member', 'import Tool from "@langchain/core/tools";\nclass X extends Tool {}'],
        ['a base class produced by a call', 'import { Tool } from "@langchain/core/tools";\nclass X extends mixin(Tool) {}'],
        ['a class that only implements', 'import { Tool } from "@langchain/core/tools";\nclass X implements Tool {}'],
        ['a class with no base', 'class X { name = "x"; }'],
        ['an anonymous default class', 'import { Tool } from "@langchain/core/tools";\nexport default class extends Tool {}'],
    ])('%s declares no tool', (_label, src) => {
        expect(declared(`${src}\n`)).toEqual({});
    });
});
