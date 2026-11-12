# Sample report

How to produce a sample set of results from made-up data, to show a client
what they will receive. It needs no access to any real system and no network.

## Why no sample file is stored here

Every run's files carry the time of the run, a random run identifier and a
signature made with the key of whoever ran it. A stored sample would go out of
date and its signature would mean nothing to you. So this page gives the
steps to make a fresh one, which takes a few seconds, and describes what you
will see.

## What the sample is made from

The repository holds a tiny made-up estate under `examples/code-only`:

- one agent, written with LangChain, that looks up a customer's order;
- a short list of agents as an organisation might declare it, naming that
  agent's owner and purpose, plus one agent that the estate does not contain.

Everything in it is invented. No real organisation, person or system appears.

## Make the sample

You need Node.js 22 or later and a copy of the repository. Run these from the
top folder of the copy.

```bash
npm ci
npm run build

export SCANNER_SIGNING_KEY="$(openssl genpkey -algorithm ed25519)"
sed "s#__REPO__#$(pwd)#" examples/code-only/config.local.template.json > /tmp/scanent-sample.json

mkdir -m 0700 -p "$HOME/scanent-sample"
npx scanent scan --config /tmp/scanent-sample.json --out "$HOME/scanent-sample"
```

The first `export` line creates a throwaway signing key that lives only in
that terminal window. The last line prints three short lines and finishes.

Then open the page. The file `latest.json` in `$HOME/scanent-sample` names the
newest run; the page is `summary.html` inside that run's folder:

```bash
cat "$HOME/scanent-sample/latest.json"
ls "$HOME/scanent-sample/runs/"
```

Open `summary.html` in a browser. It is one file and loads nothing from the
internet, so it can be shown offline, attached to a message or printed.

## What you will see

| In the sample | What it shows a client |
|---|---|
| One source, "code", read in full | The page starts with completeness: which systems were read, and whether each was read in full |
| One agent, found in `support/agent.py` | Each agent is identified by where it was found |
| Name "Support order lookup", owner "support-operations" | These come from the declared list. The page labels them as declared by the operator, not observed by the scan |
| Level **H1**, with a note that on what the scan observed alone it is H0 | A level that rests on a declaration is kept apart from what the scan saw for itself |
| A finding: an unpinned write-capable tool, `lookup_order` | The agent can call a tool whose definition nobody has reviewed and fixed in place |
| A finding: the agent is below the bar for what it can reach (H1, bar H3) | The scale sets a minimum level by how much an agent can do. The finding names the checks that block the next step |
| Many checks marked as not readable in this run | Nothing in a code-only scan could have seen them. The page says so, so that "nobody looked" is not read as "it failed" |
| One declared agent, "Billing reconciliation", that the scan did not find | What it looks like when the organisation's own list names an agent the scan cannot see |

The same run folder holds `agents.csv` and `findings.csv` for a spreadsheet,
`results.json` for tools, the signed report and a list of checksums.

One detail: the sample's declared risk assessment carries a fixed date,
1 October 2026. A risk assessment counts as current for 365 days. If you make
the sample after 1 October 2027, the agent will show at H0, not H1. The
[example's own notes](../../examples/code-only/README.md) explain how to
change the date.

## Show a comparison

To show how two runs are compared, run the scan a second time and then:

```bash
npx scanent diff "$HOME/scanent-sample"/runs/<older>/results.json \
                 "$HOME/scanent-sample"/runs/<newer>/results.json
```

Replace `<older>` and `<newer>` with the two folder names. Nothing changed
between the runs, so it reports no difference.

## When showing the sample

- Say that it is made-up data.
- Say that the scanner has not yet been run against a real organisation's
  systems. [Assurance status](../security-pack/assurance-status.md) has the
  details.
- Delete `$HOME/scanent-sample` and `/tmp/scanent-sample.json` when you are
  done. Close the terminal window to discard the throwaway key.
