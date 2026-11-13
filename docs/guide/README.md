# scanent: a guide for the organisation being scanned

This guide is for the IT or security lead of an organisation where scanent
will run. You do not need to be a developer to read it.

## What it is

scanent (also called the Agent Estate Scanner) makes a list of the AI agents
in your organisation, and of the accounts that behave like agents. An "agent"
here is a program that acts with its own account or key: a service account, an
API token, an automated workflow, a tool server, or agent code in a
repository.

For each one it finds, it reports:

- what it is and where it was found;
- which keys and passwords it holds, **by name only**, never the value;
- which tools it can call, and whether any of them can change something;
- how well it is controlled, on a scale of six levels from H0 to H5.

The result is a page you open in a browser, two spreadsheets, and a signed
report file. All of it is written to a folder you choose, on a machine you
choose.

One name comes up throughout this guide: **an Inflect tenant**. Inflect is a
separate compliance product from Inflect Ltd., the company that licenses this
scanner. An Inflect tenant is one organisation's own account on that product.
Among other things it keeps a register of that organisation's agents, and the
scanner can read that register and send its report there. You do not need
one. The scanner works without it, and this guide assumes you have none
unless it says otherwise.

## What it is not

- **It does not change anything.** It reads. It cannot create, edit, disable
  or delete an account, a key, a workflow or a file in your systems.
- **It does not read secret values.** It never asks any system for the value
  of a password, key or token. It reports that a key exists, how old it is and
  what holds it.
- **It does not read what agents say or do.** No prompts, no answers, no
  mail, no files, no chat.
- **It does not run your code.** Agent code is read as text. Nothing in it is
  started.
- **It does not block or stop an agent.** A low level is a finding in a
  report. Nothing is switched off.
- **It does not send your results anywhere.** By default the results stay in
  your folder. The scanner sends its authors nothing and does not look for
  updates.
- **It is not a certificate.** A good result says what the scanner could see
  on the day of the scan. [read-the-report.md](read-the-report.md) explains
  what a scan can and cannot show.

## Who does what

| Who | Does what |
|---|---|
| Your organisation | Decides which systems are scanned. Creates one read-only access for each of them. Decides where the results are kept and for how long |
| Whoever runs the scan: your own staff, or the engagement team | Runs three commands: set up, check, scan. Reads the results with you |
| The scanner | Reads, with the read-only access it was given. Writes its results into one folder |
| Nobody | Changes one of your systems. The scan needs no change to them and makes none |

Either you run it or the engagement team does. The commands and the results
are the same. If somebody else runs it for you, the results are still about
your systems: agree with them where the files are kept.

## The other five pages

| Page | Read it when |
|---|---|
| [what-it-reads.md](what-it-reads.md) | You are asked to grant access, and want to know what each access shows and what it must not include |
| [run-it.md](run-it.md) | You are going to run the first scan |
| [read-the-report.md](read-the-report.md) | You have results and want to know what they mean |
| [findings.md](findings.md) | The report lists a finding and you want to know what to do about it |
| [faq.md](faq.md) | Your security team has questions before it approves the scan |

The technical pages behind this guide are in the folder above this one. Each
page here points to the one that has the detail.

## What you should know before you rely on it

These are true today and are stated here so nobody has to find them out later.

- **No finished release exists yet.** There is no published, signed download.
  Today the program is built from its source code. [run-it.md](run-it.md)
  shows how.
- **It has not yet been run at a client.** It has been run once against a
  real organisation's systems: those of Inflect Ltd., the company that makes
  it, for four of the nine kinds of system. The other readers are tested only
  against a stand-in for the product they read, written from that product's
  public documentation. How often it misses an agent, or reports one wrongly,
  in a real organisation has not been measured.
- **It has had no independent security test** by an outside firm, and no
  outside code review.
- **It has not been run continuously for several days.** A five-minute
  continuous run has been done; the planned 72-hour run has not.

Plan the first scan as a trial: compare what it finds with what you already
know, and tell the engagement team what differs.

## Licence

scanent is licensed under the Business Source License 1.1. The licensor is
Inflect Ltd. You can read the source code. It is **not** an open-source
licence: use in production is subject to the terms in the
[LICENSE](../../LICENSE) file.
