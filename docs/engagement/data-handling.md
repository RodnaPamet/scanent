# Data handling

What the scanner reads, what it writes, what it keeps, what it sends, who
holds the signing key, and how to delete everything when the work is done.

This page is a plain-language summary. The full statement, with a template for
a data protection impact assessment, is [Data protection](../data-protection.md).
Every request the scanner can make is listed in
[Network and permissions](../network-and-permissions.md).

## In one paragraph

The scanner runs inside your organisation. It reads lists of non-human
accounts, automation and AI agents from the systems you choose, using
read-only access. It writes its results as files into one folder that you
choose. By default it sends nothing to anyone. It does not report back to its
authors and does not check for updates.

## What it reads

| It reads | Example | It does not read |
|---|---|---|
| Lists of non-human accounts | A service principal in Entra, a service account in Google Cloud | People's profiles, e-mail addresses, group memberships, sign-in history |
| Facts about credentials: identifier, creation date, expiry date | "This account has a key created on 3 March" | The credential itself. No password, key or secret value is requested from a vault or an identity system |
| Who owns an account, as an identifier | A directory object id, or the text your organisation wrote in an "owner" field | The owner's name, e-mail address or other details, unless your organisation wrote them in that field |
| Lists of tools an agent can use | Tool names from an MCP server or from source code | What a tool does when called. No tool is ever called |
| Source code, as text | A file that defines an agent | Nothing in the code is run |
| Automation workflow files and secret names | The names of secrets a GitHub workflow uses | Secret values, run logs |

Five things always reach the scanner's memory when their system is scanned,
because the answer it needs comes bundled with them, and a sixth only if you
switch an option on. They are discarded and are not written, logged or
reported:

- the full contents of each source file it reads (it keeps the agent
  definitions it recognises);
- the full contents of each GitHub workflow file (it keeps the permissions
  the file states and the names of the secrets it refers to);
- from Microsoft Entra ID, for each application password: a hint (the first
  few characters of the password) and the label somebody gave it. The
  scanner keeps the password's identifier and dates only;
- descriptions attached to LangSmith projects, Okta app profiles and MCP tools;
- the e-mail-style address of each Google service account (an address of a
  piece of software, not of a person);
- **only if you switch the option on:** the secrets attached to LangSmith
  deployments. The option is off unless you set it. Leave it off unless you
  need deployments in the report.

**Personal data.** The scanner's subject is software, not people. A person
appears in one way: as the owner of an account or agent, usually as an
identifier. If your organisation writes people's names into owner fields,
secret names, repository names or file paths, those names will appear in the
results. Treat the results as personal data wherever an owner is present.

## What it writes, per output

Each scan writes one new folder. Nothing already written is changed.

| File | What it is | Who it is for | Can contain |
|---|---|---|---|
| `summary.html` | One page to open in a browser. It loads nothing from the internet | Anyone reading the results | Agent identifiers, owner identifiers, findings, and the name, owner and purpose you declared for an agent if you supplied a list |
| `report.pdf` | The same results as a document | Anyone reading the results | The same as `summary.html` |
| `agents.csv` | One row per agent, for a spreadsheet | Analysts | The same |
| `findings.csv` | One row per finding | Whoever fixes findings | Agent identifiers and references to credentials (where a credential is kept, never its value) |
| `results.json` | Everything above, as data | Tools | The same as the page |
| `report.signed.json` | The scan report with a digital signature | Whoever needs proof the report was not altered | Agent identifiers and owner identifiers. Never the list you supplied |
| `manifest.json` | The name, size and checksum of the other five files | Whoever checks the files are intact | File names only |
| `latest.json` | A pointer to the newest run | Tools | The run's identifier and time, whether every system was read in full, and the number of agents |

Other things the scanner can produce:

| Output | When | Can contain |
|---|---|---|
| The log | Always. It goes to the container's log, wherever your platform keeps that | Counts, times, system addresses and the labels you gave your sources. No owner and no agent identifier. No credential |
| A support file | Only if someone runs the support command | A description of the set-up with names replaced by random tokens. No credential |
| A report sent to an Inflect tenant | Only if you configure it. Off by default | The signed report |

Before any file is written, the scanner checks everything it is about to
write for text shaped like a credential. If it finds any, it writes nothing
and says so.

The files can be read by the user the scanner runs as and that user's group,
and by nobody else on the machine.

## What it keeps

- **Between runs:** only the files in the results folder. The scanner has no
  database and no hidden store.
- **How long:** you decide. You can tell it to keep the newest N runs; it then
  removes older ones after each scan. Without that setting it never removes
  anything, and tidying the folder is up to you.
- **Removal is ordinary deletion.** The scanner does not overwrite the disk
  space a removed run used.

## What it sends

| To | What | When |
|---|---|---|
| The systems you chose (for example Microsoft, Okta, GitHub, Google) | Read requests, with your read-only credential | Every scan |
| An Inflect tenant | The signed report | Only if you configure it |
| The scanner's authors | Nothing | Never |
| Anyone else | Nothing | Never |

If your network sends traffic through a proxy that inspects encrypted
traffic, that proxy can see the scanner's requests, including the read-only
credentials. That is a property of the proxy, not of the scanner.

## The signing key

Every report is signed, so that a later reader can tell it was not altered.
Signing needs a key with two halves:

- a **private half**, which signs. It must be kept secret;
- a **public half**, which checks signatures. It is safe to share.

| Question | Answer |
|---|---|
| Who creates the key? | The set-up step creates it, on the machine where set-up is run. You may supply a key of your own instead |
| Where is it? | In one file in the set-up folder, readable only by the user who ran set-up |
| Who holds it? | Whoever runs the scanner. Agree this in the [scoping checklist](scoping-checklist.md): normally your organisation. If the engagement team runs the scanner for you, they hold it for the length of the engagement and delete it or hand it over at the end |
| Is it sent anywhere? | No. The private half never leaves that file. The public half is included in each report |
| Does anyone need the public half? | Only an Inflect tenant, if you send reports to one. It is registered there so the tenant accepts reports from this scanner |
| What if it leaks? | Someone could sign a false report in this scanner's name. Create a new key, and if a tenant was used, remove the old public half there and register the new one |
| What does the signature not cover? | Only `report.signed.json` is signed. The page, the spreadsheets and `results.json` are not. Anyone who can write to the results folder could change them. Keep the folder private |

## How to delete everything afterwards

Work through the list. Tick each line and keep the list as your record.

**1. Stop the scanner**

- [ ] Stop the schedule (stop the container, or remove the scheduled job).
- [ ] Remove the scanner's container image from the machine.
- [ ] On Kubernetes: uninstall the release. **The storage that holds the
      results is deliberately kept when the release is uninstalled.** Delete
      that storage claim separately. Delete the Secret that held the
      credentials; you created it, so uninstalling does not remove it.

**2. Remove the access** (at each system, by its administrator)

- [ ] Microsoft Entra ID: delete the client secret and the app registration.
- [ ] Azure Key Vault: remove the role assignment from each vault.
- [ ] Okta: revoke the API token; deactivate the dedicated user.
- [ ] GitHub: delete the token or remove the app installation.
- [ ] Google Cloud: delete the key and the service account.
- [ ] LangSmith: delete the service key.
- [ ] MCP servers: revoke each token.
- [ ] Inflect tenant, if used: revoke the API key and remove the scanner's
      public key.

Removing access at the system is what makes a credential useless. Do this
even if you also delete the file that held it.

**3. Delete the files**

- [ ] The set-up folder: the configuration file, the file that holds the
      credentials, the signing key file, and any key files placed beside them
      (for example the Google key).
- [ ] The results folder: every run, and `latest.json`. If the client keeps
      the results as evidence, hand the folder over instead and record who
      received it.
- [ ] The list of agents you supplied, if any.
- [ ] Any support file that was produced.
- [ ] Copies of source code made for the scan.

**4. Find the copies**

- [ ] Results attached to tickets or e-mails, or copied to shared drives.
- [ ] Results taken by the engagement team. Delete them by the date agreed in
      the scoping checklist.
- [ ] Backups of the machine that include the folders above. They follow your
      backup retention.
- [ ] The container's log. It follows your platform's log retention. It holds
      no credential, no owner and no agent identifier.
- [ ] Reports already sent to an Inflect tenant stay there under that tenant's
      retention. Ask its operator if they must be removed.

**5. Confirm**

- [ ] The client confirms in writing that access was removed at each system.
- [ ] The engagement team confirms in writing which copies it deleted and
      which it handed over.
