# Scoping checklist

Questions to settle before a scan. Agree the answers in writing with the
client. Each answer decides something practical: which access to request,
where to install, who may open the results.

Words used on this page:

- **Agent**: a piece of software that acts with some independence, often
  using an AI model, and the accounts and keys it acts with.
- **Source**: one system the scanner reads to find agents, for example Okta
  or GitHub.
- **Read-only access**: access that can look and cannot change anything.

## 1. Which systems are in scope?

Tick each system the client uses and wants read. Each one is optional. The
scanner reads only the systems that are configured.

| System | What the scanner looks for there | In scope? |
|---|---|---|
| Microsoft Entra ID | App registrations and service principals (non-human accounts) | |
| Okta | Service apps and API tokens | |
| Azure Key Vault | The names and dates of stored secrets and certificates. Never their values | |
| Google Cloud | Service accounts and the keys they hold | |
| GitHub Actions | Automation workflows, and the names of the secrets they use. Never the values | |
| LangSmith | Tracing projects, which show which agents run and which tools they call | |
| MCP servers | The list of tools each server offers to agents. No tool is ever called | |
| Source code | Agent definitions written with LangChain, LangGraph or the Claude Agent SDK, in Python, JavaScript or TypeScript. The code is read as text and never run | |
| An Inflect tenant | The client's own register of agents, if they have one | |

For each ticked system, write down:

- [ ] Its exact identifier. Examples: the Entra directory id, the Okta address
      (such as `https://example.okta.com`), the list of GitHub repositories,
      the list of Google Cloud projects, the address of each MCP server, the
      folders that hold agent code.
- [ ] Whether all of it is in scope or only part. Example: "these 12
      repositories", not "all of GitHub".
- [ ] Anything the client wants left out, and why.

Systems the scanner cannot read today are listed in the
[roadmap](../roadmap.md). Do not promise them.

## 2. Who grants access?

- [ ] For each system in scope: the name and role of the administrator who can
      create read-only access.
- [ ] Who approves the request on the client's side (often the security team).
- [ ] How long approval usually takes. Some grants need a change ticket.
- [ ] Who will hold each credential once it is created. A credential is a
      password, token or key file. It should stay with the client. The scanner
      never needs it typed into a form or sent by e-mail.

The exact access to ask for is in the
[access request templates](access-request-templates.md).

## 3. Where does it run?

The scanner runs inside the client's own environment. It needs a machine or
cluster that can run a container (a packaged program).

- [ ] Which machine or cluster, and who operates it.
- [ ] Which way of running it: one run by hand, a schedule on one machine, or a
      schedule on Kubernetes. The technical choices are in the
      [deployment guide](../deployment.md).
- [ ] Can that machine reach each system in scope over the internet (HTTPS,
      port 443)? If outbound traffic goes through a firewall, the client's
      network team needs the list of addresses. The scanner prints that list
      for a given set-up, and [Network and permissions](../network-and-permissions.md)
      shows every request it can make.
- [ ] Does traffic pass through a proxy, or a proxy that inspects encrypted
      traffic? Such a proxy can see the credentials the scanner uses. Agree
      that with the client's security team first.
- [ ] Does the site have no internet at all? Then the scanner is brought in as
      a single archive. No such archive has been published yet; today it has
      to be built from the source code.
- [ ] One run, or regular runs? If regular, how often (for example every 24
      hours).

## 4. Where do the results go?

By default the results are files in one folder on the machine where the
scanner runs. Nothing is sent anywhere else.

- [ ] Which folder, on which machine.
- [ ] Is the folder private to the people who should read the results?
- [ ] Will the results also be sent to an Inflect tenant? This is optional and
      off by default. If yes: which tenant, who operates it, and under which
      agreement.
- [ ] Will anyone copy results out of the folder (to a shared drive, a ticket,
      an e-mail)? If yes, agree where and who.

## 5. Who reads the results?

- [ ] Names and roles of the people who may open the results.
- [ ] Who acts on a finding. A finding is one thing the scan says needs
      attention, for example an agent with no named owner.
- [ ] Does the engagement team take a copy away? If yes, which files, held
      where, and for how long.
- [ ] The results can name people: the owner of an account is often recorded
      as a person's identifier. Has the client's data protection contact been
      told? [Data protection](../data-protection.md) has a template for their
      assessment.

## 6. How long is everything kept?

- [ ] How many runs to keep. The scanner can keep the newest N runs and remove
      older ones. Without that setting it removes nothing.
- [ ] When the engagement ends: the date by which results, set-up files,
      credentials and the signing key are deleted or handed over. The steps
      are in [Data handling](data-handling.md#how-to-delete-everything-afterwards).
- [ ] Who confirms in writing that access was removed.

## 7. What the client should know before agreeing

Say these plainly. They are true today.

- [ ] The scanner only reads. It cannot change, create or delete anything in
      the systems it reads.
- [ ] It has been tested against imitations of each system, built from each
      vendor's documentation. It has not yet been run against a real
      organisation's systems. Results from the first real runs should be
      checked by hand.
- [ ] It has not had an external penetration test.
- [ ] No signed release has been published yet.
- [ ] A scan can show how well an agent is controlled only as far as the
      systems in scope reveal it. The scale has six steps, H0 (lowest) to H5.
      Reaching H1 needs either the client's register in an Inflect tenant or
      a list of agents the client supplies. Going above H1 needs the register,
      and then stops at H3. Nothing the scanner reads today gives evidence for
      H4 or H5. The results page says, for each check, when nothing in the run
      could have seen it.

The full list of what has and has not been done is in
[Assurance status](../security-pack/assurance-status.md).

## Sign-off

| Item | Agreed by (client) | Agreed by (engagement team) | Date |
|---|---|---|---|
| Systems in scope | | | |
| Access and who holds credentials | | | |
| Where it runs | | | |
| Where results go and who reads them | | | |
| Retention and deletion date | | | |
