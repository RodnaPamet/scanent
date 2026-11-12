# Run-book

The engagement from start to finish: before, on the day, and after. It tells
you what to do and in which order. The exact commands are in the
[quick start](../quick-start.md); this page points to the step you need.
The same commands, explained for a reader who is not an engineer, are in the
client guide's [Run it](../guide/run-it.md) page. Its steps are numbered
differently: the table below matches them up.

| What | Quick start | Client guide, Run it |
|---|---|---|
| Get the scanner | Step 0 | Steps 1 and 2 |
| Set up | Step 1 | Step 3 |
| Fill in the credentials | Step 2 | Step 4 |
| Check | Step 3 | Step 5 |
| Scan | Step 4 | Step 6 |
| Open the results | Step 5 | Step 7 |

Words used on this page:

- **Set-up folder**: the folder that holds the scanner's configuration, the
  file with the credentials and the signing key.
- **Results folder**: the folder the scanner writes each run into.
- **Operator**: the person who types the commands. Usually someone in the
  client's platform or security team, sometimes the engagement team.

## Before the day

### 1. Agree the scope (one to two weeks before)

- [ ] Complete the [scoping checklist](scoping-checklist.md) with the client
      and get it signed.
- [ ] Tell the client what has and has not been proven about the scanner. Use
      [Assurance status](../security-pack/assurance-status.md). Do not soften
      it.
- [ ] Give the client's IT or security lead the
      [client guide](../guide/README.md). It explains the scan, the access,
      the report and each finding in plain words.
- [ ] Give the client's security reviewer the
      [security pack](../security-pack/README.md).
- [ ] Give the client's data protection contact
      [Data handling](data-handling.md) and the assessment template in
      [Data protection](../data-protection.md).

### 2. Request access (one week before)

- [ ] For each system in scope, send the matching request from the
      [access request templates](access-request-templates.md).
- [ ] Confirm who on the client side will hold each credential.
- [ ] If the client has a firewall for outbound traffic, ask the network team
      to allow the addresses the scanner needs. The operator can print the
      exact list once set-up is done (step 4). The general list is in
      [Network and permissions](../network-and-permissions.md).

### 3. Prepare the machine (a few days before)

- [ ] The operator confirms the machine can run containers (Docker or Podman),
      or that a Kubernetes cluster is available.
- [ ] Get the scanner. **No release has been published yet**, so today the
      operator builds it from the source code (quick start, step 0). Once a
      release exists, the operator downloads it and checks its signature as
      [Verify a release](../verify-a-release.md) describes.
- [ ] Create the set-up folder and the results folder, private to the operator.

### 4. Set up and check (the day before)

- [ ] The operator runs set-up (quick start, step 1). It asks which systems
      are in scope and for their identifiers. It never asks for a credential.
      It writes three files into the set-up folder: the configuration, a file
      that lists the names of the credentials to fill in, and the signing key.
- [ ] The person who holds each credential puts it into that file (quick
      start, step 2). Nobody types a credential into the scanner or sends one
      by e-mail.
- [ ] The operator runs the check (quick start, step 3). It reads only and
      changes nothing. Each line says what was found, and a failed line says
      what to fix.
- [ ] Read the check's last line. "Ready" means go. A warning that a
      credential can do more than read means stop: ask the administrator to
      replace it with the read-only one from the request.
- [ ] Some lines say "not checked" with a reason. The check cannot see every
      permission from the outside. For those, the administrator confirms the
      grant by eye.

If the check fails, fix what it names and run it again. Do not scan until it
says "Ready" or the only remaining items are understood and written down.

## On the day

### 5. Scan

- [ ] The operator runs one scan (quick start, step 4). The offline example
      takes a few seconds. How long a real estate takes has not been measured.
      The whole scan is given ten minutes unless the set-up changes it.
      Systems are read side by side, and one that is not finished by then is
      marked incomplete, with the reason `TIME_BOX`.
- [ ] The last line of output should say "results written". That line alone
      does not mean everything was read. See the next step.

### 6. Look at completeness first

- [ ] Open `summary.html` from the newest run in the results folder.
- [ ] Read the first section. It lists each system and whether it was read in
      full.
- [ ] If a system is marked incomplete, the page gives the reason (for
      example: could not be reached, access refused, took too long). Agents
      found only through that system are shown as "Not judged". This is
      deliberate: the scanner does not guess.
- [ ] Decide with the client: fix the cause and scan again, or accept the
      partial result and record why.

### 7. Check the results against what the client knows

The scanner has not yet been run against real organisations' systems. So on
the first run:

- [ ] Pick a handful of agents or accounts the client knows well. Confirm
      each appears, with the right owner and credentials.
- [ ] Pick a handful of findings. Confirm each by looking at the system
      itself.
- [ ] Ask the client whether anything they expected is missing.
- [ ] For Okta: compare the API tokens in the results with the list in the
      Okta console. The scan may not see tokens that belong to other users.
- [ ] Write down every mismatch: something reported that is wrong, and
      something real that is missing. Send the list to the scanner's
      maintainers. It is the most useful thing a first engagement can produce.

### 8. Walk through the results with the client

The client guide has a page for this:
[Read the report](../guide/read-the-report.md) explains the page section by
section, and [Findings](../guide/findings.md) explains each kind of finding
and what to do about it.

- [ ] How many agents were found, and through which systems.
- [ ] Which agents nobody had registered or claimed.
- [ ] Which credentials belong to no known agent.
- [ ] Where each agent sits on the six-step scale, and what is missing for the
      next step.
- [ ] What this run could not have seen. The page lists these checks
      separately, so that "nothing looked" is not mistaken for "it failed".
- [ ] Agree who owns each finding.

### 9. If regular scans were agreed

- [ ] The operator sets up the schedule (quick start, step 6, or the
      Kubernetes section).
- [ ] Set how many runs to keep.
- [ ] After the second run, compare the two runs with the scanner's compare
      command. It reports what is new, what changed and what is gone. It calls
      something "gone" only when the system that would have listed it was read
      in full.

## After

### 10. Hand over the results

- [ ] The results folder stays with the client.
- [ ] If the engagement team takes a copy, take only the files agreed in the
      scoping checklist, and record what was taken and where it is held.
- [ ] If a result will be used as evidence, keep `report.signed.json` with it.
      It is the one file that carries a signature.

### 11. Remove access and credentials

Do this as soon as the last scan is done, unless regular scans were agreed.

- [ ] Each administrator removes the access they created. Each
      [access request template](access-request-templates.md) says how, under
      "When the scan ends".
- [ ] Delete the file that held the credentials.
- [ ] Delete or hand over the signing key, as agreed.
- [ ] Stop and remove the scanner if it is no longer needed.

The complete list, including copies and backups, is in
[Data handling](data-handling.md#how-to-delete-everything-afterwards).

### 12. Close

- [ ] The client confirms in writing that access was removed at each system.
- [ ] The engagement team confirms in writing which copies it deleted and
      which it handed over, with the date.
- [ ] Record what was learned: mismatches found in step 7, systems that could
      not be read, anything the client asked for that the scanner cannot do
      (see the [roadmap](../roadmap.md)).

## If something goes wrong

| What you see | What it means | What to do |
|---|---|---|
| The check says a credential is missing or refused | The credential was not filled in, has expired, or is wrong | Ask the person who holds it to check the file. Ask the administrator whether the access still exists |
| The check says a system cannot be reached | The machine cannot connect to that system | Ask the network team to allow the address the check names |
| A system is marked incomplete after a scan | Part of it could not be read. Nothing about it is reported as resolved | Read the reason on the page, fix it, scan again |
| The scan finds no agents at all | The scanner treats this as a finding, not as a clean result | Check that the right systems and identifiers were configured |
| The scanner refuses to write results and mentions a secret | Something it was about to write looked like a credential, so it wrote nothing | Do not work around it. Note which system was involved and tell the maintainers |
| You need help from the maintainers | | The operator can produce a support file that describes the set-up with names replaced by random tokens and no credentials. Read it before sending. See [Operating scanent](../operations.md#asking-for-help-the-support-bundle) |
| You think you found a security problem in the scanner | | Report it privately, as the [security policy](../../SECURITY.md) says. Do not open a public issue |
