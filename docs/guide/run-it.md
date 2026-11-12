# Run it: from nothing to a first report

This page is the shortest path to a first report, using Docker. Docker is a
program that runs other programs in a sealed box called a container. The
scanner is delivered as such a box, called an image.

You need:

- a computer with Docker, that can reach the systems you want scanned;
- a Linux or macOS terminal. On Windows, use WSL (Windows Subsystem for
  Linux, which gives you a Linux terminal). The commands are written for the
  `bash` or `zsh` shell, which is what those terminals run;
- `git`, for step 1 only;
- the read-only access for each system you want scanned. Asking for it is
  usually the slow part: see [what-it-reads.md](what-it-reads.md).

Type the commands in a terminal, in one folder, in order. Nothing here
changes any of your systems.

## 1. Get the scanner

No finished release has been published yet. Until one is, you build the image
from the source code. This needs internet access, and takes a few minutes the
first time:

```bash
export IMAGE=ghcr.io/rodnapamet/scanent:0.13.0
git clone https://github.com/RodnaPamet/scanent.git
docker build -f scanent/deploy/Dockerfile -t "$IMAGE" scanent
```

The first line gives the image a name. The other steps use that name.

If your network inspects encrypted traffic, the build needs your network's
certificate: [../quick-start.md](../quick-start.md#0-get-the-image) says how.

Once a release exists, you will download the finished scanner instead of
building it. The download is public: it needs no account with us or with
GitHub, and no password.

## 2. Make a short name for "run the scanner safely"

Every step runs the scanner the same way. Type this once in the terminal you
will use. It makes `scanent` a short name for the long command:

```bash
scanent() {
  docker run --rm --user "$(id -u):$(id -g)" \
    --read-only --cap-drop ALL --security-opt no-new-privileges "$@"
}
```

In plain words, it runs the scanner:

- as you, not as an administrator of the computer;
- in a box whose own files cannot be changed;
- with every special permission removed, and no way to gain one.

If you close the terminal, open a new one in the same folder and type the
first line of step 1 and all of step 2 again before you continue. If you had
already done step 3, also type `cd site`.

## 3. Set up

Make two folders that only you can open. One holds the settings, the other
the results. Then start the set-up:

```bash
mkdir -p site/scanent site/scanent-out
chmod 0700 site/scanent site/scanent-out
cd site
scanent -it --network none -v "$PWD/scanent:/etc/scanent" "$IMAGE" init --dir /etc/scanent
```

The set-up asks questions and you type the answers:

- a short name for what is being scanned, such as `acme-prod`;
- for each kind of system, whether you have it, and then which one: a
  directory id, an address, the names of repositories;
- for agent code in folders: a short label, then the path at which **the
  scanner** will see the folder. This is not the folder's place on your
  computer. Type `/estate` (for a second folder, `/estate2`, and so on).
  Step 5 connects your real folder to that path;
- where results go. Press Enter to accept `/out`;
- how often to scan when it runs on a schedule. Press Enter to accept 24
  hours;
- an inventory file. Press Enter for none; step 7 comes back to this;
- whether to send results to an Inflect tenant. Answer `n` unless your
  organisation uses one.

**It never asks for a password, token or key.** If you paste something that
looks like one, it refuses the answer. This step makes no network connection at all, which is
what `--network none` means.

It writes three files into the `scanent` folder:

| File | What it holds |
|---|---|
| `config.json` | The settings: what to read. It holds the **names** of the credentials, never a value |
| `scanent.env` | A list of those names, each waiting for its value |
| `signing-key.pem` | A key made on your computer. Each report is signed with it, so a later change to the report can be detected |

It then prints, for each system you chose, the read-only access to create.

## 4. Create the access, and fill in the values

Create each access as [what-it-reads.md](what-it-reads.md) describes. Then
open `scanent/scanent.env` in a text editor, and put each value after the `=`
on its line. Write the value as it is, with no quotes.

One exception: the Google Cloud key is a file. Copy it into the `scanent`
folder as `gcp-key.json`, and the line reads:

```
GCP_SCANNER_KEY_FILE=/etc/scanent/gcp-key.json
```

If you scan only agent code in folders, there is nothing to fill in.

Keep this file private. It now holds credentials that can read your systems.

## 5. Check

**If you scan agent code in folders**, first give each folder to the scanner
as read-only. Add one piece like this to the command below and to the one in
step 6, just before `"$IMAGE"`. Your own folder goes on the left of the
colon, and the path you typed in step 3 goes on the right:

```
-v /srv/agents:/estate:ro
```

Here `/srv/agents` stands for your folder, and `/estate` is the path from
step 3. Without this piece the check fails at `read.permitted`, because the
scanner cannot see the folder.

```bash
scanent --env-file scanent/scanent.env \
  -v "$PWD/scanent:/etc/scanent:ro" -v "$PWD/scanent-out:/out" \
  "$IMAGE" doctor --config /etc/scanent/config.json
```

This is a rehearsal. It tries each access with the smallest read it can, and
prints one line for each check: `PASS`, `WARN`, `FAIL` or `SKIPPED`.
`SKIPPED` means not checked, and the line says why. A line that fails says
what to fix. It writes nothing and changes nothing.

When everything is ready, the last line looks like this. The numbers are your
own:

```
8 passed, 0 warnings, 0 failed, 10 not checked (1 not observable, 9 not applicable). Ready. 10 checks were not checked; each says why above.
```

"Not checked" is never counted as passed.
[read-the-report.md](read-the-report.md#words-the-results-use) says what it
means.

The most common lines that need action:

| The check says | What to do |
|---|---|
| `FAIL credential.present` | A value is missing in `scanent.env` |
| `FAIL host.resolves` or `FAIL reachable` | The computer cannot reach that system. Ask for the address to be opened in the firewall, on port 443 |
| `FAIL authenticated` | The system refused the credential. Check it is the right one and has not expired |
| `FAIL read.permitted` | The credential works but lacks the read-only role the line names. For agent code in folders: the folder was not given to the scanner, or cannot be read. See the note at the top of this step |
| `WARN write.absent` | The credential can change things. Replace it with one that cannot |

## 6. Scan

```bash
scanent --env-file scanent/scanent.env \
  -v "$PWD/scanent:/etc/scanent:ro" -v "$PWD/scanent-out:/out" \
  "$IMAGE" scan --config /etc/scanent/config.json
```

The scanner prints a few lines as it works. One line for each system says
whether it was read in full (`"status":"COMPLETE"`). The last line says the
results were written:

```
{"ts":"…","level":"info","msg":"results written","scan":"<name>-<time>-<id>","dir":"runs/<name>-<time>-<id>","files":6,"removedRuns":0}
```

That last line alone does not mean everything was read. The report says what
was not, at the top.

## 7. Open the report

```bash
cat scanent-out/latest.json
```

This names the newest run. Open the folder `scanent-out/runs/`, then the
folder with that name, then `summary.html`. It opens in any browser and loads
nothing from the internet.

[read-the-report.md](read-the-report.md) explains the page.

### Then: tell it which agents you already know

On a first scan, every agent is shown as unknown to you, because the scanner
has no list of the agents you know about. You can give it one. It is called
an inventory.

Open `agents.csv` from the run in a spreadsheet. The first column,
`discoveredId`, is the scanner's name for each agent. Make a new file,
`scanent/inventory.csv`, with one line for each agent you recognise:

```
discoveredId,name,owner,purpose,autonomyLevel,dataAccessScope,reversibility,provenance,riskTier,riskAssessedOn
entra:sp:00000000-0000-0000-0000-000000000000,Invoice triage,finance-operations,Sorts incoming invoices into queues,2,WRITE_TENANT_DATA,COMPENSABLE,FIRST_PARTY,MODERATE,2026-09-30
```

- `discoveredId` must be copied exactly.
- `name`, `owner` and `purpose` are required. `owner` can be a team: you do
  not have to write a person's name.
- The last six are optional, but an agent reaches level H1 only with all of
  them. Without them it stays at level H0, even though it is on your list.
  The first four describe the agent, and you give all four or none:

  | Column | What to write |
  |---|---|
  | `autonomyLevel` | How far it acts on its own, as a whole number from 0 to 6. 0: it only suggests to a person. 1: it reads data by itself. 2: it drafts changes that a person approves. 3: it carries out several steps in a row with nobody watching. 4 to 6: more independent still, up to 6, which acts across several systems with nobody watching. Inflect's own register says a level above 3 changes nothing about what an agent can reach today, so 3 is enough unless your organisation uses the higher numbers |
  | `dataAccessScope` | How far into your data it reaches. `NONE`: only what it is handed. `READ_METADATA`: names, counts and dates, not content. `READ_TENANT_DATA`: it reads your content. `WRITE_TENANT_DATA`: it changes your content. `EXTERNAL_EGRESS`: it sends your data outside your organisation |
  | `reversibility` | How hard it is to undo what it does. `REVERSIBLE`: it can be put back as it was. `COMPENSABLE`: it cannot, but something can be done to make up for it. `TERMINAL`: neither, for example a message that has been sent |
  | `provenance` | Who wrote it. `FIRST_PARTY`: your organisation. `THIRD_PARTY`: a supplier |

  The last two are its risk rating (`LOW`, `MODERATE`, `HIGH` or `CRITICAL`)
  and the date of that rating, written like `2026-09-30`, which must be
  within the 365 days before the scan. You give both or neither.

  These are the same descriptions, with the same words, that an Inflect
  tenant keeps for an agent. Write the values exactly as shown, in capitals.

Then open `scanent/config.json` in a text editor, and add this line directly
after the first `{`:

```
"inventory": { "path": "/etc/scanent/inventory.csv" },
```

Run step 6 again. The new report shows what you declared, and always labels
it "declared by the operator": the scanner did not see it for itself.

## Running it again, and comparing

Each scan writes a new folder under `scanent-out/runs/` and changes no older
one. To see what changed between two runs, put the two folder names in place
of `<older>` and `<newer>`:

```bash
scanent --network none -v "$PWD/scanent-out:/out:ro" "$IMAGE" \
  diff /out/runs/<older>/results.json /out/runs/<newer>/results.json
```

[read-the-report.md](read-the-report.md#comparing-two-runs) says how to read
the answer.

## Other ways to run it

The steps above are one scan, by hand, with Docker. The technical pages cover
the rest:

| You want | Read |
|---|---|
| The same steps with Podman instead of Docker | [../deployment.md](../deployment.md#rootless-docker-and-podman) |
| A scan every day, by itself, with Docker Compose | [../deployment.md](../deployment.md#on-a-schedule-with-compose) |
| To run it in Kubernetes | [../deployment.md](../deployment.md#kubernetes-with-helm) |
| To run it at a site with no internet access | [../deployment.md](../deployment.md#a-site-with-no-internet) |
| To go through a proxy, or to trust your own certificate authority | [../deployment.md](../deployment.md#proxy-and-certificate-authority) |
| Every command and every setting | [../scanner.md](../scanner.md) |

At a site with no internet access the scanner is loaded from a package you
carry in. A released package is signed. No release has been published yet,
so today that package is one you build yourself, and it carries no signature.
