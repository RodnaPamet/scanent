# Run it: from nothing to a first report

This page is the shortest path to a first report, using Docker. Docker is a
program that runs other programs in a sealed box called a container. The
scanner is delivered as such a box, called an image.

You need:

- a computer with Docker, that can reach the systems you want scanned;
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
export IMAGE=ghcr.io/rodnapamet/scanent:0.12.0
git clone https://github.com/RodnaPamet/scanent.git
docker build -f scanent/deploy/Dockerfile -t "$IMAGE" scanent
```

The first line gives the image a name. The other steps use that name.

If your network inspects encrypted traffic, the build needs your network's
certificate: [../quick-start.md](../quick-start.md#0-get-the-image) says how.

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

If you close the terminal, type steps 1 (first line only) and 2 again before
you continue.

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

```bash
scanent --env-file scanent/scanent.env \
  -v "$PWD/scanent:/etc/scanent:ro" -v "$PWD/scanent-out:/out" \
  "$IMAGE" doctor --config /etc/scanent/config.json
```

This is a rehearsal. It tries each access with the smallest read it can, and
prints one line for each check: `PASS`, `WARN`, `FAIL` or `SKIPPED`. A line
that fails says what to fix. It writes nothing and changes nothing.

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
| `FAIL read.permitted` | The credential works but lacks the read-only role the line names |
| `WARN write.absent` | The credential can change things. Replace it with one that cannot |

**If you scan agent code in folders**, give each folder to the scanner as
read-only, at the path you typed in step 3. Add this to the command above and
to the one in step 6, before `"$IMAGE"`, with your own folder on the left:

```
-v /srv/agents:/estate:ro
```

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
discoveredId,name,owner,purpose,autonomy,dataClass,reach,riskTier,riskAssessedOn
entra:sp:00000000-0000-0000-0000-000000000000,Invoice triage,finance-operations,Sorts incoming invoices into queues,human-approves,confidential,write,MEDIUM,2026-09-30
```

- `discoveredId` must be copied exactly.
- `name`, `owner` and `purpose` are required. `owner` can be a team: you do
  not have to write a person's name.
- The last five are optional, and an agent reaches level H1 only with all of
  them: how independent it is (`human-approves`, `human-reviews` or
  `autonomous`), how sensitive its data is (`public`, `internal`,
  `confidential` or `restricted`), what it can reach (`read-only`, `write` or
  `external`), its risk rating (`LOW`, `MEDIUM`, `HIGH` or `CRITICAL`) and the
  date of that rating, which must be within the 365 days before the scan.

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
