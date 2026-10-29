# How to Recreate This Lab, Task by Task

This guide walks through the entire Threat Actor Attribution Lab from start to finish: what to do, which commands to run, and what you should see. Every command and number below was checked against the dataset that `make_case.py` generates.

**Time:** about 3 to 4 hours. **Cost:** $0. **Skill level:** a beginner who is comfortable with computers and willing to learn the Linux command line.

**How to get the most from it:** the "Expected result" lines let you check your work, but they also spoil the discoveries. Try each task, form your own conclusion, and only then compare.

> All data is synthetic. Every external IP address comes from the ranges reserved for documentation (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), so nothing here points at a real system.

---

## What you need

- An Ubuntu 22.04 virtual machine (or any Linux or macOS terminal) with Python 3. Check with `python3 --version`. I used 3.10.12.
- The standard tools `grep`, `awk`, `sort`, `uniq`, `cut`, `wc`, `sed`, and `nano`. Check with `which grep awk sort uniq cut wc sed nano`. Every one should print a path.
- A web browser, to read MITRE ATT&CK at `attack.mitre.org`.
- A free GitHub account, if you want to publish your own copy.
- A text editor for notes (VS Code, Notepad, or anything else).

If the VM has no internet and no clipboard sharing, do the research and note-taking on your own computer and keep the terminal work on the VM.

---

## Task 0: Set up your workspace (5 min)

```bash
mkdir -p ~/threat-actor-lab && cd ~/threat-actor-lab && pwd
```

`mkdir -p` creates the folder, `cd` moves into it, and `pwd` prints where you are. If you get "No such file or directory", check the spelling. A single missing hyphen is a classic cause.

Download the generator from this repository (`make_case.py` is in `threat-actor-lab-data/`), or clone the repo:

```bash
git clone https://github.com/phillipbcollier26/threat-actor-attribution-lab.git
cd threat-actor-attribution-lab/threat-actor-lab-data
```

**Safe-script habit:** before running any script, check what it can touch.

```bash
grep -nE "^import|^from|open\(|os\.|subprocess|socket" make_case.py
```

Expected: only imports of `os`, `random`, and `datetime`, one `os.makedirs` call, and one `open(` call. If you ever see `subprocess` or `socket` in a script, stop and find out why.

---

## Task 1: Write your profiles and predictions BEFORE seeing data (45 min)

This step matters most. Writing down what each actor *should* look like first keeps you from fitting a story to the data afterward.

1. Open `https://attack.mitre.org/groups/` and pick **two** groups: one state-sponsored and one financially motivated. I used APT28 (G0007) and INC Ransom (G1032).
2. For each group, write down its origin or sponsor, its motivation, three techniques with their `T####` IDs, and anything that suggests resources or patience. Open each technique's own page to confirm the ID.
3. Write a profile for each of five actor types: **nation-state, organized crime, hacktivist, unskilled attacker, insider threat**. Use these fields:

   ```
   - Internal/external:
   - Resources/funding:
   - Sophistication:
   - Motivations:        (use terms from Security+ objective 2.1)
   - Typical targets:
   - Real-world example: (with a source link, or label it a hypothetical)
   ```

4. Fill in a **Committed Predictions** table with one value per cell. No "can be" or "varies". Each cell is a bet you will score later.

   | Actor | Hours (business / after-hours / overnight) | Pace (burst / slow) | Source IPs (1 / few / many) | Noise (high / low) |
   |---|---|---|---|---|
   | Nation-state | | | | |
   | Organized crime | | | | |
   | Hacktivist | | | | |
   | Unskilled attacker | | | | |
   | Insider | | | | |

   Definitions: **volume** is how many events there are, and **noise** is how likely the activity is to stand out or trigger an alert.

5. Save everything in `actor-profiles.md` and don't change the table afterward.

**Why do this first?** Analysts do it to resist confirmation bias. Real analysts hedge in reports, but they start an investigation with a testable hypothesis.

---

## Task 2: Generate the case data (5 min)

```bash
python3 make_case.py
wc -l data/*
head -n 2 data/web_access.log data/auth_audit.log
```

Expected result:

```
6031 web lines; 990 auth lines
   990 data/auth_audit.log
  6031 data/web_access.log
  7021 total
```

The first web line should be `192.0.2.99 - - [12/Oct/2026:07:01:06 -0400] "GET /contact HTTP/1.1" 200 8051 ...`. If your counts differ, you changed the script or the seed (`random.seed(7)`).

**Don't read the actor sections of the script yet.** Treat it as an answer key you haven't earned.

**Log formats**

Web log, split into fields by `awk`:

| Field | Contents |
|---|---|
| `$1` | Source IP |
| `$4` | Timestamp, starting with `[` |
| `$6` | HTTP method, with a leading quote mark |
| `$7` | Path requested |
| `$9` | Status code (200 OK, 403 forbidden, 404 not found, 503 server unavailable) |
| `$10` | Response size in bytes |

Audit log:

| Field | Contents |
|---|---|
| `$1`, `$2` | Date and time |
| `$4` | Event type (`LOGIN_OK`, `LOGIN_FAIL`, `FILE_READ`, `FILE_RENAME`, `FILE_COPY`, `FILE_CREATE`) |
| `$5` | `user=<name>` |
| `$6` | `src=<IP>` for logins, or `path=<file>` for file events |

Addresses starting `10.20.0.` are inside the company network. Everything else is external.

**Pipeline rules you'll use all the time**

- `|` sends one command's output into the next command.
- `uniq -c` counts only *consecutive* duplicates, so **always `sort` first**.
- `sort -rn` sorts numerically, biggest first, and `head` keeps the first 10 lines.

---

## Task 3: Orient in the web log (20 min)

Run each of these from the folder that contains `data/`.

**3a. Top source IPs**

```bash
awk '{print $1}' data/web_access.log | sort | uniq -c | sort -rn | head
```

Expected: one IP, `203.0.113.197`, with **600** requests, while the next highest has 70.

**3b. Status codes**

```bash
awk '{print $9}' data/web_access.log | sort | uniq -c | sort -rn
```

Expected: 4,631 × 200, 800 × 503, 480 × 404, 120 × 403. Note that 404 and 403 are the *client's* behavior (asking for things that don't exist or aren't allowed), while 503 is the *server's* condition (it couldn't cope). Which part of the CIA triad does a 503 affect?

**3c. Busiest hours (date and hour)**

```bash
awk '{print $4}' data/web_access.log | cut -d: -f1,2 | sort | uniq -c | sort -rn | head
```

`cut -d: -f1,2` splits on colons and keeps the first two fields, which gives date and hour. Expected: **2,003** requests in `[16/Oct/2026:00`, then 625 at `[15/Oct/2026:15` and 620 at `[15/Oct/2026:12`, and then everything else is about 37 or fewer. Always keep the date with the hour.

**3d. User agents**

```bash
awk -F'"' '{print $6}' data/web_access.log | sort | uniq -c | sort -rn
```

`-F'"'` makes `awk` split on the quote character, so `$6` is the user agent. Expected: 3,430 Windows browser, 2,000 Linux Firefox, 600 `python-requests/2.28.1`, and 1 `curl/7.81.0`.

**Write down** two or three things that look abnormal, described in numbers. Don't name an actor type yet. An unusual spike isn't automatically an attack, so ask what harmless explanation each one could have.

---

## Task 4: Drill into the web anomalies (30 min)

**4a. Profile the 600-request IP**

```bash
grep '^203.0.113.197 ' data/web_access.log | wc -l
grep '^203.0.113.197 ' data/web_access.log | awk '{print $7}' | sort | uniq -c | sort -rn
grep '^203.0.113.197 ' data/web_access.log | awk '{print $9}' | sort | uniq -c
grep '^203.0.113.197 ' data/web_access.log | sed -n '1p;$p' | awk '{print $4}'
```

`^` anchors the match to the start of the line, and the trailing space stops it from also matching longer IPs. `sed -n '1p;$p'` prints the first and last lines.

Expected: 600 requests across 10 paths (60 each, for example `/wp-login.php`, `/server-status`, `/phpmyadmin`), 480 × 404 and 120 × 403, from `[15/Oct/2026:15:20:00` to `[15/Oct/2026:15:22:59`. That's about 3.3 requests per second. There isn't a single 200.

**4b. Profile the three spikes** (change the date and hour in `grep` for each one)

```bash
grep '16/Oct/2026:00' data/web_access.log | wc -l
grep '16/Oct/2026:00' data/web_access.log | awk '{print $1}' | sort -u | wc -l
grep '16/Oct/2026:00' data/web_access.log | awk '{print $9}' | sort | uniq -c
grep '15/Oct/2026:12' data/web_access.log | wc -l
grep '15/Oct/2026:12' data/web_access.log | awk '{print $1}' | sort -u | wc -l
```

`sort -u` removes duplicates, so `... | sort -u | wc -l` counts **distinct** values.

Expected:

| Spike | Requests | Distinct IPs | Status mix | Notes |
|---|---|---|---|---|
| `16/Oct 00:xx` | 2,003 | 302 | 1,203 × 200, 800 × 503 | One path (`/`), mostly one user agent |
| `15/Oct 12:xx` | 620 | 100 | all 200 | Varied shop pages, normal visitors |
| `15/Oct 15:xx` | 625 | 21 | 480 × 404, 120 × 403, 25 × 200 | 600 of these are the scanner |

The noon spike is a legitimate sales promotion, not an attack. The difference from the midnight flood is that the flood used one path, one identical user agent, and rising errors, while the sale used varied pages and ordinary visitors who all got 200s.

**Why didn't the midnight flood appear in the top-IPs list?** About 2,000 requests came from about 300 IPs, which is only 6 or 7 each. Counting per IP catches one noisy source, and counting per time window catches a distributed one. You need both views.

**4c. The single `curl` request**

```bash
awk -F'"' '{print $2}' data/web_access.log | awk '{print $1}' | sort | uniq -c
grep curl data/web_access.log
grep -c '^198.51.100.17 ' data/web_access.log
grep -c ' 1337 "' data/web_access.log
```

Expected: 6,030 `GET` and **1 `PUT`**. The `curl` line is `198.51.100.17`, `PUT /index.html`, status 200, size 1337, at `[16/Oct/2026:00:38:00`. That IP has 6 lines in the log, 5 of them part of the flood. `PUT` writes or replaces a resource, which an anonymous shop visitor never needs. Afterward `GET /` returns **1,337 bytes** (31 lines in the log have that size, the PUT plus 30 reads about every 10 minutes) instead of the normal 2,000 to 9,000, so the homepage changed. That's an integrity problem, and the 503s were an availability problem.

**4d. Timing of the flood**

```bash
grep ' 503 ' data/web_access.log | sed -n '1p;$p' | awk '{print $4}'
```

Expected: the first 503 at `[16/Oct/2026:00:25:00` and the last at `[16/Oct/2026:00:34:59`. The flood ran 00:10:00 to 00:34:59, and the PUT came about three minutes after it ended. The responses aren't random: the server held up for about 15 minutes, then failed.

---

## Task 5: Investigate the file server audit log (30 min)

**5a. Event types**

```bash
awk '{print $4}' data/auth_audit.log | sort | uniq -c | sort -rn
```

Expected: 337 `FILE_READ`, 306 `LOGIN_FAIL`, 250 `FILE_RENAME`, 60 `FILE_COPY`, 36 `LOGIN_OK`, 1 `FILE_CREATE`.

**5b. Failed logins per hour**

```bash
grep LOGIN_FAIL data/auth_audit.log | awk '{print $1, substr($2,1,2)}' | sort | uniq -c | sort -rn | head
```

`substr($2,1,2)` keeps the first two characters of the time (the hour). Expected: **300** in `2026-10-14 03`, and then single digits elsewhere.

Dig into the burst:

```bash
grep LOGIN_FAIL data/auth_audit.log | grep '^2026-10-14 03' | awk '{print $6}' | sort -u | wc -l
grep LOGIN_FAIL data/auth_audit.log | grep '^2026-10-14 03' | awk '{print $5}' | sort | uniq -c | sort -rn
grep LOGIN_FAIL data/auth_audit.log | grep '^2026-10-14 03' | sed -n '1p;$p' | awk '{print $1, $2}'
```

Expected: **136** distinct source IPs, **15** usernames, from 03:00:01 to 03:39:48. That's about 2 attempts per IP, which stays under a typical per-IP lockout threshold.

**5c. Successful logins from outside the network**

```bash
grep LOGIN_OK data/auth_audit.log | grep -v 'src=10\.20\.0\.'
```

`grep -v` inverts the match. Expected: 8 lines, one for `tpatel` at `2026-10-14 03:41:00` from `192.0.2.112` (an outside address, one minute after the burst ended) and seven for `svc_backup` from 3 different IPs between 01:02 and 03:44.

**5d. What did tpatel do next?**

```bash
grep 'user=tpatel' data/auth_audit.log | grep '^2026-10-14 03:[45]' | awk '{print $4}' | sort | uniq -c
```

Expected: 40 `FILE_READ`, 250 `FILE_RENAME`, and 1 `FILE_CREATE` (`/srv/shared/README_RESTORE.txt`). Each renamed file ends in `.locked`. All of it happens in about 16 minutes after the login. tpatel normally logs in between 08:00 and 10:00 from `10.20.0.42`.

**5e. Folder access by user**

```bash
grep FILE_READ data/auth_audit.log | awk '{split($6,p,"/"); print $5, p[3]}' | sort | uniq -c | sort -rn
```

`split($6, p, "/")` breaks `path=/srv/finance/doc3.xlsx` at each slash, so `p[3]` is the department folder. Then look at rlee's activity on 16 October:

```bash
grep 'user=rlee' data/auth_audit.log | grep '^2026-10-16' | grep FILE_READ | awk '{split($6,p,"/"); print p[3]}' | sort | uniq -c
grep FILE_COPY data/auth_audit.log | sed -n '1p;$p'
grep FILE_COPY data/auth_audit.log | awk '{print $7}' | sort | uniq -c
```

Expected: rlee read **77 finance** and **73 hr** files (plus 6 sales files), when his normal pattern is 4 to 8 sales reads per day. There are **60 `FILE_COPY`** events from 19:00:00 to 19:04:55, all copying finance files to `dest=/media/usb0`. His login came from his own workstation (`10.20.0.43`), so there is no strange IP and no failed login.

**5f. Compare `svc_backup` with its own baseline**

```bash
grep 'user=svc_backup' data/auth_audit.log | grep LOGIN_OK | awk '{print $1, $2, $6}'
grep 'user=svc_backup' data/auth_audit.log | grep LOGIN_OK | grep -c 'src=10.20.0.5'
grep 'user=svc_backup' data/auth_audit.log | grep LOGIN_OK | grep -vc 'src=10.20.0.5'
grep 'user=svc_backup' data/auth_audit.log | grep FILE_READ | awk '{split($6,p,"/"); print p[3]}' | sort | uniq -c
```

Expected: 14 logins in two groups of 7. One group is the normal pattern, 23:00 every night from the internal backup server `10.20.0.5`. The other group comes from **outside** at 01:02 to 03:44 from 3 IPs (`198.51.100.18`, `198.51.100.237`, `203.0.113.166`). The account also read 28 files, 18 in `contracts` and 10 in `engineering`, which a backup account has no reason to open. The signal is that the same account has two different behaviors.

---

## Task 6: Fill in the evidence table (15 min)

For each case, record first and last time, source IP count, event count, and the key evidence.

| Case | First / last time | Source IPs | Event count | Key evidence |
|---|---|---|---|---|
| 1. Midnight flood + PUT | 00:10:00 to 00:34:59; PUT at 00:38:00 | 300 | 2,000 `GET /`, 1 `PUT` | 800 × 503 from 00:25:00, one path, one user agent, page shrinks to 1,337 bytes |
| 2. 600-request scanner | 15:20:00 to 15:22:59 | 1 | 600 | Default `python-requests` agent, 10 paths, 480 × 404 and 120 × 403, no 200s |
| 3. Failed-login burst → tpatel | 03:00:01 to 03:57:00 (14 Oct) | 136 (plus the success from `192.0.2.112`) | 300 `LOGIN_FAIL`, 1 `LOGIN_OK`, 40 reads, 250 renames, 1 create | Only external tpatel login of the week; `.locked` files; `README_RESTORE.txt` |
| 4. rlee file activity | 18:30 to 19:05 (16 Oct) | 1, internal | 150 reads outside his department, 60 copies | Valid account from a trusted address; finance files to `/media/usb0` |
| 5. `svc_backup` external logins | 12 to 18 Oct, 01:02 to 03:44 | 3 external | 7 external logins, 28 reads | Normal login is internal at 23:00; extra external logins every night |

---

## Task 7: Assign actor types and score your predictions (35 min)

For each case, write down:

1. The **actor type**
2. The **motivation**, using a term from the objective 2.1 list
3. **Internal or external**, and your estimate of resources and sophistication
4. **Confidence** (high, medium, or low) and your **two strongest pieces of evidence**
5. **One thing that could make you wrong**

Then compare with the answer key:

| Case | Actor type |
|---|---|
| Midnight flood + PUT | Hacktivist |
| 600-request scanner | Unskilled attacker |
| Failed-login burst → tpatel | Organized crime |
| rlee file activity | Insider threat |
| `svc_backup` external logins | Nation-state |

Calibration tips:

- Use "consistent with" instead of "is" when the logs can't prove it. The logs show renames to `.locked`, not encryption itself, and they show a flood and a changed page, but not the message on it.
- "High" confidence should mean you've ruled out the alternatives.
- Don't claim a motive you can't see. The logs show data exfiltration for rlee, not revenge or greed.
- Logs show behavior, not identity.

**Score your Committed Predictions** one cell at a time (right or wrong, 4 cells per actor). For each miss, write one sentence explaining it **from the evidence** and not from what you think the attacker was thinking. My result was 14 out of 20. The cell I missed most often was Hours.

---

## Task 8: Write the attribution report (35 min)

Write for a manager, not a classmate. Use this structure:

```markdown
# Attribution Assessment: <case name>

## Summary          (3 to 4 sentences: who, which incidents matter most, what to do first)
## Findings         (one section per case: what happened, actor type, motivation,
                     internal/external, sophistication, confidence, evidence, what could make you wrong)
## Prediction scorecard
## Recommendations  (one specific control per case, tied to the evidence)
## Limitations      (only the sources you actually had, and what they cannot show)
```

Pick one control per case and explain why it fits that evidence. Candidates:

- Lock `svc_backup` to its one expected source address
- Disable `PUT` on the web server
- Rate limiting
- Account lockout across IPs, and multi-factor authentication
- USB and file-copy monitoring
- Least-privilege folder access
- Offline backups

For a possible insider, first preserve the logs and restrict the account, then hand the evidence to HR and legal. The employment decision isn't the analyst's call.

---

## Task 9: Publish (20 min)

1. Create a public GitHub repository and upload `make_case.py`, your notes, your profiles, your report, and a `README.md`.
2. You don't need to upload the log files, since anyone can regenerate them with the fixed seed.
3. Take 2 or 3 screenshots with Cmd+Shift+4 (macOS), cropped to just the terminal. Leave out browser tabs, your full name, and any lab URLs.
4. Check every file for personal details, then add a repository description and topics.
5. Test the instructions yourself: clone the repo into a fresh folder, run `python3 make_case.py`, and confirm you get 6,031 and 990 lines.

---

## Troubleshooting

| Problem | Likely cause and fix |
|---|---|
| `No such file or directory` | You're in the wrong folder. Run `pwd` and `ls` and check that `data/` is there |
| `uniq -c` counts look wrong | You forgot to `sort` first |
| `awk` prints nothing | Use straight single quotes around the program, and check the file path |
| `grep user=admin` also matches `administrator` | Anchor the pattern with a trailing space, as in `user=admin ` |
| Line counts don't match | You changed the script or its `random.seed(7)` line |
| `Permission denied` | Check you're in a folder you own |

## Optional extensions (not part of the core lab)

- Load the same logs into a free SIEM (Security Onion or Wazuh) and compare its alerts with your manual findings.
- Write detection rules for the two hardest cases: an internal user copying files to removable media, and a service account logging in from a new source.
- Change the seed or add a sixth actor to `make_case.py` and see whether you can still find everything.

## Security+ SY0-701 Objective 2.1 coverage

Threat actors (nation-state, unskilled attacker, hacktivist, insider threat, organized crime), attributes (internal or external, resources and funding, sophistication), and motivations (espionage, financial gain, data exfiltration, service disruption, philosophical or political beliefs).
