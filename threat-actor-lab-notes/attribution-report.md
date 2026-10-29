# Attribution Assessment: Buckeye Ridge Weekend Incidents

## Summary

Between October 12 and 18, Buckeye Ridge was hit by five separate incidents from five different kinds of attackers. The logs show a hacktivist-style flood and defacement of our website, an organized crime attack that took over tpatel's account and renamed 250 files, an insider (rlee) copying finance files to a removable drive, a basic scanner that found nothing, and the svc_backup account logging in from outside our network every night. My top priorities are containing the attacks that may still be active (the tpatel account and the svc_backup logins) and limiting rlee's access while the situation is reviewed. The website needs to be restored and fixed so the same change can't happen again.

## Findings

### 1. Midnight flood and website change: Hacktivist

On October 16 from 00:10 to 00:34, about 300 different IP addresses sent 2,000 requests to the homepage (`/`) using the same user agent. The server started returning 503 errors at 00:25 and kept failing until the flood stopped. At 00:38, `198.51.100.17`, one of the flood IPs, sent a `PUT /index.html` request that the server accepted (status 200). After that, `GET /` returned 1,337 bytes instead of the normal 2,000 to 9,000, until about 05:35. I think the page was replaced with the attacker's own content, and a message promoting some cause fits a hacktivist.

**Motivation:** Philosophical/political beliefs, with service disruption as the method

**Internal/external:** External

**Resources and sophistication:** Moderate. Coordinating about 300 sources takes some organization, but the page change only worked because the server accepted an unauthenticated PUT.

**Confidence:** Medium. The logs show a flood and a changed page, but I can't see what the new page said.

**What could I be wrong about:** It could be an unskilled attacker using a bot, since the PUT would have worked for anyone. Having 300 coordinated sources makes that less likely, but I can't rule it out.

### 2. 600 request scanner: Unskilled attacker

On October 15 from 15:20:00 to 15:22:59, a single IP (`203.0.113.197`) sent 600 requests, about 3.3 per second, using the default `python-requests/2.28.1` user agent. It cycled through the same 10 sensitive paths (`/admin`, `/.env`, `/.git/config`, and so on) over and over. It got 480 "not found" and 120 "forbidden" responses, and never got a single success.

**Motivation:** Unclear. Probably looking for an easy way in, to steal data or just to get access.

**Internal/external:** External

**Resources and sophistication:** Low. One IP, a default tool signature, a fixed list, and no attempt to slow down or hide.

**Confidence:** High. Everything in the pattern points to a script running without any tuning.

**What could I be wrong about:** It could be a hacktivist or a more skilled attacker doing quick reconnaissance. Since the scan got nothing, I have no way to tell what the attacker would have done next. The server didn't block the scan. It answered all 600 requests, and the attack only failed because there was nothing to find.

### 3. Failed-login burst: Organized crime

On October 14 from 03:00 to 03:39, there were 300 failed logins from 136 different IPs trying 15 usernames, with each IP making only 1 to 8 attempts. At 03:41, someone logged in as tpatel from `192.0.2.112`, which was tpatel's only external login all week (normally 08:00 to 10:00 from `10.20.0.42`). The account read 40 files, then renamed 250 files with the `.locked` ending in about four minutes (03:52 to 03:56), and created `README_RESTORE.txt` at 03:57. This is consistent with a ransomware attack.

**Motivation:** Financial gain

**Internal/external:** External

**Resources and sophistication:** High. Spreading attempts across 136 IPs keeps each one below a normal lockout threshold, and the whole attack after login took less than 20 minutes.

**Confidence:** High that it was a deliberate, financially motivated attack. The logs show the renames, not the encryption itself, and I can't see what the note says.

**What could I be wrong about:** It could be an unskilled attacker who got lucky, but the number of IPs and the speed make that unlikely.

### 4. rlee file activity: Insider threat

On Friday, October 16, rlee logged in at 18:30 from his usual workstation (`10.20.0.43`). Between 18:35 and about 19:00, the account read 150 files in the finance and hr folders, which it never touches (rlee normally reads 4 to 8 sales files a day). From 19:00 to 19:05 it copied 60 finance files to `/media/usb0`, a removable drive.

**Motivation:** Unknown. The logs show data being exfiltrated but not why.

**Internal/external:** Internal

**Resources and sophistication:** Low, but rlee already has legitimate access, so no technical skill was needed.

**Confidence:** High that this activity came from rlee's account and is a real deviation from his normal behavior. Medium that rlee himself is responsible and acting maliciously.

**What could I be wrong about:** Someone else could have been using rlee's workstation or account, or he could have an approved reason I don't know about. It could also be a nation-state or other outside actor working through an insider, but it would still be an insider threat from our side. This type of activity never fails a login or comes from a strange IP, so a blocklist or a failed-login alert wouldn't catch it.

### 5. svc_backup external logins: Nation-state

The svc_backup account normally logs in once a night at 23:00 from `10.20.0.5` (the backup server). On top of that, from October 12 to 18, it logged in from outside the network every night between 01:02 and 03:44, using 3 different IPs (`198.51.100.18`, `198.51.100.237`, `203.0.113.166`). Each session read 2 to 5 files in `/srv/contracts` and `/srv/engineering`, 28 files in total. Nothing was changed, encrypted, or copied that the logs show.

**Motivation:** Espionage

**Internal/external:** External

**Resources and sophistication:** High. Using a valid service account, staying quiet for a week, and keeping the volume low is patient, careful behavior.

**Confidence:** Medium. This is consistent with a nation-state, but the logs don't say who is behind it.

**What could I be wrong about:** It could be an organized crime group doing reconnaissance before a later attack, or any attacker who stole that account's password. The logs only show that someone had valid credentials and used them from outside.

## Prediction scorecard

I made these predictions before looking at any data. Each actor has four cells (Hours, Pace, Source IPs, Noise).

\| Actor              | Hours      | Pace| Source IPs| Noise|

\|                    |            |     |           |      |

\| Nation-state       |Business    |Slow |Few        |Low   | 2/4

\| Organized crime    |After-hours |Burst|Many       |High  | 4/4

\| Hacktivist         |Overnight   |Burst|Many       |High  | 4/4

\| Unskilled attacker |After-hours |Slow |1          |High  | 2/4

\| Insider            |Business    |Slow |1          |Low   | 2/4

**Total: 14/20.** Hours was the cell I missed most often.

**What I got wrong:**

- **Nation-state (Hours):** The logins were overnight (01:02 to 03:44), not business hours. I can't tell why from the logs. It could be the attackers' time zone or avoiding daytime staff, but that's a guess.
- **Organized crime (Hours):** I predicted after-hours and the attack was at 03:00, which I defined as overnight, so I'm counting it wrong.
- **Unskilled attacker (Hours and Pace):** The scan was at 15:20 during business hours and finished in three minutes. Nothing in the logs shows any effort to hide. It looks like a script running at full speed.
- **Insider (Hours and Pace):** The activity was at 18:30 to 19:05 (after hours), and it was a burst of about 210 events in 35 minutes compared to a normal 4 to 8 reads a day. I can't tell from the logs whether he picked that time on purpose.

## Recommendations

My first steps are to preserve the logs, bring in outside incident response help if we don't have any, and report the ransomware attack to law enforcement. After that, one control for each case:

1. **tpatel / ransomware:** Disable and reset tpatel's account, check what was renamed, and restore from offline backups. Add account lockout across IPs (not just per IP), multi-factor authentication, and alerts on mass file renames.
2. **svc_backup:** Reset its credentials and restrict it to log in only from `10.20.0.5`. Then review what the external sessions could access.
3. **rlee:** Restrict his access to finance and hr folders while it's reviewed, and give the evidence to management, HR, and legal, who decide what happens next. Block or monitor USB copying and limit folder access by department.
4. **Website:** Restore `index.html`, disable the `PUT` method, and add rate limiting for the flood.
5. **Scanner:** Rate limit or block IPs that make many requests that return 404 or 403. This is lower priority because the scan found nothing.

After that I recommend a full security review, including password changes and better protection of critical documents.

## Limitations

These logs show behavior, not identity. I can see what happened but not who is behind it, and motivation is inferred. Sophistication is hard to measure from logs alone. I only had two sources, the web access log and the file server audit log. I did not have firewall, endpoint, or email logs, so I can't see the content of the changed web page, the files after they were renamed, or the ransom note. rlee's activity is unusual but not proven to be malicious. The data in this lab is synthetic and the IP addresses come from reserved documentation ranges.
