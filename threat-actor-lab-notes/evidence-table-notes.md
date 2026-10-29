# Which Archetype of Threat Actor Was Each Case?

## 1. Midnight flood: Hacktivist

The midnight flood is a hacktivist attack because the target was bringing a webpage down and replacing it with its own page. This page is likely a message promoting some cause that the hacktivist supports.

**Motivation:** Ideological reasons and beliefs

**Attributes:** Changing a web page

**Confidence:** High. Web page change, quick attack at night overwhelming the server

**What could I be wrong about:** It could be an unskilled hacker because I would guess that they used a bot to hit the server hard and gain access which could be done by an unskilled hacker.

### Evidence: Midnight flood + PUT (web log, 16 Oct)

- **Time:** Flood 00:10:00 to 00:34:59; PUT at 00:38:00.
- **Source IPs:** 300 flood sources; the PUT came from 198.51.100.17, one of the 300.
- **Event count:** 2,000 GET / requests; 1 PUT /index.html.
- **Key evidence:** All 2,000 requests hit one path with an identical user agent. The first 800-error stretch begins at 00:25:00 (800 × 503). The PUT returned 200 and size 1337, and GET / then returned 1,337 bytes about every 10 minutes until ~05:35 (30 more reads).

## 2. 600 request scanner: Unskilled attacker

This attack involved a python script cycling through sensitive paths, however the script was weak and hit with 404 and 403 errors and never gained access to the system

**Motivation:** Stealing sensitive info to sell or satisfaction of gaining entry to a system.

**Attributes:** Python script was used and did not work.

**Confidence:** High. The unskilled hacker simply used a python script to feel for weaknesses inside the system. However there were none that the script exploited and the server single handedly shut them down.

**What could I be wrong about:** It could be a hacktivist because of the bombardment of 600 requests trying to breach the system, however we have no way of knowing because they did not get it. The attacker not gaining access to the system is a key contributor to my belief that it was an unskilled attacker.

### Evidence: 600-request scanner (web log, 15 Oct)

- **Time:** 15:20:00 to 15:22:59 (about 3.3 req/s).
- **Source IPs:** 1 (203.0.113.197).
- **Event count:** 600 requests.
- **Key evidence:** User agent python-requests/2.28.1. It cycled through 10 sensitive paths (/admin, /.env, /.git/config, and so on): 480 × 404, 120 × 403, and no 200s, so it never found anything.

## 3. Failed-login burst: Cyber Crime Group

The burst of failed logins followed by a successful one and the encrypting of many important files, all in the span of 20 minutes and then a file named README_RESTORE.txt leads me to believe the the system was hit by a ransomware attack. Ransomware attacks are done for financial benefit, which is why cyber crime group is the obvious choice.

**Motivation:** Money

**Attributes:** Encrypted files and has a 'README_RESTORE' file that likely asks for money in exchange for restoring the files.

**Confidence:** High. Clearly for monetary gain, and well done (done in only a few minutes), indicating resources and experience

**What could I be wrong about:** It could be an unskilled attacker who got lucky and quickly encrypted files after logging into the system. This is unlikely due to the speed of the attack.

### Evidence: Failed-login burst → tpatel (audit log, 14 Oct)

- **Time:** Failures 03:00:01 to 03:39:48; success 03:41:00; renames 03:52:00 to ~03:56; note at 03:57:00.
- **Source IPs:** 136 distinct external IPs; the successful login came from 192.0.2.112.
- **Event count:** 300 LOGIN_FAIL (1 to 8 per IP, about 2 on average, 15 usernames; 29 of them against tpatel); then 1 LOGIN_OK, 40 FILE_READ, 250 FILE_RENAME, and 1 FILE_CREATE.
- **Key evidence:** The success is the only external login for tpatel all week (normally 08:00 to 09:59, from 10.20.0.42). Every file was renamed with .locked, and the created file is README_RESTORE.txt.

## 4. rlee file activity: Insider threat

The user rlee logged in normally, then accessed files outside of their department and copied them to a personal drive. This is strictly against organization policy and it is clear that this user needs to be investigated further.

**Motivation:** Revenge, personal gain

**Attributes:** Inside the company, normal user, accessing files that should not be accessed by user, copying files to personal drive

**Confidence:** High. The attack could have easily gone unnoticed since the user who took the information was already in the system legally and did not have to break into it like the others did.

**What could I be wrong about:** It could be a nation state group attack if the user secretly worked for another country however it would still be an insider threat.

### Evidence: rlee file activity (audit log, 16 Oct)

- **Time:** Login 18:30; reads 18:35:00 to ~19:00; copies 19:00:00 to 19:04:55.
- **Source IPs:** 1 internal IP (10.20.0.43, his usual workstation).
- **Event count:** 150 FILE_READ outside his department (77 finance, 73 hr); 60 FILE_COPY.
- **Key evidence:** Normally rlee reads 4 to 8 /srv/sales files per day and never touches finance or hr. All 60 copies were finance files to /media/usb0. The activity was after hours, but the login source and account were completely normal.

## 5. svc_backup external logins: Nation State

The nation state's attack was the hardest to uncover. It was covert, and used svc_backup which allowed them to sneak into the system undetected. Once there the attacker quietly read files and moved out without making much noise.

**Motivation:** Espionage

**Attributes:** Covert, quiet, hard to detect

**Confidence:** High. The attackers used the svc_backup to infiltrate the system which was not easily noticed due to the backup regularly requested from outside sources. This attack had the most sophistication making it clearly thr nation state.

**What could I be wrong about:** It could be a cyber crime group due to the sophistication of the attack however, since it does not seem to be done for financial purposes and only files were read and not changed or encrypted it believe it was a nation state attack.

### Evidence: svc_backup external logins (audit log, 12 to 18 Oct)

- **Time:** One login per night, 01:02 to 03:44.
- **Source IPs:** 3 distinct external IPs (198.51.100.18, 198.51.100.237, 203.0.113.166).
- **Event count:** 7 external LOGIN_OK and 28 FILE_READ (18 in /srv/contracts, 10 in /srv/engineering).
- **Key evidence:** The account’s normal pattern is 7 logins at 23:00 from 10.20.0.5 (the backup server). The 7 external logins come on top of that, so the same account is logging in from outside every night with a few reads each time. That is 14 logins in total, split evenly into two patterns.