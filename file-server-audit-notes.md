# Authentication Audit Findings

## 1. Event Types

**Command used:**
```bash
awk '{print $4}' data/auth_audit.log | sort | uniq -c | sort -rn
```

**Event counts:**
- 337 FILE_READ
- 306 LOGIN_FAIL
- 250 FILE_RENAME
- 60 FILE_COPY
- 36 LOGIN_OK
- 1 FILE_CREATE

## 2. Failed Logins by Date

**Command used:**

**Failed logins per date:**
- 301 on Oct 14
- 3 on Oct 15
- 1 on Oct 16
- 1 on Oct 12

## 3. Failed Logins by Hour

**Command used:**
```bash
grep 'LOGIN_FAIL' data/auth_audit.log | awk '{print $1, substr($2,1,2)}' | sort | uniq -c | sort -rn
```

**Failed logins per hour:**
- 300 2026-10-14 03
- 1 2026-10-16 08
- 1 2026-10-15 13
- 1 2026-10-15 09
- 1 2026-10-15 08
- 1 2026-10-14 13 
- 1 2026-10-12 12

## 4. Distinct IP Addresses

**Command used:**
```bash
grep '2026-10-14 03' data/auth_audit.log | grep 'src' | awk '{print $6}' | sort -u | wc -l
```

**Number of distinct IP's:** 136

**Average attempts by IP:** Attempts were done 1 to 8 times.

## 5. Usernames Tried

- tpatel
- backup
- rlee
- guest
- accounting
- mhuges
- jsmith
- finance
- sales
- kwong
- hr
- administrator
- info
- test
- admin

## 6. Successful Logins

**LOGIN_OK's:**
- tpatel
- svc_backup
- rlee
- mhuges
- kwong

**Command used:**
```bash
grep '2026-10-14' data/auth_audit.log | grep 'LOGIN_OK' | awk {print $5, $6}' | sort | uniq -c | sort -rn
```

### Logins Not From 10.20.0.x

- tpatel 192.0.2.112
- svc_backup 198.51.100.237 (regular)

## 7. Anomaly

- tpatel 192.0.2.112

## 8. Suspicious Activity

The attacker logged in at 3:00 AM and read several files and then locked them. They then created a text file names readme restore all within 20 minutes of logging in successfully.

User rlee shows up to be looking folders that do not pertain to her department.

User rlee is also shown to be copying files from the finance departments to a potential flash drive!