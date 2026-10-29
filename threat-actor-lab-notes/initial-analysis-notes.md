# Web Access Log Analysis Notes

## 1. Top Source IP Addresses

**Command:**
```bash
awk '{print $1}' data/web_access.log | sort | uniq -c | sort -rn | head
```

This command showed me the top 10 IP source IP addresses. 

The only abnormality I noticed was that line one of the top 10 began with 600 which was significantly higher than all other IP's.

**Abnormality:**
- 1 - 600 203.0.113.197 (this means that IP has made 600 requests)

## 2. HTTP Status Codes

**Command:**
```bash
awk '{print $9}' data/web_access.log | sort | uniq -c | sort -rn | head
```

Because of $9, this command shows me how many times each status code was appeared in the log. 

HTTP status code (200 = OK, 404 = not found, 403 = forbidden, 503 = server unavailable)

- 4631 instances of 200,
- 800 instances of 503,
- 480 instances of 404,
- 120 instances of 403

This is strange to me because I would have expected near random number for 503, 404, and 403. This would appear to me that there were a preset or targeted number of guesses that ended in error. 

**Abnormality:** Large numbers of error codes indicating an attacker was testing the network to see what would stick.

## 3. Busiest Hours

**Command:**
```bash
awk '{print $4}' data/web_access.log | sort | uniq -c | sort -rn | head
```

This command showed me the fictional organization's busiest hours. Which are (Number 1: How many times there is a log at that hour. Number 2: The hour):

- 2003 00,
- 625 15,
- 620 12,
- 37 20, 
- 37 14, 
- 37 22, 
- 37 18, 
- 36 17, 
- 34 14, 
- 33 22

I notice that 00 has a shocking 2003 logs which is drastically different from second place with 625. I also notice that the top 3 busier hours are significantly busier than the rest of the top 10. 

**Abnormality:** There is a massive spike in the hours 00, 15, 12.

## 4. User-Agent Requests

**Command:**
```bash
awk -F'"' '{print $6}' data/web_access.log | sort | uniq -c | sort -rn | head
```

This command told me how many requests each user agent made.

There were:
- 3430 Mozilla Windows requests
- 2000 Mozilla Linux Requests
- 600 Python requests
- 1 curl request

A single curl request stuck out to me. I am not yet sure what a curl request does, however there being a single on is striking to me and raises a red flag.