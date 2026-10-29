I now have four leads: the 600-request IP, the hour 00 spike, the hour 15 spike, and the hour 12 spike, plus the curl request.

4 Leads:  
1. 600 request IP  
2. Network spike at hour 00  
3. Network spike at hour 15  
4. Single curl request  

### 1. 600 Request IP Lead

To dive deeper into this lead I used the command:  
`grep '^203.0.113.197 ' data/web_access.log | sort -u`

I selected the IP address that made 600 requests and looked at the log. What I found was highly concerning. The requests made by the flagged IP address were all made in a span of about 3 minutes, from 15:20:00 to 15:22:59, at approximately 3.3 requests per second.

The attempted destinations of these requests were admin, login, Git, and .env pages. This suggests that the fictional company was being targeted.

Next I used the command:  
`grep '^203.0.113.197 ' data/web_access.log | awk '{print $9}' | sort | uniq -c | sort -rn`

This allowed me to see how many HTTP status codes were given for requests from the targeted IP.

What I found was alarming. There were 480 HTTP 404 responses and 120 HTTP 403 responses from the targeted IP. The 404 responses mean the requested resources were not found, while the 403 responses mean access was forbidden. The evidence suggests that the IP was unsuccessful in accessing the targeted resources.

Another thing I noticed was that every request made by the suspicious IP address used the `python-requests/2.28.1` user agent. The rapid, consistent requests suggest automated scanning for weaknesses in the system.

### 2. Three Traffic Spikes

#### 1. 16/Oct/2026:00 -- 2,003 Requests

Commands used:  
`grep '16/Oct/2026:00' data/web_access.log | awk '{print $1}' | sort -u | wc -l`

`grep '16/Oct/2026:00' data/web_access.log | awk '{print $9}' | sort | uniq -c | sort -rn`

`grep '16/Oct/2026:00' data/web_access.log | awk -F'"' '{print $6}' | sort | uniq -c | sort -rn`

`grep '16/Oct/2026:00' data/web_access.log | awk '{print $7}' | sort | uniq -c | sort -rn`

`grep 'curl' data/web_access.log`

Requests: 2,003  
Distinct IPs: 302  
Status Codes: 1,203 × 200  
　　　　　　　800 × 503  
User Agents: 2,002 × Mozilla/5.0  
　　　　　　1 × curl/7.81.0  
Paths Requested: 2,002 × `/`  
　　　　　　　　1 × `/index.html`

Analysis: There was an abnormal spike in requests at `16/Oct/2026:00`. The traffic began at 00:10:00 and continued until 00:34:59. The first 503 response appeared at 00:25:00, after which the server continued returning errors. This suggests that the server was overwhelmed by the flood of requests.

After investigating the curl request, I found that it used the HTTP `PUT` method to write or replace `/index.html`. The request came from `198.51.100.17` at 00:38:00, with a status code of 200 and a response size of 1,337 bytes. The same IP also made five other requests during the midnight flood.

This is suspicious because the `PUT` request occurred shortly after the flood ended and came from an IP involved in the flood. An anonymous visitor to a public shopping website would not normally need to modify the homepage.

After the `PUT` request, the homepage began returning responses of only 1,337 bytes, much smaller than the normal page sizes of approximately 2,000–9,000 bytes. This suggests that the homepage content may have been changed without authorization.

The total of 2,003 requests consists of 2,000 flood requests, one `PUT` request, and two additional `GET /` requests at 00:45 and 00:55.

#### 2. 15/Oct/2026:15 -- 625 Requests

Commands used:  
`grep '15/Oct/2026:15' data/web_access.log | awk '{print $1}' | sort -u | wc -l`

`grep '15/Oct/2026:15' data/web_access.log | awk '{print $9}' | sort | uniq -c | sort -rn`

`grep '15/Oct/2026:15' data/web_access.log | awk -F'"' '{print $6}' | sort | uniq -c | sort -rn`

`grep '15/Oct/2026:15' data/web_access.log | awk '{print $7}' | sort | uniq -c | sort -rn`

Requests: 625  
Distinct IPs: 21  
Status Codes: 480 × 404  
　　　　　　　120 × 403  
　　　　　　　25 × 200  
User Agents: 600 × python-requests/2.28.1  
　　　　　　25 × Mozilla/5.0  
Paths Requested: Sensitive paths, including `/wp-login.php`, `/server-status`, `/phpmyadmin`, `/login`, `/.git/config`, `/backup.zip`, `/administrator`, and `/admin`, along with normal shopping paths.

Analysis: This hour includes the 600 requests from the single IP I investigated earlier. The IP appears to be searching the system for openings. It used Python automation to look for weaknesses and targeted sensitive files and administrative pages that should be protected. The 404 and 403 responses suggest that the requested resources were missing or access was forbidden.

#### 3. 15/Oct/2026:12 -- 620 Requests

Commands used:  
`grep '15/Oct/2026:12' data/web_access.log | awk '{print $1}' | sort -u | wc -l`

`grep '15/Oct/2026:12' data/web_access.log | awk '{print $9}' | sort | uniq -c | sort -rn`

`grep '15/Oct/2026:12' data/web_access.log | awk -F'"' '{print $6}' | sort | uniq -c | sort -rn`

`grep '15/Oct/2026:12' data/web_access.log | awk '{print $7}' | sort | uniq -c | sort -rn`

Requests: 620  
Distinct IPs: 100  
Status Codes: 620 × 200  
User Agents: 620 × Mozilla/5.0  
Paths Requested: Normal shopping pages

Analysis: This seems to be a busy period rather than malicious activity. The requests came from 100 distinct IPs, accessed normal shopping pages, and all received status 200. Unlike the midnight flood and the 600-request IP, there is no obvious evidence of automated scanning or server failure.

### 3. The curl Request

Analysis: The curl request should not be considered an administrative request to restore the system. It used `PUT /index.html`, came from `198.51.100.17` at 00:38:00, and received status 200. This IP also made five other requests during the midnight flood. After the PUT request, the homepage began returning a much smaller response size of 1,337 bytes. These findings suggest that the request may have been an unauthorized modification of the homepage.

### Benign Results

The traffic spike at October 15 at 12:00 appears to be benign.

**Benign Evidence:**  
Request spike at 12:00: The traffic involved 100 distinct IPs, normal shopping pages, and 620 successful HTTP responses. There is no obvious evidence of malicious activity.

### Malicious Results

The 600-request IP and the midnight traffic spike appear malicious. The curl request is also highly suspicious and appears connected to the midnight flood.

**Malicious Evidence:**

600 Request IP: The IP address made 600 requests using Python automation within approximately three minutes. It targeted sensitive administrative and configuration paths, receiving 480 HTTP 404 responses and 120 HTTP 403 responses.

00 Hour Spike: The midnight flood involved 2,000 requests from 300 sources, all targeting the homepage with the same user agent. The server began returning 503 errors at 00:25:00, suggesting that the traffic overwhelmed its capacity.

Curl Request: The `PUT /index.html` request came from an IP that also participated in the flood. It occurred shortly after the flood ended, and the homepage response size dropped to 1,337 bytes afterward. This suggests a possible unauthorized homepage modification.