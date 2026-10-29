import os
import random
from datetime import datetime, timedelta

random.seed(7)
START = datetime(2026, 10, 12)  # a Monday
web, auth = [], []


def t(day, hour, minute=0, sec=0):
    return START + timedelta(days=day, hours=hour, minutes=minute, seconds=sec)


def w(when, ip, method, path, status, size, ua):
    line = f'{ip} - - [{when:%d/%b/%Y:%H:%M:%S} -0400] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'
    web.append((when, line))


def a(when, event, detail):
    auth.append((when, f"{when:%Y-%m-%d %H:%M:%S} fileserver01 {event} {detail}"))


# Fake internet addresses from the documentation ranges (safe, never routed)
pool = [f"{p}.{i}" for p in ("192.0.2", "198.51.100", "203.0.113") for i in range(1, 255)]
random.shuffle(pool)
customers = pool[:100]
A1_IPS = pool[100:250]
A4_IPS = pool[250:550]
A5_IPS = pool[550:553]
A3_IP = pool[553]

# ---------- Normal business activity ----------
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
pages = ["/", "/shop", "/shop/boots", "/shop/tents", "/about", "/contact", "/cart"]
for d in range(7):
    for _ in range(400):
        w(t(d, random.randint(7, 22), random.randint(0, 59), random.randint(0, 59)),
          random.choice(customers[:60]), "GET", random.choice(pages), 200, random.randint(2000, 9000), UA)
for _ in range(600):  # a Thursday sales promotion at lunchtime
    w(t(3, 12, random.randint(0, 20), random.randint(0, 59)),
      random.choice(customers), "GET", random.choice(pages[:4]), 200, random.randint(2000, 9000), UA)

staff = {"mhughes": ("10.20.0.41", "finance"), "tpatel": ("10.20.0.42", "hr"),
         "rlee": ("10.20.0.43", "sales"), "kwong": ("10.20.0.44", "engineering")}
for d in range(5):
    for u, (ip, dept) in staff.items():
        start = t(d, random.randint(8, 9), random.randint(0, 59))
        a(start, "LOGIN_OK", f"user={u} src={ip}")
        for _ in range(random.randint(3, 8)):
            a(start + timedelta(minutes=random.randint(1, 400)), "FILE_READ",
              f"user={u} path=/srv/{dept}/doc{random.randint(1, 60)}.xlsx")
for d in range(7):
    a(t(d, 23), "LOGIN_OK", "user=svc_backup src=10.20.0.5")
for _ in range(6):
    a(t(random.randint(0, 4), random.randint(8, 17), random.randint(0, 59)), "LOGIN_FAIL",
      f"user={random.choice(list(staff))} src=10.20.0.{random.randint(41, 44)}")

# ---------- Actor 1 ----------
names = ["admin", "administrator", "jsmith", "accounting", "backup", "mhughes", "tpatel",
         "rlee", "kwong", "info", "sales", "hr", "finance", "test", "guest"]
for _ in range(300):
    a(t(2, 3, random.randint(0, 39), random.randint(0, 59)), "LOGIN_FAIL",
      f"user={random.choice(names)} src={random.choice(A1_IPS)}")
a(t(2, 3, 41), "LOGIN_OK", f"user=tpatel src={A1_IPS[0]}")
for i in range(40):
    a(t(2, 3, 45, i), "FILE_READ", f"user=tpatel path=/srv/shared/file{i}.docx")
for i in range(250):
    a(t(2, 3, 52, i), "FILE_RENAME",
      f"user=tpatel path=/srv/shared/file{i}.docx new=/srv/shared/file{i}.docx.locked")
a(t(2, 3, 57), "FILE_CREATE", "user=tpatel path=/srv/shared/README_RESTORE.txt")

# ---------- Actor 2 ----------
a(t(4, 18, 30), "LOGIN_OK", "user=rlee src=10.20.0.43")
for i in range(150):
    a(t(4, 18, 35, i * 10), "FILE_READ",
      f"user=rlee path=/srv/{random.choice(['finance', 'hr'])}/file{i}.xlsx")
for i in range(60):
    a(t(4, 19, 0, i * 5), "FILE_COPY",
      f"user=rlee path=/srv/finance/file{i}.xlsx dest=/media/usb0")

# ---------- Actor 3 ----------
probe = ["/admin", "/wp-login.php", "/phpmyadmin", "/.env", "/config.php",
         "/backup.zip", "/login", "/administrator", "/server-status", "/.git/config"]
for i in range(600):
    p = probe[i % len(probe)]
    w(t(3, 15, 20) + timedelta(milliseconds=i * 300), A3_IP, "GET", p,
      403 if p in ("/server-status", "/.git/config") else 404, 512, "python-requests/2.28.1")

# ---------- Actor 4 ----------
FUA = "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0"
for i in range(2000):
    w(t(4, 0, 10) + timedelta(seconds=i * 0.75), random.choice(A4_IPS), "GET", "/",
      200 if i < 1200 else 503, 4096 if i < 1200 else 0, FUA)
w(t(4, 0, 38), A4_IPS[0], "PUT", "/index.html", 200, 1337, "curl/7.81.0")
for i in range(30):
    w(t(4, 0, 45) + timedelta(minutes=i * 10), random.choice(customers[:60]), "GET", "/", 200, 1337, UA)

# ---------- Actor 5 ----------
for d in range(7):
    s = t(d, random.randint(1, 4), random.randint(0, 59))
    a(s, "LOGIN_OK", f"user=svc_backup src={random.choice(A5_IPS)}")
    for k in range(random.randint(2, 5)):
        a(s + timedelta(minutes=10 * (k + 1)), "FILE_READ",
          f"user=svc_backup path=/srv/{random.choice(['engineering', 'contracts'])}/spec{random.randint(1, 40)}.pdf")

# ---------- Write the files ----------
os.makedirs("data", exist_ok=True)
for name, rows in (("web_access.log", web), ("auth_audit.log", auth)):
    with open(f"data/{name}", "w") as f:
        for _, line in sorted(rows, key=lambda r: r[0]):
            f.write(line + "\n")
print(len(web), "web lines;", len(auth), "auth lines")
