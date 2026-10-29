# Vulnerable Lab Environment - Setup Guide

| CVE | Component | Pinned vulnerable version | Fixed in |
|-----|-----------|---------------------------|----------|
| CVE-2026-93546 | Apache HTTP Server (`mod_dav_fs`) | 2.4.68 | 2.4.69 |
| CVE-2026-19553 | CPython (`ssl` module) | 3.13.15 | 3.13.16 |
| CVE-2026-44172 | MariaDB Connector/C (`libmariadb`) | 3.4.8 | 3.4.9 |

**Companion files in this package:**
- `setup-lab.sh` - automated installer that performs this entire guide in one run (see below).
- `site/index.php`, `site/search.php` - the sample PHP site (§5).
- `db_client.c` - a C client linked against the pinned 3.4.8 connector (§5b), the piece that
  makes the MariaDB CVE actually demonstrable rather than just configured.
- `cve-reading-list.md` - curated advisories, patch commits, and background papers for the
  vulnerabilities and their mitigations.

> **Repo layout note:** the `site/` folder here just holds the PHP sources for browsing and
> reference. The setup - whether you run `setup-lab.sh` or follow the manual steps - writes its
> own copies of these files to `~/lab-site/` on the VM at install time and serves them from
> there. So the repo layout is independent of where the app actually runs; moving the sources
> around in the repo doesn't change the setup. If you prefer to serve the repo copies directly,
> `cd` into `site/` and run `php -S 127.0.0.1:8000` from there instead.

---

## Quick path: the automated installer (easiest and recommended)

If you'd rather not run every step by hand, `setup-lab.sh` does the whole guide - base deps,
all three from-source builds, WebDAV config, the database + seed data, the PHP site, and the C
client - then prints a verification summary. It is **resumable** (re-run it and it skips steps
that already succeeded) and asks for confirmation before it starts.

```bash
chmod +x setup-lab.sh
./setup-lab.sh            # full run
./setup-lab.sh --verify   # just re-run the verification checks
```

It needs internet while it runs (to download the pinned sources), so run it *before* switching
the VM to host-only networking. The manual steps below remain the reference for understanding
what each part does, and for troubleshooting if a build fails.

---

## 0. Safety & isolation (IMPORTANT!!!!!)
1. **Networking:** In VirtualBox/VMware, set the VM network adapter to **Host-Only** (or
   **Internal Network**). This lets your host reach the VM for the demo but keeps the vulnerable
   services off the internet and your LAN.
   - You'll need internet *temporarily* to download/build the pinned versions. Do that first on a
     NAT adapter, then switch to Host-Only before running anything. Or download, then `apt-mark hold`.
2. **Snapshot:** Once everything is installed and verified, take a VM snapshot named
   `lab-ready`. If a demo breaks the box, revert in seconds.
3. **Hold packages** so `apt upgrade` can't silently patch your vulnerable versions:
   ```bash
   sudo apt-mark hold apache2 libapache2-mod-* 2>/dev/null || true
   ```
4. **Never** put real data, real credentials, or personal files on this VM.

---

## 1. Base packages

```bash
sudo apt update
sudo apt install -y build-essential wget curl git \
  libssl-dev libpcre3-dev libxml2-dev zlib1g-dev libapr1-dev libaprutil1-dev \
  libffi-dev libsqlite3-dev libbz2-dev libreadline-dev
```

---

## 2. CVE-2026-93546 - Apache HTTP Server 2.4.68 (mod_dav_fs)

This flaw is an integer overflow in `mod_dav_fs`, reachable by an **authenticated WebDAV client
with write access** via PROPPATCH requests. So the demo environment needs: Apache 2.4.68 + WebDAV
enabled + an auth-protected WebDAV directory that's writable.

### 2a. Build Apache 2.4.68 from source (pinned)

Kali's repo Apache will be too new, so build the exact version into `/opt` to keep it separate
from the system.

```bash
cd /usr/local/src
sudo wget https://archive.apache.org/dist/httpd/httpd-2.4.68.tar.gz
sudo tar xzf httpd-2.4.68.tar.gz
cd httpd-2.4.68

sudo ./configure --prefix=/opt/httpd-2.4.68 \
  --enable-dav --enable-dav-fs --enable-dav-lock \
  --enable-so --enable-rewrite --enable-ssl
sudo make -j"$(nproc)"
sudo make install
```

Verify the version:
```bash
/opt/httpd-2.4.68/bin/httpd -v     # should print 2.4.68
/opt/httpd-2.4.68/bin/httpd -M | grep dav   # confirm dav_module + dav_fs_module loaded
```

### 2b. Configure a writable, authenticated WebDAV location

Append to `/opt/httpd-2.4.68/conf/httpd.conf` (modules may already be built-in; if `-M` showed
them, skip the LoadModule lines):

```apache
# WebDAV lab share
DavLockDB "/opt/httpd-2.4.68/var/DavLock"
Alias /webdav "/opt/httpd-2.4.68/htdocs/webdav"

<Directory "/opt/httpd-2.4.68/htdocs/webdav">
    Dav On
    AuthType Basic
    AuthName "webdav-lab"
    AuthUserFile "/opt/httpd-2.4.68/conf/.davpasswd"
    Require valid-user
</Directory>
```

Create the directory, lock DB dir, and a lab user:
```bash
sudo mkdir -p /opt/httpd-2.4.68/htdocs/webdav /opt/httpd-2.4.68/var
sudo chown -R daemon:daemon /opt/httpd-2.4.68/htdocs/webdav /opt/httpd-2.4.68/var
# create WebDAV user 'labuser' (you'll be prompted for a password)
sudo /opt/httpd-2.4.68/bin/htpasswd -c /opt/httpd-2.4.68/conf/.davpasswd labuser
# the automated script instead sets it non-interactively with the lab password 'labpass':
# sudo /opt/httpd-2.4.68/bin/htpasswd -bc /opt/httpd-2.4.68/conf/.davpasswd labuser labpass
```

Start it (on a non-standard port so it doesn't clash with anything):
```bash
sudo /opt/httpd-2.4.68/bin/apachectl -k start
# tail logs: /opt/httpd-2.4.68/logs/error_log
```

**Verify WebDAV is live and writable** (this is a normal WebDAV operation, not an exploit):
```bash
# upload a test file via WebDAV using the lab creds
curl -u labuser:labpass -T /etc/hostname http://localhost/webdav/test.txt
# list it back
curl -u labuser:labpass http://localhost/webdav/
```
If `test.txt` appears, the vulnerable surface (authenticated WebDAV write) is correctly exposed
for your demo.

---

## 3. CVE-2026-19553 - Python 3.13.15 (ssl module)

This is unrelated to the web stack - it's a hostname-verification bypass in CPython's `ssl`
module (`SSLContext.wrap_bio()`). Build 3.13.15 as a **separate interpreter** so you don't touch Kali's system Python.

```bash
cd /usr/local/src
sudo wget https://www.python.org/ftp/python/3.13.15/Python-3.13.15.tgz
sudo tar xzf Python-3.13.15.tgz
cd Python-3.13.15

sudo ./configure --prefix=/opt/python-3.13.15 --with-openssl=/usr --enable-optimizations
sudo make -j"$(nproc)"
sudo make altinstall      # altinstall = does NOT overwrite /usr/bin/python3
```

Verify:
```bash
/opt/python-3.13.15/bin/python3.13 --version    # Python 3.13.15
/opt/python-3.13.15/bin/python3.13 -c "import ssl; print(ssl.OPENSSL_VERSION)"
```

Make a venv for any demo scripts:
```bash
/opt/python-3.13.15/bin/python3.13 -m venv ~/cve-19553-venv
source ~/cve-19553-venv/bin/activate
```

That gives you a pinned 3.13.15 interpreter with the vulnerable `ssl` behavior present. (The official note for this CVE is that the fix is a behavior change in `wrap_bio`; 3.13.15 predates it.)

---

## 4. CVE-2026-44172 - MariaDB Connector/C 3.4.8 (libmariadb)

Key point: the vulnerability is in the **client library** (`libmariadb` / Connector/C), in
`mysql_real_escape_string()` mishandling the `big5` charset - *not* in the MariaDB server. So you
need: a MariaDB server (any recent version is fine) + Connector/C **3.4.8** pinned + an app that
connects using the `big5` charset and escapes input with that function.

### 4a. MariaDB server (for the app to talk to)

```bash
sudo apt install -y mariadb-server
sudo systemctl start mariadb
sudo mysql -e "CREATE DATABASE labdb; \
  CREATE USER 'labapp'@'localhost' IDENTIFIED BY 'labpass'; \
  GRANT ALL ON labdb.* TO 'labapp'@'localhost'; \
  FLUSH PRIVILEGES;"
sudo mysql labdb -e "CREATE TABLE users(id INT, name VARCHAR(64), secret VARCHAR(64)); \
  INSERT INTO users VALUES (1,'alice','flag_alpha'),(2,'bob','flag_bravo');"
```
Set the server's charset so the big5 path is exercisable:
```bash
sudo mysql -e "SHOW VARIABLES LIKE 'character_set%';"
```

### 4b. Build Connector/C 3.4.8 from source (pinned)

```bash
cd /usr/local/src
sudo git clone --branch v3.4.8 --depth 1 \
  https://github.com/mariadb-corporation/mariadb-connector-c.git mcc-3.4.8
cd mcc-3.4.8
sudo mkdir build && cd build
sudo cmake .. -DCMAKE_INSTALL_PREFIX=/opt/libmariadb-3.4.8
sudo make -j"$(nproc)"
sudo make install
```
Verify the pinned version:
```bash
ls /opt/libmariadb-3.4.8/lib/mariadb/
/opt/libmariadb-3.4.8/bin/mariadb_config --version 2>/dev/null || true
```

Any C or PHP program you build against `/opt/libmariadb-3.4.8` will use the vulnerable escaping
routine. (See §5 for wiring PHP to it - note the caveat there.)

---

## 5. Sample PHP site

A minimal PHP app that (a) serves normally, and (b) exposes a DB-query page that connects with the
`big5` charset - the configuration relevant to the MariaDB CVE.

### 5a. PHP + a lightweight server
```bash
sudo apt install -y php php-mysql php-cli
mkdir -p ~/lab-site && cd ~/lab-site
```

Create `~/lab-site/index.php`:
```php
<?php
// Lab landing page
echo "<h1>CVE Lab Demo Site</h1>";
echo "<ul>";
echo "<li><a href='search.php?name=alice'>User lookup (big5 charset demo)</a></li>";
echo "</ul>";
```

Create `~/lab-site/search.php`:
```php
<?php
// Demo query page. Connects using big5 charset - the setting relevant to CVE-2026-44172.
$mysqli = new mysqli("127.0.0.1", "labapp", "labpass", "labdb");
if ($mysqli->connect_errno) { die("DB connect failed: " . $mysqli->connect_error); }

// Set big5 - this is the charset involved in the Connector/C escaping bug.
$mysqli->set_charset("big5");

$name = $_GET['name'] ?? '';
$escaped = $mysqli->real_escape_string($name);   // the function at the center of the CVE
$sql = "SELECT id, name FROM users WHERE name = '$escaped'";

echo "<p>Query: " . htmlspecialchars($sql) . "</p>";
$res = $mysqli->query($sql);
if ($res) {
    while ($row = $res->fetch_assoc()) {
        echo "Found: #{$row['id']} {$row['name']}<br>";
    }
} else {
    echo "Query error: " . htmlspecialchars($mysqli->error);
}
```

Run it:
```bash
cd ~/lab-site
php -S 127.0.0.1:8000
# browse to http://127.0.0.1:8000/
```

> **Caveat on PHP + the pinned connector:** distro PHP links against its own bundled `mysqlnd`/
> `libmariadb`, so by default it won't use your `/opt/libmariadb-3.4.8` build. Getting PHP to use
> the *exact* pinned 3.4.8 requires either compiling PHP `--with-mysqli=/opt/libmariadb-3.4.8` or
> writing a small **C program** linked against it (see §5b). For a cleaner "exact version"
> demonstration of this specific CVE, a tiny C client against `/opt/libmariadb-3.4.8` is the most
> faithful. If your instructor only needs the big5/charset configuration shown in a PHP app, the
> above is fine. Ask which they expect - it changes whether you need to recompile PHP.

### 5b. C client linked against the pinned connector (the faithful target)

Because the PHP site uses PHP's *own* bundled connector, the pinned 3.4.8 build isn't actually
in its path. The C client closes that gap: it links explicitly against `/opt/libmariadb-3.4.8`,
so it genuinely exercises the vulnerable escaping routine. `db_client.c` is included in this
package (the automated script also writes and compiles it). It mirrors `search.php` - connects
with the `big5` charset and escapes input with `mysql_real_escape_string()` - and prints the
escaped bytes so the behavior is visible. It is a **target app only**; it contains no attack
payload and takes the lookup name as an argument.

Compile it against the pinned connector (paths may vary slightly by build layout):
```bash
INC=$(dirname "$(find /opt/libmariadb-3.4.8 -name mysql.h | head -1)")
LIB=$(dirname "$(find /opt/libmariadb-3.4.8 -name 'libmariadb.so*' | head -1)")
gcc ~/lab-site/db_client.c -o ~/lab-site/db_client \
  -I"$INC" -L"$LIB" -lmariadb -Wl,-rpath,"$LIB"
```

Run it (benign usage) and confirm it's linked to 3.4.8:
```bash
~/lab-site/db_client alice          # 'client library' line in the output shows the version
ldd ~/lab-site/db_client | grep mariadb   # confirms it loads /opt/libmariadb-3.4.8
```

The `-Wl,-rpath` flag bakes in the path so the binary loads the pinned 3.4.8 at runtime rather
than the system library. For a before/after mitigation demo you can rebuild the same client
against a patched 3.4.9 connector and compare the escaped output for the *same* input - using
test input supplied by your course, not generated here.

---

## 6. Final verification checklist

```bash
# Apache 2.4.68 + WebDAV
/opt/httpd-2.4.68/bin/httpd -v
curl -u labuser http://localhost/webdav/

# Python 3.13.15
/opt/python-3.13.15/bin/python3.13 --version

# Connector/C 3.4.8
ls /opt/libmariadb-3.4.8/lib

# MariaDB server + data
sudo mysql labdb -e "SELECT * FROM users;"

# PHP site
curl http://127.0.0.1:8000/

# C client linked to the pinned 3.4.8 connector
~/lab-site/db_client alice
ldd ~/lab-site/db_client | grep mariadb
```

Or just run `./setup-lab.sh --verify`, which checks all of the above at once.

Then: **take the `lab-ready` snapshot**, switch the network adapter to Host-Only, and you're set.