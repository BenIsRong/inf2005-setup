#!/usr/bin/env bash
# ============================================================================
# setup-lab.sh — Provision a contained, offline CVE lab environment
#
#   CVE-2026-93546  Apache HTTP Server 2.4.68  (mod_dav_fs integer overflow)
#   CVE-2026-19553  CPython 3.13.15            (ssl wrap_bio hostname bypass)
#   CVE-2026-44172  MariaDB Connector/C 3.4.8  (big5 escaping SQL injection)
#
# Target OS: Kali / Debian-based. Run as a normal user WITH sudo available.
#
# This installs INTENTIONALLY OUTDATED, VULNERABLE software for a security
# course. It is the TARGET environment only — no exploit/attack code.
# Treat this VM as disposable and keep it on a host-only / internal network.
#
# Usage:
#   chmod +x setup-lab.sh
#   ./setup-lab.sh            # full run
#   ./setup-lab.sh --verify   # just re-run the verification checks
# ============================================================================

set -euo pipefail

# ---- pinned versions --------------------------------------------------------
APACHE_VER="2.4.68"
PYTHON_VER="3.13.15"
CONNC_VER="3.4.8"          # vulnerable connector (default target for web_app.py / db_client)
CONNC_FIXED_VER="3.4.11"   # patched connector, for the before/after mitigation demo

# ---- paths ------------------------------------------------------------------
SRC_DIR="/usr/local/src"
APACHE_PREFIX="/opt/httpd-${APACHE_VER}"
PYTHON_PREFIX="/opt/python-${PYTHON_VER}"
CONNC_PREFIX="/opt/libmariadb-${CONNC_VER}"
CONNC_FIXED_PREFIX="/opt/libmariadb-${CONNC_FIXED_VER}"
SITE_DIR="${HOME}/lab-site"
STAMP_DIR="${HOME}/.cve-lab-stamps"   # marks completed steps for resumability

# ---- db config (matches the guide) ------------------------------------------
DB_NAME="labdb"
DB_USER="labapp"
DB_PASS="labpass"

# ---- pretty output ----------------------------------------------------------
c_blue=$'\e[34m'; c_green=$'\e[32m'; c_yellow=$'\e[33m'; c_red=$'\e[31m'; c_off=$'\e[0m'
say()  { printf '%s==>%s %s\n' "$c_blue"  "$c_off" "$*"; }
ok()   { printf '%s[ok]%s %s\n' "$c_green" "$c_off" "$*"; }
warn() { printf '%s[!!]%s %s\n' "$c_yellow" "$c_off" "$*"; }
die()  { printf '%s[xx]%s %s\n' "$c_red" "$c_off" "$*" >&2; exit 1; }

mkdir -p "$STAMP_DIR"
done_before() { [[ -f "${STAMP_DIR}/$1" ]]; }
mark_done()   { touch "${STAMP_DIR}/$1"; }

# ============================================================================
# Pre-flight
# ============================================================================
preflight() {
    say "Pre-flight checks"
    [[ "$(id -u)" -ne 0 ]] || die "Run as a normal user (not root). sudo is used where needed."
    command -v sudo >/dev/null || die "sudo not found."
    command -v apt  >/dev/null || die "This script targets Debian/Kali (apt not found)."

    warn "This installs deliberately vulnerable software. Confirm the VM is isolated"
    warn "(host-only / internal network) BEFORE exposing any service beyond localhost."
    warn "Internet IS needed now to download sources; isolate afterwards."
    read -rp "Continue? [y/N] " reply
    [[ "$reply" =~ ^[Yy]$ ]] || die "Aborted by user."
    ok "Proceeding."
}

# ============================================================================
# Base packages
# ============================================================================
install_base() {
    if done_before base; then ok "Base packages already installed (skip)"; return; fi
    say "Installing base build dependencies"
    sudo apt update
    sudo apt install -y build-essential wget curl git cmake \
        libssl-dev libpcre3-dev libxml2-dev zlib1g-dev libapr1-dev libaprutil1-dev \
        libffi-dev libsqlite3-dev libbz2-dev libreadline-dev
    mark_done base
    ok "Base packages installed"
}

# ============================================================================
# CVE-2026-93546 — Apache 2.4.68 + WebDAV
# ============================================================================
install_apache() {
    if done_before apache; then ok "Apache ${APACHE_VER} already built (skip)"; return; fi
    say "Building Apache HTTP Server ${APACHE_VER} (CVE-2026-93546)"

    cd "$SRC_DIR"
    local tarball="httpd-${APACHE_VER}.tar.gz"
    [[ -f "$tarball" ]] || sudo wget -q "https://archive.apache.org/dist/httpd/${tarball}"
    sudo rm -rf "httpd-${APACHE_VER}"
    sudo tar xzf "$tarball"
    cd "httpd-${APACHE_VER}"

    sudo ./configure --prefix="${APACHE_PREFIX}" \
        --enable-dav --enable-dav-fs --enable-dav-lock \
        --enable-so --enable-rewrite --enable-ssl >/dev/null
    sudo make -j"$(nproc)" >/dev/null
    sudo make install >/dev/null

    # --- WebDAV config: authenticated, writable share ---
    say "Configuring authenticated WebDAV share"
    sudo mkdir -p "${APACHE_PREFIX}/htdocs/webdav" "${APACHE_PREFIX}/var"
    sudo chown -R daemon:daemon "${APACHE_PREFIX}/htdocs/webdav" "${APACHE_PREFIX}/var"

    # create lab WebDAV user non-interactively (lab-only credential)
    sudo "${APACHE_PREFIX}/bin/htpasswd" -bc "${APACHE_PREFIX}/conf/.davpasswd" labuser labpass

    # Ensure the DAV modules are loaded. Depending on the build they may be
    # compiled statically into httpd (already active) or built as shared .so
    # files (present in modules/ but NOT loaded without a LoadModule line).
    # Add a LoadModule line for the shared case only when there isn't already
    # an ACTIVE one. The grep is anchored (^[[:space:]]*LoadModule) so a
    # commented-out "#LoadModule dav_fs_module ..." in the stock httpd.conf does
    # NOT count as present — otherwise the module never loads and DavLockDB/Dav
    # below are rejected. These lines go in before the WebDAV block, since httpd
    # reads the config top-to-bottom and those directives need the module first.
    for mod in dav dav_fs; do
        if [[ -f "${APACHE_PREFIX}/modules/mod_${mod}.so" ]] \
           && ! grep -qE "^[[:space:]]*LoadModule ${mod}_module" "${APACHE_PREFIX}/conf/httpd.conf"; then
            echo "LoadModule ${mod}_module modules/mod_${mod}.so" \
                | sudo tee -a "${APACHE_PREFIX}/conf/httpd.conf" >/dev/null
        fi
    done

    if ! grep -q "WebDAV lab share" "${APACHE_PREFIX}/conf/httpd.conf"; then
        sudo tee -a "${APACHE_PREFIX}/conf/httpd.conf" >/dev/null <<APACHECONF

# === WebDAV lab share (CVE-2026-93546 target) ===
DavLockDB "${APACHE_PREFIX}/var/DavLock"
Alias /webdav "${APACHE_PREFIX}/htdocs/webdav"
<Directory "${APACHE_PREFIX}/htdocs/webdav">
    Dav On
    AuthType Basic
    AuthName "webdav-lab"
    AuthUserFile "${APACHE_PREFIX}/conf/.davpasswd"
    Require valid-user
</Directory>
APACHECONF
    fi

    mark_done apache
    ok "Apache ${APACHE_VER} built and WebDAV configured"
}

start_apache() {
    say "Starting Apache"
    sudo "${APACHE_PREFIX}/bin/apachectl" -k restart 2>/dev/null || \
        sudo "${APACHE_PREFIX}/bin/apachectl" -k start
    sleep 1
    ok "Apache running (logs: ${APACHE_PREFIX}/logs/error_log)"
}

# ============================================================================
# CVE-2026-19553 — Python 3.13.15 (separate interpreter, altinstall)
# ============================================================================
install_python() {
    if done_before python; then ok "Python ${PYTHON_VER} already built (skip)"; return; fi
    say "Building CPython ${PYTHON_VER} (CVE-2026-19553)"

    cd "$SRC_DIR"
    local tarball="Python-${PYTHON_VER}.tgz"
    [[ -f "$tarball" ]] || sudo wget -q "https://www.python.org/ftp/python/${PYTHON_VER}/${tarball}"
    sudo rm -rf "Python-${PYTHON_VER}"
    sudo tar xzf "$tarball"
    cd "Python-${PYTHON_VER}"

    sudo ./configure --prefix="${PYTHON_PREFIX}" --with-openssl=/usr >/dev/null
    sudo make -j"$(nproc)" >/dev/null
    sudo make altinstall >/dev/null   # altinstall: does NOT overwrite system python3

    mark_done python
    ok "Python ${PYTHON_VER} installed at ${PYTHON_PREFIX}/bin/python3.13"
}

# ============================================================================
# CVE-2026-44172 — MariaDB Connector/C 3.4.8 (+ server for the app)
# ============================================================================
install_mariadb_server() {
    if done_before mariadb_server; then ok "MariaDB server + data already set up (skip)"; return; fi
    say "Installing MariaDB server and seeding lab data"
    sudo apt install -y mariadb-server
    sudo systemctl enable --now mariadb

    # --skip-ssl: these are all-local lab connections, and this system's
    # MariaDB client config forces TLS, which fails against the server's
    # auto-generated cert (MariaDB 11.8 + OpenSSL 3). No TLS is needed locally.
    sudo mysql --skip-ssl <<SQL
CREATE DATABASE IF NOT EXISTS ${DB_NAME};
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
USE ${DB_NAME};
CREATE TABLE IF NOT EXISTS users(id INT, name VARCHAR(64), secret VARCHAR(64));
DELETE FROM users;
INSERT INTO users VALUES (1,'alice','flag_alpha'),(2,'bob','flag_bravo');
SQL

    # Make the name column use the big5 charset (relevant to CVE-2026-44172),
    # then seed a row whose name is raw big5 bytes (0xA4A4A4E5). SET NAMES big5
    # must run in the same client session as the INSERT so the server reads the
    # literal bytes as big5, so this is a separate invocation from the heredoc.
    mysql -u "${DB_USER}" -p"${DB_PASS}" "${DB_NAME}" \
        -e "ALTER TABLE users MODIFY name VARCHAR(64) CHARACTER SET big5;"
    mysql -u "${DB_USER}" -p"${DB_PASS}" "${DB_NAME}" \
        -e "SET NAMES big5; INSERT INTO users VALUES (3, 0xA4A4A4E5, 'flag_chinese');"

    mark_done mariadb_server
    ok "MariaDB server ready (db=${DB_NAME}, user=${DB_USER})"
}

# Build one pinned Connector/C from source into its own prefix.
#   $1 version (e.g. 3.4.8)   $2 install prefix   $3 label for logging
build_connc() {
    local ver="$1" prefix="$2" label="$3" stamp="connc-$1"
    if done_before "$stamp"; then ok "Connector/C ${ver} already built (skip)"; return; fi
    say "Building MariaDB Connector/C ${ver} — ${label} (CVE-2026-44172)"

    cd "$SRC_DIR"
    sudo rm -rf "mcc-${ver}"
    sudo git clone --branch "v${ver}" --depth 1 \
        https://github.com/mariadb-corporation/mariadb-connector-c.git "mcc-${ver}"
    cd "mcc-${ver}"

    # Older Connector/C releases build with -Werror; newer GCC (14/15 on current
    # Kali) flags const-qualifier discards that older GCC did not, turning them
    # into fatal errors. The project injects -Werror where a -Wno-error compiler
    # flag can't override it, so strip -Werror from the build files outright
    # (matches plain -Werror and -Werror=... forms, leaves other -W flags
    # intact). The warnings then stay non-fatal and the connector builds.
    sudo grep -rln 'Werror' . | xargs -r sudo sed -i 's/-Werror[^ "]*//g'

    sudo rm -rf build && sudo mkdir -p build && cd build
    sudo cmake .. -DCMAKE_INSTALL_PREFIX="${prefix}" >/dev/null
    sudo make -j"$(nproc)" >/dev/null
    sudo make install >/dev/null

    mark_done "$stamp"
    ok "Connector/C ${ver} installed at ${prefix}"
}

install_connc() {
    # Vulnerable build (what web_app.py / db_client target by default) ...
    build_connc "${CONNC_VER}"       "${CONNC_PREFIX}"       "vulnerable target"
    # ... and the patched build, so you can run the SAME input through both and
    # compare the escaped output for the before/after mitigation demo.
    build_connc "${CONNC_FIXED_VER}" "${CONNC_FIXED_PREFIX}" "patched / before-after demo"
}

# ============================================================================
# Sample web app (Python) — loads the pinned Connector/C 3.4.8 directly
# ============================================================================
# A pure-Python HTTP server that loads the pinned libmariadb 3.4.8 via ctypes,
# so it genuinely exercises the vulnerable big5 escaping routine. Uses only the
# standard library — no extra packages, and the system python3 is fine (this is
# NOT the pinned 3.13.15 interpreter, which belongs to the unrelated ssl CVE).
# TARGET app, no payload.
install_web_app() {
    if done_before web_app; then ok "Web app already created (skip)"; return; fi
    say "Creating the Python sample web app"
    command -v python3 >/dev/null || die "python3 not found (needed for the web app)."
    mkdir -p "$SITE_DIR"

    cat > "${SITE_DIR}/web_app.py" <<'WEBAPP'
import ctypes
import ctypes.util
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import html
import os

LIB_PATH = "/opt/libmariadb-3.4.8/lib/mariadb/libmariadb.so"
#LIB_PATH = "/opt/libmariadb-3.4.11/lib/mariadb/libmariadb.so"
if not os.path.exists(LIB_PATH):
    for root, dirs, files in os.walk("/opt/libmariadb-3.4.8"):
        for f in files:
            if f.startswith("libmariadb.so"):
                LIB_PATH = os.path.join(root, f)
                break

lib = ctypes.CDLL(LIB_PATH)

lib.mysql_init.restype = ctypes.c_void_p
lib.mysql_init.argtypes = [ctypes.c_void_p]

lib.mysql_options.restype = ctypes.c_int
lib.mysql_options.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p]

lib.mysql_real_connect.restype = ctypes.c_void_p
lib.mysql_real_connect.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint,
    ctypes.c_char_p, ctypes.c_ulong
]

lib.mysql_real_escape_string.restype = ctypes.c_ulong
lib.mysql_real_escape_string.argtypes = [
    ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong
]

lib.mysql_query.restype = ctypes.c_int
lib.mysql_query.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

lib.mysql_store_result.restype = ctypes.c_void_p
lib.mysql_store_result.argtypes = [ctypes.c_void_p]

lib.mysql_fetch_row.restype = ctypes.POINTER(ctypes.c_char_p)
lib.mysql_fetch_row.argtypes = [ctypes.c_void_p]

lib.mysql_num_rows.restype = ctypes.c_ulonglong
lib.mysql_num_rows.argtypes = [ctypes.c_void_p]

lib.mysql_num_fields.restype = ctypes.c_uint
lib.mysql_num_fields.argtypes = [ctypes.c_void_p]

lib.mysql_free_result.restype = None
lib.mysql_free_result.argtypes = [ctypes.c_void_p]

lib.mysql_close.restype = None
lib.mysql_close.argtypes = [ctypes.c_void_p]

lib.mysql_error.restype = ctypes.c_char_p
lib.mysql_error.argtypes = [ctypes.c_void_p]

lib.mysql_get_client_info.restype = ctypes.c_char_p
lib.mysql_get_client_info.argtypes = []

lib.mysql_character_set_name.restype = ctypes.c_char_p
lib.mysql_character_set_name.argtypes = [ctypes.c_void_p]

MYSQL_SET_CHARSET_NAME = 7


def do_query(name_bytes):
    conn = lib.mysql_init(None)
    if not conn:
        return None, "mysql_init failed"

    lib.mysql_options(conn, MYSQL_SET_CHARSET_NAME, b"big5")

    ret = lib.mysql_real_connect(
        conn, b"127.0.0.1", b"labapp", b"labpass", b"labdb", 0, None, 0
    )
    if not ret:
        err = lib.mysql_error(conn).decode(errors="replace")
        lib.mysql_close(conn)
        return None, f"connect failed: {err}"

    client_ver = lib.mysql_get_client_info().decode(errors="replace")
    charset = lib.mysql_character_set_name(conn).decode(errors="replace")

    escaped_buf = ctypes.create_string_buffer(len(name_bytes) * 2 + 1)
    esc_len = lib.mysql_real_escape_string(conn, escaped_buf, name_bytes, len(name_bytes))
    escaped = escaped_buf.raw[:esc_len]

    query = b"SELECT id, name FROM users WHERE name = '" + escaped + b"'"

    hex_dump = " ".join(f"{b:02x}" for b in escaped)

    info = {
        "client": client_ver,
        "charset": charset,
        "input_hex": " ".join(f"{b:02x}" for b in name_bytes),
        "escaped_hex": hex_dump,
        "query": query.decode(errors="replace"),
        "rows": []
    }

    if lib.mysql_query(conn, query):
        info["error"] = lib.mysql_error(conn).decode(errors="replace")
    else:
        result = lib.mysql_store_result(conn)
        if result:
            nrows = lib.mysql_num_rows(result)
            nfields = lib.mysql_num_fields(result)
            for _ in range(nrows):
                row = lib.mysql_fetch_row(result)
                if row:
                    cols = []
                    for j in range(nfields):
                        val = row[j]
                        cols.append(val.decode("big5", errors="replace") if val else "NULL")
                    info["rows"].append(cols)
            lib.mysql_free_result(result)

    lib.mysql_close(conn)
    return info, None


HTML_TEMPLATE = """<!DOCTYPE html>
<html><head><title>User Lookup - CVE Lab (Python)</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 700px; margin: 2rem auto; padding: 0 1rem; }}
.q {{ background: #f0f0f0; padding: .5rem .7rem; border-radius: 4px; font-family: monospace; word-break: break-all; }}
.result {{ margin: 1rem 0; }}
.row {{ padding: .3rem 0; }}
.info {{ color: #666; font-size: 0.9em; }}
.error {{ color: #c00; }}
</style>
</head><body>
<h1>User Lookup</h1>
<p class="info">Python app using MariaDB Connector/C via ctypes</p>
<form method="get" action="/search">
<label>Name: <input type="text" name="name" value=""></label>
<button type="submit">Search</button>
</form>
{body}
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/search":
            params = parse_qs(parsed.query, keep_blank_values=True, encoding='latin-1')
            name_raw = params.get("name", [None])[0]

            if name_raw is None:
                body = '<p class="info">Enter a name to search.</p>'
            else:
                name_bytes = name_raw.encode('latin-1')

                info, err = do_query(name_bytes)
                if err:
                    body = f'<p class="error">{html.escape(err)}</p>'
                else:
                    body = f'<p class="info">Client: {html.escape(info["client"])} | Charset: {html.escape(info["charset"])}</p>\n'
                    body += f'<p class="info">Input hex: {html.escape(info["input_hex"])}</p>\n'
                    body += f'<p class="info">Escaped hex: {html.escape(info["escaped_hex"])}</p>\n'
                    body += '<p>Query sent to the database:</p>\n'
                    body += f'<div class="q">{html.escape(info["query"])}</div>\n'

                    if "error" in info:
                        body += f'<p class="error">Query error: {html.escape(info["error"])}</p>\n'
                    else:
                        body += f'<div class="result"><p>Rows returned: {len(info["rows"])}</p>\n'
                        for cols in info["rows"]:
                            body += f'<div class="row">#{html.escape(cols[0])} {html.escape(cols[1])}</div>\n'
                        body += '</div>\n'
        else:
            body = '<p class="info">Enter a name to search.</p>'

        page = HTML_TEMPLATE.format(body=body)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(page.encode())

    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {args[0]}")


if __name__ == "__main__":
    port = 9000
    client_ver = lib.mysql_get_client_info().decode()
    print(f"Loaded MariaDB Connector/C: {client_ver}")
    print(f"Library path: {LIB_PATH}")
    print(f"Serving on http://127.0.0.1:{port}/")
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
WEBAPP

    mark_done web_app
    ok "Web app created at ${SITE_DIR}/web_app.py"
}

# ============================================================================
# C client linked against the pinned Connector/C 3.4.8
# (makes the MariaDB CVE faithful; TARGET app, no attack payload)
# ============================================================================
install_c_client() {
    if done_before c_client; then ok "C client already built (skip)"; return; fi
    say "Building C client linked against Connector/C ${CONNC_VER}"

    [[ -d "${CONNC_PREFIX}" ]] || { warn "Connector/C not built; skipping C client"; return; }

    # locate the installed headers and library (layout varies by build)
    local inc_dir lib_dir
    inc_dir="$(dirname "$(find "${CONNC_PREFIX}" -name mysql.h 2>/dev/null | head -1)")"
    lib_dir="$(dirname "$(find "${CONNC_PREFIX}" -name 'libmariadb.so*' 2>/dev/null | head -1)")"
    [[ -n "$inc_dir" && -n "$lib_dir" ]] || { warn "could not locate connector headers/lib; skipping"; return; }

    mkdir -p "$SITE_DIR"
    cat > "${SITE_DIR}/db_client.c" <<'CCLIENT'
/* db_client.c — CVE Lab target client.
 *
 * Linked against the pinned MariaDB Connector/C 3.4.8. Mirrors search.php:
 * connects with the big5 charset and escapes input with mysql_real_escape_string().
 * This is the TARGET application — written the normal, trusting way. The flaw
 * is in the connector's big5 handling, not in this code. No attack payload here.
 *
 *   ./db_client "alice"
 *
 * It prints the escaped bytes (and their hex) so you can run the SAME input
 * against a 3.4.8 build and a patched 3.4.9 build and compare the output —
 * a clean, defensive before/after for the mitigation demo.
 */
#include <mysql.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <name>\n", argv[0]); return 1; }
    const char *input = argv[1];

    MYSQL *conn = mysql_init(NULL);
    if (!conn) { fprintf(stderr, "mysql_init failed\n"); return 1; }

    /* big5 — the charset involved in CVE-2026-44172 */
    mysql_options(conn, MYSQL_SET_CHARSET_NAME, "big5");

    if (!mysql_real_connect(conn, "127.0.0.1", "labapp", "labpass", "labdb", 0, NULL, 0)) {
        fprintf(stderr, "connect failed: %s\n", mysql_error(conn));
        mysql_close(conn); return 1;
    }

    printf("client library : %s\n", mysql_get_client_info());  /* confirms which version is linked */

    /* the developer's intended safety mechanism */
    size_t len = strlen(input);
    char *escaped = malloc(len * 2 + 1);
    mysql_real_escape_string(conn, escaped, input, len);

    printf("input          : %s\n", input);
    printf("escaped        : %s\n", escaped);
    printf("escaped (hex)  : ");
    for (size_t i = 0; escaped[i]; i++) printf("%02x ", (unsigned char)escaped[i]);
    printf("\n");

    char query[1024];
    snprintf(query, sizeof(query),
             "SELECT id, name FROM users WHERE name = '%s'", escaped);
    printf("query          : %s\n", query);

    if (mysql_query(conn, query)) {
        fprintf(stderr, "query error    : %s\n", mysql_error(conn));
    } else {
        MYSQL_RES *res = mysql_store_result(conn);
        if (res) {
            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)))
                printf("row            : #%s %s\n", row[0], row[1]);
            mysql_free_result(res);
        }
    }

    free(escaped);
    mysql_close(conn);
    return 0;
}
CCLIENT

    # compile, linking the pinned connector and baking in its rpath so the
    # binary loads 3.4.8 at runtime rather than the system library
    if gcc "${SITE_DIR}/db_client.c" -o "${SITE_DIR}/db_client" \
        -I"${inc_dir}" -L"${lib_dir}" -lmariadb -Wl,-rpath,"${lib_dir}"; then
        mark_done c_client
        ok "C client built: ${SITE_DIR}/db_client"
    else
        warn "C client compile failed (check gcc + connector paths)"
    fi
}

# ============================================================================
# Verification
# ============================================================================
verify() {
    say "Verifying installed components"
    echo

    printf '  Apache:      '
    if [[ -x "${APACHE_PREFIX}/bin/httpd" ]]; then
        "${APACHE_PREFIX}/bin/httpd" -v | head -1
        "${APACHE_PREFIX}/bin/httpd" -M 2>/dev/null | grep -q dav_fs_module \
            && ok "  mod_dav_fs present" || warn "  mod_dav_fs NOT found"
    else warn "not built"; fi

    printf '  Python:      '
    [[ -x "${PYTHON_PREFIX}/bin/python3.13" ]] && \
        "${PYTHON_PREFIX}/bin/python3.13" --version || warn "not built"

    printf '  Connector/C (vuln %s):  ' "${CONNC_VER}"
    if [[ -d "${CONNC_PREFIX}/lib" ]]; then
        ls "${CONNC_PREFIX}"/lib/mariadb/libmariadb.so* 2>/dev/null | head -1 \
            || ls "${CONNC_PREFIX}"/lib/libmariadb.so* 2>/dev/null | head -1 \
            || echo "installed at ${CONNC_PREFIX}"
    else warn "not built"; fi

    printf '  Connector/C (fixed %s): ' "${CONNC_FIXED_VER}"
    if [[ -d "${CONNC_FIXED_PREFIX}/lib" ]]; then
        ls "${CONNC_FIXED_PREFIX}"/lib/mariadb/libmariadb.so* 2>/dev/null | head -1 \
            || ls "${CONNC_FIXED_PREFIX}"/lib/libmariadb.so* 2>/dev/null | head -1 \
            || echo "installed at ${CONNC_FIXED_PREFIX}"
    else warn "not built"; fi

    printf '  MariaDB svc: '
    systemctl is-active mariadb 2>/dev/null || warn "not running"

    printf '  Lab data:    '
    sudo mysql --skip-ssl "${DB_NAME}" -e "SELECT COUNT(*) AS users FROM users;" 2>/dev/null \
        | tail -1 | xargs -I{} echo "{} user rows" || warn "no data"

    printf '  Web app:     '
    [[ -f "${SITE_DIR}/web_app.py" ]] && echo "present at ${SITE_DIR}/web_app.py" || warn "missing"

    printf '  C client:    '
    if [[ -x "${SITE_DIR}/db_client" ]]; then
        echo "built at ${SITE_DIR}/db_client"
        printf '  linked lib:  '
        ldd "${SITE_DIR}/db_client" 2>/dev/null | grep -i mariadb | awk '{print $3}' | head -1 \
            || echo "(run: ldd ${SITE_DIR}/db_client)"
    else warn "not built"; fi

    echo
}

# ============================================================================
# Final notes
# ============================================================================
final_notes() {
    cat <<NOTES

${c_green}============================================================${c_off}
${c_green} Lab environment provisioned.${c_off}
${c_green}============================================================${c_off}

 Start the services for a demo:
   sudo ${APACHE_PREFIX}/bin/apachectl -k start
   cd ${SITE_DIR} && python3 web_app.py          # then browse http://127.0.0.1:9000/

 Quick WebDAV sanity check (normal operation, not an exploit):
   curl -u labuser:labpass -T /etc/hostname http://localhost/webdav/test.txt
   curl -u labuser:labpass http://localhost/webdav/

 Python interpreter:
   ${PYTHON_PREFIX}/bin/python3.13

 Web app — loads the pinned connector directly via ctypes (benign usage):
   cd ${SITE_DIR} && python3 web_app.py      # → http://127.0.0.1:9000/  (loads 3.4.8)
   # To demo the patched build, edit LIB_PATH in web_app.py to point at
   # ${CONNC_FIXED_PREFIX} (a commented line for it is already in the file),
   # re-run, and compare the 'Escaped hex' for the SAME big5 input.

 C client linked to the pinned 3.4.8 connector (benign usage):
   ${SITE_DIR}/db_client alice
   # 'client library' in the output confirms 3.4.8 is the linked version.

${c_yellow} NEXT STEPS / CAVEATS${c_off}
  * Prevent silent patching of the pinned versions:
      sudo apt-mark hold apache2 mariadb-server
  * Switch the VM network adapter to Host-Only / Internal NOW, then snapshot
    the VM as 'lab-ready'.
  * The web app loads ${CONNC_PREFIX} (or ${CONNC_FIXED_PREFIX}) directly via
    ctypes, so it genuinely exercises the pinned connector's escaping routine,
    and nothing needs recompiling to switch between vuln and patched.

NOTES
}

# ============================================================================
# Main
# ============================================================================
main() {
    if [[ "${1:-}" == "--verify" ]]; then verify; exit 0; fi

    preflight
    install_base
    install_apache
    install_python
    install_mariadb_server
    install_connc
    install_web_app
    install_c_client
    start_apache
    verify
    final_notes
}

main "$@"
