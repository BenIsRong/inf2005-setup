import ctypes
import ctypes.util
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote_to_bytes
import html
import os

LIB_PATH = "/opt/libmariadb-3.4.8/lib/mariadb/libmariadb.so"
#LIB_PATH = "/opt/libmariadb-3.4.11/lib/mariadb/libmariadb.so"
if not os.path.exists(LIB_PATH):
    # try alternate layout
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

MYSQL_SET_CHARSET_NAME = 7  # mysql option enum value


def do_query(name_bytes):
    """Connect, escape, query — mirrors the C client exactly."""
    conn = lib.mysql_init(None)
    if not conn:
        return None, "mysql_init failed"

    # Set big5 before connect, same as the original C client
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

    # Escape with the vulnerable function
    escaped_buf = ctypes.create_string_buffer(len(name_bytes) * 2 + 1)
    esc_len = lib.mysql_real_escape_string(conn, escaped_buf, name_bytes, len(name_bytes))
    escaped = escaped_buf.raw[:esc_len]

    # Build the query
    query = b"SELECT id, name FROM users WHERE name = '" + escaped + b"'"

    # Hex dump of escaped bytes
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
            params = parse_qs(parsed.query, keep_blank_values=True)
            name_raw = params.get("name", [None])[0]

            if name_raw is None:
                body = '<p class="info">Enter a name to search.</p>'
            else:
                # Get raw bytes from the URL-decoded input
                name_bytes = unquote_to_bytes(name_raw)

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
