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
