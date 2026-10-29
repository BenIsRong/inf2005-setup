<?php
// ============================================================
// CVE Lab Demo Site — user lookup page
//
// Demonstrates the configuration relevant to CVE-2026-44172:
// a database connection using the big5 character set, with user
// input passed through mysql_real_escape_string() (here, the
// mysqli::real_escape_string wrapper).
//
// This is the TARGET app for the lab. It is written the way a
// normal developer would write it — relying on real_escape_string()
// to be safe. The CVE is that the underlying Connector/C library
// (libmariadb 3.4.8) mishandles big5 multi-byte sequences in that
// escaping routine. No attack payload is included here.
// ============================================================

header('Content-Type: text/html; charset=utf-8');

// --- DB connection (matches the labdb set up in cve-lab-setup.md) ---
$DB_HOST = '127.0.0.1';
$DB_USER = 'labapp';
$DB_PASS = 'labpass';
$DB_NAME = 'labdb';

$mysqli = new mysqli($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME);
if ($mysqli->connect_errno) {
    http_response_code(500);
    die('DB connect failed: ' . htmlspecialchars($mysqli->connect_error));
}

// Set the big5 charset — the encoding at the center of CVE-2026-44172.
$mysqli->set_charset('big5');

// --- Query ---
$name = $_GET['name'] ?? '';

// The developer's intended safety mechanism. With a patched connector
// (3.4.9+) this correctly neutralises quotes; with the pinned 3.4.8
// build it mishandles big5 multi-byte input.
$escaped = $mysqli->real_escape_string($name);

$sql = "SELECT id, name FROM users WHERE name = '$escaped'";
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>User lookup — CVE Lab</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 640px; margin: 3rem auto; padding: 0 1rem; }
        .q { background: #f0f0f0; padding: .5rem .7rem; border-radius: 4px; font-family: monospace; word-break: break-all; }
        .result { margin-top: 1rem; }
        a { color: #0645ad; }
    </style>
</head>
<body>
    <h1>User lookup</h1>

    <form method="get" action="search.php">
        <label>Name: <input type="text" name="name" value="<?= htmlspecialchars($name) ?>"></label>
        <button type="submit">Search</button>
    </form>

    <p>Query sent to the database:</p>
    <div class="q"><?= htmlspecialchars($sql) ?></div>

    <div class="result">
    <?php
    $res = $mysqli->query($sql);
    if ($res) {
        if ($res->num_rows === 0) {
            echo '<p>No rows matched.</p>';
        }
        while ($row = $res->fetch_assoc()) {
            echo 'Found: #' . htmlspecialchars($row['id']) . ' '
                . htmlspecialchars($row['name']) . '<br>';
        }
    } else {
        echo '<p>Query error: ' . htmlspecialchars($mysqli->error) . '</p>';
    }
    ?>
    </div>

    <p style="margin-top:2rem;"><a href="index.php">&larr; back</a></p>
</body>
</html>
<?php
$mysqli->close();
