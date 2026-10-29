<?php
// ============================================================
// CVE Lab Demo Site — landing page
// Part of a contained, offline lab environment for a security
// course. Target app only — no attack code here.
// ============================================================
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>CVE Lab Demo Site</title>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 640px; margin: 3rem auto; padding: 0 1rem; }
        h1 { border-bottom: 2px solid #333; padding-bottom: .3rem; }
        code { background: #f0f0f0; padding: .1rem .3rem; border-radius: 3px; }
        .warn { background: #fff4e5; border-left: 4px solid #e69500; padding: .6rem 1rem; margin: 1rem 0; }
    </style>
</head>
<body>
    <h1>CVE Lab Demo Site</h1>

    <div class="warn">
        Isolated lab environment. This VM runs intentionally outdated, vulnerable
        software and must stay on a host-only / internal network.
    </div>

    <p>Demo pages:</p>
    <ul>
        <li>
            <a href="search.php?name=alice">User lookup</a>
            &mdash; connects to MariaDB using the <code>big5</code> charset
            (the configuration relevant to CVE-2026-44172, the Connector/C
            <code>mysql_real_escape_string()</code> escaping bug).
        </li>
    </ul>

    <p style="color:#666; font-size:.9rem;">
        Served by the pinned Apache 2.4.68 build / PHP CLI server described in
        <code>cve-lab-setup.md</code>.
    </p>
</body>
</html>
