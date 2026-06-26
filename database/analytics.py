from database.db import connect


# -----------------------------
# Save Scan
# -----------------------------

def save_scan(ip, url, risk):
    """
    Save QR scan information into SQLite database.
    """

    conn = connect()

    try:
        cur = conn.cursor()

        cur.execute(
            """
            INSERT INTO scans
            (user_ip, qr_url, risk_score)
            VALUES (?, ?, ?)
            """,
            (ip, url, risk)
        )

        conn.commit()

    finally:
        conn.close()


# -----------------------------
# Dashboard Statistics
# -----------------------------

def get_stats():
    """
    Returns:
    total scans,
    unique users,
    top 5 scanned URLs
    """

    conn = connect()

    try:
        cur = conn.cursor()

        # Total scans
        cur.execute(
            "SELECT COUNT(*) FROM scans"
        )

        total = cur.fetchone()[0]

        # Unique users
        cur.execute(
            """
            SELECT COUNT(DISTINCT user_ip)
            FROM scans
            """
        )

        users = cur.fetchone()[0]

        # Top scanned URLs
        cur.execute(
            """
            SELECT qr_url,
                   COUNT(*) AS scans
            FROM scans
            GROUP BY qr_url
            ORDER BY scans DESC
            LIMIT 5
            """
        )

        top = cur.fetchall()

        return total, users, top

    finally:
        conn.close()