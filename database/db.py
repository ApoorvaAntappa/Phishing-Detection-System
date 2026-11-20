import json
import mysql.connector
import config
from typing import Dict, Any, Optional


def _get_conn():
    return mysql.connector.connect(
        host=config.MYSQL_HOST,
        user=config.MYSQL_USER,
        password=config.MYSQL_PASSWORD,
        database=config.MYSQL_DB,
    )


def insert_detected_url(url: str, domain: str, status: str, risk_score: float, features: Dict[str, Any], extra: Optional[str] = None):
    conn = _get_conn()
    cur = conn.cursor()
    try:
        # Discover available columns in detected_urls
        cur.execute("SHOW COLUMNS FROM detected_urls")
        cols = [row[0] for row in cur.fetchall()]

        insert_cols = []
        values = []

        if 'url' in cols:
            insert_cols.append('url')
            values.append(url)
        if 'domain' in cols:
            insert_cols.append('domain')
            values.append(domain)
        elif 'domain_name' in cols:
            insert_cols.append('domain_name')
            values.append(domain)
        if 'status' in cols:
            insert_cols.append('status')
            values.append(status)
        if 'risk_score' in cols:
            insert_cols.append('risk_score')
            values.append(risk_score)
        if 'features' in cols:
            insert_cols.append('features')
            values.append(json.dumps(features))
        if 'extra' in cols:
            insert_cols.append('extra')
            values.append(extra)

        if not insert_cols:
            # Nothing to insert
            return

        placeholders = ','.join(['%s'] * len(values))
        sql = f"INSERT INTO detected_urls ({','.join(insert_cols)}) VALUES ({placeholders})"
        cur.execute(sql, tuple(values))
        conn.commit()
    finally:
        cur.close()
        conn.close()


def fetch_recent(limit: int = 50):
    conn = _get_conn()
    cur = conn.cursor()
    try:
        # Discover available columns and map legacy names to the normalized set
        cur.execute("SHOW COLUMNS FROM detected_urls")
        existing = {row[0] for row in cur.fetchall()}

        id_expr = 'id'
        url_expr = 'url'

        if 'domain' in existing:
            domain_expr = 'domain'
        elif 'domain_name' in existing:
            domain_expr = 'domain_name AS domain'
        else:
            domain_expr = "NULL AS domain"

        status_expr = 'status' if 'status' in existing else "NULL AS status"

        if 'risk_score' in existing:
            risk_expr = 'risk_score'
        else:
            risk_expr = 'NULL AS risk_score'

        if 'detected_at' in existing:
            time_expr = 'detected_at'
        elif 'capture_time' in existing:
            time_expr = 'capture_time AS detected_at'
        else:
            time_expr = "NULL AS detected_at"

        sql = f"SELECT {id_expr}, {url_expr}, {domain_expr}, {status_expr}, {risk_expr}, {time_expr} FROM detected_urls ORDER BY id DESC LIMIT %s"
        cur.execute(sql, (limit,))
        return cur.fetchall()
    finally:
        cur.close()
        conn.close()
