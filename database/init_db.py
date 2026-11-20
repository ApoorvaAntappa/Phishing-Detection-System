import mysql.connector
import config
import os


def init():
    conn = mysql.connector.connect(
        host=config.MYSQL_HOST,
        user=config.MYSQL_USER,
        password=config.MYSQL_PASSWORD,
    )
    cur = conn.cursor()
    try:
        cur.execute(f"CREATE DATABASE IF NOT EXISTS {config.MYSQL_DB}")
        conn.commit()
    finally:
        cur.close()
        conn.close()

    # Run schema
    conn = mysql.connector.connect(
        host=config.MYSQL_HOST,
        user=config.MYSQL_USER,
        password=config.MYSQL_PASSWORD,
        database=config.MYSQL_DB,
    )
    cur = conn.cursor()
    try:
        here = os.path.dirname(__file__)
        schema_file = os.path.join(here, 'schema.sql')
        with open(schema_file, 'r', encoding='utf-8') as f:
            schema_sql = f.read()
        for stmt in schema_sql.split(';'):
            stmt = stmt.strip()
            if stmt:
                cur.execute(stmt)
        conn.commit()
    finally:
        cur.close()
        conn.close()


if __name__ == '__main__':
    init()
    print('Database initialized')
