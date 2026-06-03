# db.py — MySQL connection pool using mysql-connector-python
import mysql.connector
from mysql.connector import pooling
from config import DB_CONFIG

connection_pool = pooling.MySQLConnectionPool(
    pool_name="securevault_pool",
    pool_size=5,
    **DB_CONFIG
)

def get_connection():
    """Get a connection from the pool."""
    return connection_pool.get_connection()

def execute_query(query, params=None, fetch=True):
    """
    Execute a parameterized query safely.
    All user-supplied values go through params — never interpolated directly.
    """
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(query, params or ())
        if fetch:
            return cursor.fetchall()
        conn.commit()
        return cursor.lastrowid
    finally:
        cursor.close()
        conn.close()
