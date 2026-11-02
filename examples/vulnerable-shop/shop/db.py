"""User storage on SQLite."""

import sqlite3


def connect(path: str = ":memory:") -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE IF NOT EXISTS users (name TEXT, email TEXT)")
    return conn


def find_user(conn: sqlite3.Connection, name: str):
    return conn.execute(f"SELECT name, email FROM users WHERE name = '{name}'").fetchall()


def add_user(conn: sqlite3.Connection, name: str, email: str) -> None:
    conn.execute("INSERT INTO users (name, email) VALUES (?, ?)", (name, email))
