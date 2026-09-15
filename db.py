"""
db.py — шар роботи з даними для порталу "Єдине цифрове вікно співробітника".

У реальному впровадженні (див. Roadmap, Фаза 3) ці таблиці будуть замінені /
синхронізовані з ERP/HR (BAS/1С, SAP) через API, а автентифікація —
делегована в Active Directory / LDAP (SSO). У цьому демо-MVP всі дані
зберігаються локально в SQLite, щоб застосунок можна було запустити
"з коробки" без зовнішньої інфраструктури.
"""

import sqlite3
import datetime as dt
import json
from pathlib import Path

DB_PATH = Path(__file__).parent / "portal.db"


def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    login TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,          -- демо: відкритий текст. Прод: SSO/AD, без пароля в БД.
    full_name TEXT NOT NULL,
    position TEXT,
    department TEXT,
    branch TEXT,
    role TEXT NOT NULL,              -- employee | hr | safety_admin | admin
    access_level INTEGER DEFAULT 1   -- рівень допуску (напр., до високовольтних схем)
);

CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    work_date TEXT NOT NULL,
    shift TEXT NOT NULL,             -- напр. "08:00–20:00"
    location TEXT
);

CREATE TABLE IF NOT EXISTS leave_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    req_type TEXT NOT NULL,          -- відпустка | відгул
    date_from TEXT NOT NULL,
    date_to TEXT NOT NULL,
    comment TEXT,
    approver TEXT,
    status TEXT DEFAULT 'На розгляді',   -- На розгляді | Погоджено | Відхилено
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS certificate_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    cert_type TEXT NOT NULL,         -- З місця роботи | Про доходи
    status TEXT DEFAULT 'В обробці', -- В обробці | Готово | Видано
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    department TEXT,                 -- NULL/'Усі' = для всіх філій
    branch TEXT,
    urgent INTEGER DEFAULT 0,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS safety_instructions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    category TEXT,                   -- Вступний | Позаплановий | Допуск до робіt підв. небезпеки
    content TEXT NOT NULL,
    required_for_role TEXT,          -- 'Усі' або конкретна роль/посада
    valid_days INTEGER DEFAULT 90    -- частота повторного тестування (квартал = 90 днів)
);

CREATE TABLE IF NOT EXISTS quiz_questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    instruction_id INTEGER NOT NULL REFERENCES safety_instructions(id),
    question TEXT NOT NULL,
    options TEXT NOT NULL,           -- JSON-список варіантів
    correct_index INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS test_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    instruction_id INTEGER NOT NULL REFERENCES safety_instructions(id),
    score REAL NOT NULL,
    passed INTEGER NOT NULL,
    taken_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS kb_documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    category TEXT,                   -- Регламент | Схема | Паспорт обладнання | Інструкція | НПАОП
    tags TEXT,                       -- через кому
    content TEXT NOT NULL,           -- текст документа (у проді: посилання на S3 + індекс у Qdrant)
    min_access_level INTEGER DEFAULT 1,
    owner TEXT,
    updated_at TEXT
);
"""


def init_db():
    conn = get_conn()
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def now():
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M")


def db_empty():
    conn = get_conn()
    n = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    conn.close()
    return n == 0
