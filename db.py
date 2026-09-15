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
    access_level INTEGER DEFAULT 1,  -- рівень допуску (напр., до високовольтних схем)
    hire_date TEXT,                  -- дата прийому на роботу
    is_new_hire INTEGER DEFAULT 0    -- 1 = проходить програму адаптації (Onboarding)
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
    updated_at TEXT,
    substation_id INTEGER REFERENCES substations(id)  -- прив'язка паспорта/схеми/інструкції до об'єкта на карті
);

-- ---------------------------------------------------------------------
-- 4. Енергетична та диспетчерська специфіка
-- ---------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS substations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    branch TEXT,
    voltage_class TEXT,               -- напр. "110/10 кВ"
    latitude REAL NOT NULL,
    longitude REAL NOT NULL,
    status TEXT DEFAULT 'В роботі'    -- В роботі | Планове відключення | Аварія
);

CREATE TABLE IF NOT EXISTS operational_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),   -- диспетчер/бригада ОВБ, що зробили запис
    substation_id INTEGER REFERENCES substations(id),
    event_type TEXT NOT NULL,         -- Аварійне відключення | Планове відключення | Спрацювання захисту | Виїзд ОВБ | Інше
    description TEXT NOT NULL,
    status TEXT DEFAULT 'Відкрито',   -- Відкрито | В роботі | Закрито
    brigade TEXT,                     -- назва/склад оперативно-виїзної бригади
    created_at TEXT NOT NULL,
    resolved_at TEXT
);

-- ---------------------------------------------------------------------
-- 3. Розширення функціоналу для співробітників та HR
-- ---------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS equipment_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    request_type TEXT NOT NULL,       -- Спецодяг/ЗІЗ | Інструмент | Несправність обладнання
    item_name TEXT NOT NULL,
    quantity INTEGER DEFAULT 1,
    description TEXT,
    priority TEXT DEFAULT 'Звичайна', -- Звичайна | Термінова (для несправностей, що впливають на безпеку)
    status TEXT DEFAULT 'Подано',     -- Подано | На розгляді | Видано/Виконано | Відхилено
    created_at TEXT NOT NULL,
    resolved_at TEXT
);

CREATE TABLE IF NOT EXISTS onboarding_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    order_index INTEGER NOT NULL,
    task_type TEXT NOT NULL,          -- Інструктаж | Регламент | Ментор | Інше
    title TEXT NOT NULL,
    description TEXT,
    related_instruction_id INTEGER REFERENCES safety_instructions(id),
    related_document_id INTEGER REFERENCES kb_documents(id),
    mentor_name TEXT,
    status TEXT DEFAULT 'Не виконано',  -- Не виконано | Виконано
    completed_at TEXT
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
