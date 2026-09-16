-- postgres_schema.sql
-- Референсна схема для переходу з SQLite на PostgreSQL (+ опційно pgvector).
--
-- Це НЕ автоматично підключений другий бекенд застосунку — переписати весь
-- шар app.py/db.py на психопг2 з урахуванням відмінностей SQLite↔Postgres
-- (AUTOINCREMENT→SERIAL, lastrowid→RETURNING id, інша обробка плейсхолдерів
-- `?`→`%s` тощо) виходить за межі точкового доповнення функціоналу. Натомість
-- тут наведено готову цільову схему та коментарі, за якими це можна зробити
-- інкрементально, таблиця за таблицею, не зупиняючи роботу застосунку
-- (SQLite лишається робочим бекендом до завершення міграції).
--
-- Встановлення pgvector: https://github.com/pgvector/pgvector
--   CREATE EXTENSION IF NOT EXISTS vector;

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    login TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,           -- прод: не зберігати пароль тут узагалі, лише через LDAP/SSO
    full_name TEXT NOT NULL,
    position TEXT,
    department TEXT,
    branch TEXT,
    role TEXT NOT NULL,
    access_level INTEGER DEFAULT 1,
    hire_date DATE,
    is_new_hire BOOLEAN DEFAULT FALSE
);

CREATE TABLE schedules (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    work_date DATE NOT NULL,
    shift TEXT NOT NULL,
    location TEXT
);

CREATE TABLE leave_requests (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    req_type TEXT NOT NULL,
    date_from DATE NOT NULL,
    date_to DATE NOT NULL,
    comment TEXT,
    approver TEXT,
    status TEXT DEFAULT 'На розгляді',
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE certificate_requests (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    cert_type TEXT NOT NULL,
    status TEXT DEFAULT 'В обробці',
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE notifications (
    id SERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    department TEXT,
    branch TEXT,
    urgent BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE safety_instructions (
    id SERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    category TEXT,
    content TEXT NOT NULL,
    required_for_role TEXT,
    valid_days INTEGER DEFAULT 90
);

CREATE TABLE quiz_questions (
    id SERIAL PRIMARY KEY,
    instruction_id INTEGER NOT NULL REFERENCES safety_instructions(id) ON DELETE CASCADE,
    question TEXT NOT NULL,
    options JSONB NOT NULL,           -- нативний JSON замість TEXT з json.dumps
    correct_index INTEGER NOT NULL
);

CREATE TABLE test_results (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    instruction_id INTEGER NOT NULL REFERENCES safety_instructions(id) ON DELETE CASCADE,
    score REAL NOT NULL,
    passed BOOLEAN NOT NULL,
    taken_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE substations (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    branch TEXT,
    voltage_class TEXT,
    latitude DOUBLE PRECISION NOT NULL,
    longitude DOUBLE PRECISION NOT NULL,
    status TEXT DEFAULT 'В роботі'
);

CREATE TABLE kb_documents (
    id SERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    category TEXT,
    tags TEXT,
    content TEXT NOT NULL,
    min_access_level INTEGER DEFAULT 1,
    owner TEXT,
    updated_at TIMESTAMPTZ DEFAULT now(),
    substation_id INTEGER REFERENCES substations(id),
    embedding VECTOR(1536)             -- pgvector: ембединг для семантичного пошуку
                                        -- (замість окремого сервісу Qdrant — див. vector_store.py)
);

-- Індекс наближеного пошуку найближчих сусідів (ANN) для pgvector:
CREATE INDEX kb_documents_embedding_idx ON kb_documents
    USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);

-- Приклад запиту семантичного пошуку через pgvector (аналог vector_store.QdrantBackend.search):
--   SELECT id, title, content, 1 - (embedding <=> :query_embedding) AS score
--   FROM kb_documents
--   WHERE min_access_level <= :user_access_level
--   ORDER BY embedding <=> :query_embedding
--   LIMIT 5;

CREATE TABLE operational_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    substation_id INTEGER REFERENCES substations(id),
    event_type TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT DEFAULT 'Відкрито',
    brigade TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ
);

CREATE TABLE equipment_requests (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    request_type TEXT NOT NULL,
    item_name TEXT NOT NULL,
    quantity INTEGER DEFAULT 1,
    description TEXT,
    priority TEXT DEFAULT 'Звичайна',
    status TEXT DEFAULT 'Подано',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ
);

CREATE TABLE onboarding_tasks (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    order_index INTEGER NOT NULL,
    task_type TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    related_instruction_id INTEGER REFERENCES safety_instructions(id),
    related_document_id INTEGER REFERENCES kb_documents(id),
    mentor_name TEXT,
    status TEXT DEFAULT 'Не виконано',
    completed_at TIMESTAMPTZ
);

-- Аудит: у продакшні варто заборонити UPDATE/DELETE на рівні прав ролі БД,
-- щоб журнал був справді незмінним (append-only) для державного аудиту.
CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    user_name TEXT,
    action_type TEXT NOT NULL,
    object_type TEXT,
    object_id INTEGER,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_created_at_idx ON audit_log (created_at DESC);
CREATE INDEX audit_log_user_id_idx ON audit_log (user_id);

CREATE TABLE chat_history (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    question TEXT NOT NULL,
    answer TEXT NOT NULL,
    sources JSONB,
    llm_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
