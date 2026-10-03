"""
Центр моніторингу, диспетчерський хаб та адміністрування (Streamlit, один файл)

Розділи:
  1. Security & Operations Dashboard (стан систем, кібербезпека, інфраструктура)
  3. Диспетчерський та технічний хаб (SCADA/GIS/телемеханіка, аварійні сповіщення)
  4. Адміністрування контенту та інтеграцій (API/шлюзи, реєстр нормативних документів)
  6. Інциденти (плейбуки, таймлайн, MTTA/MTTR, автостворення з критичних алертів)
  7. Активи та відповідність (патчі, сертифікати, вразливості, ризик-скор)
  8. Звіти та SLA (Excel-звіт, оперативне зведення)
  9. Сповіщення (Telegram, dry-run за замовчуванням)
  10. Збереження стану: інциденти, документи, журнал дій, метрики -> SQLite / PostgreSQL
  11. Прогноз заповнення дисків (лінійний тренд) та виявлення аномалій (z-score)
  12. Оперативний журнал переключень (стан комутаційних апаратів, блокування, хто/коли/за яким нарядом)
  13. GIS: імпорт/експорт схем мереж (GeoJSON, KML) замість демо-координат
  14. Метеомоніторинг підстанцій (вітер, ожеледь, грози) із прив'язкою до алертів
  15. Темна / світла тема з перемикачем (CSS-тема, графіки Plotly, тайли карт; зберігається в URL ?theme=)

Запуск:
    pip install streamlit pandas numpy plotly openpyxl sqlalchemy folium streamlit-folium
    # для PostgreSQL додатково: pip install psycopg2-binary
    streamlit run security_ops_dashboard.py

База даних:
    за замовчуванням — SQLite-файл ops_center.db поруч зі скриптом;
    для PostgreSQL задайте DATABASE_URL (змінна середовища або .streamlit/secrets.toml), напр.:
    postgresql://user:password@host:5432/opscenter

Дані у цій версії СИМУЛЬОВАНІ (генеруються в реальному часі).
Щоб підключити реальні джерела, замініть функції-провайдери:
    tick_services(), tick_auth_logs(), tick_servers(), get_backups(),
    tick_ot(), tick_gateways()
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import re
import xml.etree.ElementTree as ET
import zlib
from xml.sax.saxutils import escape as xml_escape
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from io import BytesIO

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import streamlit as st

try:
    from sqlalchemy import (
        Column, DateTime, Float, Integer, LargeBinary, MetaData, String, Table, Text,
        create_engine, delete, func, insert, select, update,
    )

    HAS_DB = True
except ImportError:  # SQLAlchemy не встановлено — працюємо лише в пам'яті
    HAS_DB = False

# ----------------------------------------------------------------------------
# Налаштування сторінки
# ----------------------------------------------------------------------------
st.set_page_config(
    page_title="Центр моніторингу та безпеки",
    page_icon="🛡️",
    layout="wide",
)

# ----------------------------------------------------------------------------
# Константи та довідники
# ----------------------------------------------------------------------------
SERVICES = [
    "Біллінгова система",
    "Єдина база абонентів",
    "Корпоративна пошта",
    "Внутрішні сервери",
]

SERVERS = ["SRV-BILLING-01", "SRV-DB-01", "SRV-MAIL-01", "SRV-APP-01", "SRV-FILE-01"]

BACKUP_JOBS = [
    ("Біллінг — повний", "SRV-BILLING-01", 26),
    ("База абонентів — інкрементальний", "SRV-DB-01", 6),
    ("Пошта — повний", "SRV-MAIL-01", 26),
    ("Файловий сервер — повний", "SRV-FILE-01", 26),
    ("Застосунки — знімок ВМ", "SRV-APP-01", 26),
]

# Співробітники: (логін, місто, країна, lat, lon, IP)
EMPLOYEES = [
    ("o.kovalenko", "Київ", "Україна", 50.45, 30.52, "91.203.14.21"),
    ("i.melnyk", "Львів", "Україна", 49.84, 24.03, "91.203.22.87"),
    ("m.shevchenko", "Ужгород", "Україна", 48.62, 22.29, "91.203.31.5"),
    ("a.bondar", "Одеса", "Україна", 46.48, 30.73, "91.203.40.113"),
    ("v.tkachenko", "Харків", "Україна", 49.99, 36.23, "91.203.55.9"),
    ("n.kravchenko", "Дніпро", "Україна", 48.46, 35.05, "91.203.61.140"),
    ("d.oliynyk", "Київ", "Україна", 50.45, 30.52, "91.203.14.77"),
    ("s.moroz", "Львів", "Україна", 49.84, 24.03, "91.203.22.19"),
]

# Зовнішні (підозрілі) джерела: (місто, країна, lat, lon, IP)
EXTERNAL = [
    ("Амстердам", "Нідерланди", 52.37, 4.90, "185.220.101.34"),
    ("Франкфурт", "Німеччина", 50.11, 8.68, "45.153.160.12"),
    ("Сінгапур", "Сінгапур", 1.35, 103.82, "103.253.145.8"),
    ("Сан-Паулу", "Бразилія", -23.55, -46.63, "177.54.144.90"),
    ("Ешберн", "США", 39.04, -77.49, "34.201.55.170"),
    ("Ханой", "В'єтнам", 21.03, 105.85, "14.161.30.66"),
    ("Лагос", "Нігерія", 6.52, 3.38, "197.210.55.4"),
]

ATTACK_USERNAMES = ["admin", "root", "administrator", "billing", "postmaster", "test", "support"]
ACCESS_SYSTEMS = ["VPN", "Біллінг", "Пошта", "Адмін-панель", "SSH"]

STATUS_OK, STATUS_WARN, STATUS_DOWN = "Працює", "Деградація", "Недоступний"
STATUS_COLOR = {STATUS_OK: "#22c55e", STATUS_WARN: "#f59e0b", STATUS_DOWN: "#ef4444"}
STATUS_ICON = {STATUS_OK: "🟢", STATUS_WARN: "🟡", STATUS_DOWN: "🔴"}

MAX_LOG_ROWS = 3000
MAX_HISTORY = 90
MAX_FC_HISTORY = 360  # довша історія для прогнозу та аномалій
DB_URL_DEFAULT = "sqlite:///ops_center.db"

STATUS_OFF = "Вимкнено"
STATUS_COLOR[STATUS_OFF] = "#9ca3af"
STATUS_ICON[STATUS_OFF] = "⚪"

MAX_UPLOAD_MB = 20
UPLOAD_TYPES = ["pdf", "docx", "xlsx", "txt", "md"]

# --- Розділ 3: ОТ-інтеграції (SCADA / GIS / телемеханіка)
OT_SCADA = "SCADA/ОІК: диспетчерський центр"
OT_RTU_PS = "Телемеханіка: RTU підстанцій 110/35 кВ"
OT_RTU_RP = "Телемеханіка: РП/ТП 10 кВ (GPRS-шлюз)"
OT_INTEGRATIONS = [
    ("GIS: карта електромереж Вінниччини", "GIS", "WMS/WFS · REST"),
    ("GIS: шар підстанцій та ліній 35–110 кВ", "GIS", "WFS"),
    (OT_SCADA, "SCADA", "IEC 60870-5-104"),
    (OT_RTU_PS, "Телемеханіка", "IEC 60870-5-104"),
    (OT_RTU_RP, "Телемеханіка", "Modbus TCP · GPRS"),
    ("АСКОЕ: збір даних обліку", "Облік", "DLMS/COSEM"),
    ("OMS: журнал відключень", "OMS", "REST API"),
]

NODE_OK, NODE_STALE, NODE_LOST = "На зв'язку", "Застарілі дані", "Немає зв'язку"
NODE_COLOR = {NODE_OK: "#22c55e", NODE_STALE: "#f59e0b", NODE_LOST: "#ef4444"}
NODE_ICON = {NODE_OK: "🟢", NODE_STALE: "🟡", NODE_LOST: "🔴"}

# Умовні вузли (назва, тип, lat, lon, канал) — демо-дані
OT_NODES = [
    ("ПС «Вінниця-Центральна»", "ПС 110/35 кВ", 49.2331, 28.4682, OT_RTU_PS),
    ("ПС «Жмеринка»", "ПС 110/35 кВ", 49.0354, 28.1158, OT_RTU_PS),
    ("ПС «Хмільник»", "ПС 110/35 кВ", 49.5566, 27.9718, OT_RTU_PS),
    ("ПС «Гайсин»", "ПС 110/35 кВ", 48.8078, 29.3833, OT_RTU_PS),
    ("ПС «Могилів-Подільський»", "ПС 110/35 кВ", 48.4501, 27.7976, OT_RTU_PS),
    ("ПС «Козятин»", "ПС 110/35 кВ", 49.7139, 28.8378, OT_RTU_PS),
    ("ПС «Тульчин»", "ПС 110/35 кВ", 48.6772, 28.8497, OT_RTU_PS),
    ("РП-10 «Бар»", "РП 10 кВ", 49.0762, 27.6733, OT_RTU_RP),
    ("РП-10 «Ладижин»", "РП 10 кВ", 48.6833, 29.2333, OT_RTU_RP),
    ("РП-10 «Іллінці»", "РП 10 кВ", 49.1000, 29.2167, OT_RTU_RP),
    ("РП-10 «Липовець»", "РП 10 кВ", 49.2167, 29.0000, OT_RTU_RP),
    ("РП-10 «Немирів»", "РП 10 кВ", 48.9689, 28.8394, OT_RTU_RP),
]

SEVERITIES = ["Критично", "Високий", "Середній"]
SEV_ICON = {"Критично": "🔴", "Високий": "🟠", "Середній": "🟡"}
SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}

# (джерело, критичність, повідомлення) — збої ПЗ диспетчерів та бригад
ALERT_TEMPLATES = [
    ("ПЗ диспетчера (ОІК)", "Критично", "Втрачено з'єднання клієнта диспетчера ОІК із сервером реального часу"),
    ("ПЗ диспетчера (ОІК)", "Високий", "Затримка оновлення оперативної схеми понад 30 с"),
    ("Мобільний застосунок бригад", "Високий", "Збій синхронізації нарядів-допусків (бригада №{n})"),
    ("Мобільний застосунок бригад", "Середній", "Не вдалося передати GPS-трек бригади №{n}"),
    ("OMS", "Критично", "Помилка запису оперативної події у журнал відключень"),
    ("GIS", "Високий", "Тайли схеми електромереж не завантажуються (HTTP 503)"),
    ("Телемеханіка", "Критично", "Перевищено час опитування RTU (тайм-аут IEC 104)"),
    ("Наряди-допуски", "Високий", "Помилка формування наряду-допуску (БД недоступна)"),
]
ALERT_SOURCES = sorted(
    {t[0] for t in ALERT_TEMPLATES} | {i[1] for i in OT_INTEGRATIONS} | {"API-шлюз", "Інфраструктура", "Метеомоніторинг"}
)

# --- Розділ 4: API-шлюзи (назва, ендпоінт, протокол, базовий RPS, ліміт RPS, базова затримка мс)
GATEWAYS = [
    ("Держреєстри (обмін даними)", "/api/gov-registries", "REST · mTLS", 12, 50, 180),
    ("Кабінет споживача електроенергії", "/api/consumer-cabinet", "REST · OAuth2", 85, 300, 90),
    ("Платіжні шлюзи (біллінг)", "/api/payments", "REST · HMAC", 30, 120, 140),
    ("Обмін з оператором ринку", "/api/market-operator", "SOAP/XML", 6, 30, 260),
    ("SMS/Viber-інформування", "/api/notify", "REST", 20, 100, 110),
    ("Внутрішній API єдиної бази абонентів", "/internal/subscribers", "gRPC", 140, 500, 35),
    ("Міст ОТ ↔ портал (GIS/SCADA)", "/internal/ot-bridge", "REST · mTLS", 25, 100, 70),
]

# --- Ролі та рівні секретності документів
# clear — макс. рівень допуску; upload — може завантажувати/керувати; ack — обробка алертів;
# audit — бачить журнал дій; switch — може виконувати переключення в оперативному журналі
ROLES = {
    "Працівник": {"clear": 1, "upload": False, "ack": False, "audit": False, "switch": False},
    "Диспетчер": {"clear": 2, "upload": False, "ack": True, "audit": False, "switch": True},
    "Спеціаліст з ІБ": {"clear": 3, "upload": True, "ack": True, "audit": True, "switch": False},
    "Адміністратор": {"clear": 3, "upload": True, "ack": True, "audit": True, "switch": True},
}
LEVELS = {0: "Публічний", 1: "Внутрішній", 2: "Для службового користування", 3: "Конфіденційний"}
LEVEL_ICON = {0: "🟢", 1: "🔵", 2: "🟠", 3: "🔴"}
CATEGORIES = [
    "Внутрішній регламент",
    "Інструкція з кібербезпеки",
    "Технічний регламент",
    "Наказ / розпорядження",
    "Інструкція для бригад",
]

# --- Розділи 6–9: інциденти, активи, SLA
INC_STATUSES = ["Відкрито", "В роботі", "Локалізовано", "Закрито"]
SLA_TARGET = 99.9
CRIT_LABEL = {1: "Низька", 2: "Середня", 3: "Висока"}

PLAYBOOKS = {
    "Brute-force / компрометація облікового запису": [
        "Заблокувати IP-адресу джерела на міжмережевому екрані",
        "Перевірити успішні входи з цього IP за останні 24 год",
        "Примусово скинути паролі уражених облікових записів",
        "Перевірити ввімкнення MFA для адміністративних систем",
        "Задокументувати інцидент і повідомити керівника ІБ",
    ],
    "Втрата зв'язку SCADA / телемеханіки": [
        "Повідомити чергового диспетчера та перейти на резервний канал",
        "Перевірити канал зв'язку (GPRS/оптика) та живлення шлюзу",
        "Перевірити міжмережевий екран між ОТ та ІТ сегментами",
        "Зафіксувати час втрати та відновлення для звіту",
    ],
    "Збій API-шлюзу": [
        "Перевірити логи шлюзу та частку помилок",
        "Перезапустити шлюз у розділі «API та шлюзи»",
        "Перевірити термін дії ключів і сертифікатів",
        "Повідомити зовнішніх партнерів про можливі затримки",
    ],
    "Збій ПЗ диспетчера / бригад": [
        "Перевірити доступність сервера реального часу / БД",
        "Зв'язатися з диспетчером або бригадою",
        "Перезапустити службу застосунку",
        "Перевірити синхронізацію нарядів-допусків",
    ],
    "Заповнення диска / ємність": [
        "Визначити, що саме швидко росте (логи, БД, тимчасові файли)",
        "Очистити/архівувати логи та тимчасові дані",
        "Перевірити, що резервні копії не накопичуються локально",
        "Розширити том або перенести дані на додаткове сховище",
        "Налаштувати ротацію логів / квоти, щоб запобігти повторенню",
    ],
    "Загальний інцидент": [
        "Оцінити вплив і залучити відповідальних",
        "Локалізувати проблему",
        "Відновити роботу сервісу",
        "Провести розбір причин",
    ],
}


# ----------------------------------------------------------------------------
# Симуляція даних (замініть на реальні джерела)
# ----------------------------------------------------------------------------
def _make_event(rng: np.random.Generator, ts: datetime, attacker: tuple | None = None) -> dict:
    """Одна подія авторизації."""
    if attacker is not None:
        city, country, lat, lon, ip = attacker
        return {
            "time": ts,
            "user": str(rng.choice(ATTACK_USERNAMES)),
            "ip": ip,
            "city": city,
            "country": country,
            "lat": lat,
            "lon": lon,
            "system": str(rng.choice(["VPN", "SSH", "Адмін-панель"])),
            # дуже мала ймовірність, що підбір вдався
            "result": "Успішно" if rng.random() < 0.004 else "Невдало",
        }

    # звичайна активність співробітників
    if rng.random() < 0.03:  # вхід із «дивної» геолокації
        city, country, lat, lon, ip = EXTERNAL[rng.integers(len(EXTERNAL))]
        user = EMPLOYEES[rng.integers(len(EMPLOYEES))][0]
    else:
        user, city, country, lat, lon, ip = EMPLOYEES[rng.integers(len(EMPLOYEES))]
    return {
        "time": ts,
        "user": user,
        "ip": ip,
        "city": city,
        "country": country,
        "lat": lat,
        "lon": lon,
        "system": str(rng.choice(ACCESS_SYSTEMS)),
        "result": "Успішно" if rng.random() < 0.93 else "Невдало",
    }


def init_state() -> None:
    """Початкова ініціалізація симуляції."""
    if "initialized" in st.session_state:
        return

    rng = np.random.default_rng()
    ss = st.session_state
    ss.rng = rng
    ss.attack_ticks = 0
    ss.attacker = None
    ss.tick_n = 0
    ss.fc_alerted = set()

    # --- Сервіси
    ss.services = {
        name: {
            "status": STATUS_OK,
            "latency": float(rng.uniform(20, 80)),
            "uptime": float(rng.uniform(99.6, 99.99)),
            "since": datetime.now(),
        }
        for name in SERVICES
    }

    # --- Логи авторизації за останню годину
    now = datetime.now()
    events = [
        _make_event(rng, now - timedelta(seconds=int(s)))
        for s in sorted(rng.uniform(0, 3600, 220), reverse=True)
    ]
    ss.logs = pd.DataFrame(events)

    # --- Сервери
    ss.servers = {
        s: {
            "cpu": float(rng.uniform(20, 55)),
            "ram": float(rng.uniform(40, 70)),
            "disk": float(rng.uniform(45, 80)),
            "net": float(rng.uniform(50, 400)),
            "disk_rate": float(rng.uniform(0.5, 6.0)),  # демо-швидкість росту диска, %/год
        }
        for s in SERVERS
    }
    ss.cpu_hist = pd.DataFrame(
        {s: [ss.servers[s]["cpu"]] for s in SERVERS}, index=[now]
    )
    ss.ram_hist = pd.DataFrame(
        {s: [ss.servers[s]["ram"]] for s in SERVERS}, index=[now]
    )
    ss.disk_hist = pd.DataFrame(
        {s: [ss.servers[s]["disk"]] for s in SERVERS}, index=[now]
    )

    # --- Бекапи
    backups = []
    for name, host, max_age_h in BACKUP_JOBS:
        backups.append(
            {
                "Завдання": name,
                "Сервер": host,
                "Останній запуск": now - timedelta(hours=float(rng.uniform(1, max_age_h - 3))),
                "Статус": "Успішно",
                "Розмір, ГБ": round(float(rng.uniform(20, 900)), 1),
                "Тривалість, хв": int(rng.integers(8, 95)),
                "Макс. вік, год": max_age_h,
            }
        )
    ss.backups = pd.DataFrame(backups)

    init_extra_state()
    init_ext_state()
    init_switch_state()
    load_persistent_state()  # відновлення збереженого стану з БД
    ss.initialized = True


def tick_services() -> None:
    rng = st.session_state.rng
    for name, s in st.session_state.services.items():
        r = rng.random()
        if s["status"] == STATUS_OK and r < 0.025:
            s["status"], s["since"] = STATUS_WARN, datetime.now()
        elif s["status"] == STATUS_OK and r < 0.030:
            s["status"], s["since"] = STATUS_DOWN, datetime.now()
        elif s["status"] != STATUS_OK and r < 0.35:
            s["status"], s["since"] = STATUS_OK, datetime.now()

        base = {STATUS_OK: 45, STATUS_WARN: 380, STATUS_DOWN: 0}[s["status"]]
        s["latency"] = 0.0 if s["status"] == STATUS_DOWN else max(
            5.0, base + float(rng.normal(0, base * 0.2 + 5))
        )
        if s["status"] == STATUS_DOWN:
            s["uptime"] = max(90.0, s["uptime"] - 0.05)
        elif s["status"] == STATUS_WARN:
            s["uptime"] = max(90.0, s["uptime"] - 0.005)
        else:
            s["uptime"] = min(99.999, s["uptime"] + 0.0005)


def tick_auth_logs() -> None:
    ss = st.session_state
    rng = ss.rng
    now = datetime.now()

    # випадковий старт атаки (рідко) або за кнопкою
    if ss.attack_ticks == 0 and rng.random() < 0.02:
        ss.attack_ticks = int(rng.integers(3, 7))
    if ss.attack_ticks > 0 and ss.attacker is None:
        ss.attacker = EXTERNAL[rng.integers(len(EXTERNAL))]

    new_events = [_make_event(rng, now) for _ in range(int(rng.integers(2, 8)))]

    if ss.attack_ticks > 0:
        new_events += [
            _make_event(rng, now, attacker=ss.attacker)
            for _ in range(int(rng.integers(15, 35)))
        ]
        ss.attack_ticks -= 1
        if ss.attack_ticks == 0:
            ss.attacker = None

    ss.logs = pd.concat([ss.logs, pd.DataFrame(new_events)], ignore_index=True).tail(MAX_LOG_ROWS)


def tick_servers() -> None:
    ss = st.session_state
    rng = ss.rng
    now = datetime.now()
    dt = min((now - ss.get("last_tick", now)).total_seconds(), 120.0)
    ss.last_tick = now
    for name, m in ss.servers.items():
        m["cpu"] = float(np.clip(m["cpu"] + rng.normal(0, 6) + (rng.random() < 0.03) * 30, 3, 100))
        m["cpu"] = m["cpu"] * 0.93 + 35 * 0.07  # повернення до середнього
        m["ram"] = float(np.clip(m["ram"] + rng.normal(0, 1.5), 15, 99))
        step = m.get("disk_rate", 2.0) * dt / 3600  # ріст прив'язаний до реального часу, %
        m["disk"] += abs(float(rng.normal(step, step * 0.5)))
        if m["disk"] >= 97:  # імітація очищення диска адміністратором
            m["disk"] -= float(rng.uniform(15, 30))
        m["disk"] = float(np.clip(m["disk"], 10, 99))
        m["net"] = float(np.clip(m["net"] + rng.normal(0, 40), 5, 1000))

    ss.cpu_hist.loc[now] = [ss.servers[s]["cpu"] for s in SERVERS]
    ss.ram_hist.loc[now] = [ss.servers[s]["ram"] for s in SERVERS]
    ss.disk_hist.loc[now] = [ss.servers[s]["disk"] for s in SERVERS]
    ss.cpu_hist = ss.cpu_hist.tail(MAX_FC_HISTORY)
    ss.ram_hist = ss.ram_hist.tail(MAX_FC_HISTORY)
    ss.disk_hist = ss.disk_hist.tail(MAX_FC_HISTORY)

    ss.tick_n += 1
    db_save_metrics(now, ss.servers)
    if ss.tick_n % 500 == 0:
        db_prune_metrics()


def get_backups() -> pd.DataFrame:
    """Стан резервного копіювання (з рідкісними збоями для демонстрації)."""
    ss = st.session_state
    rng = ss.rng
    now = datetime.now()
    df = ss.backups
    for i in df.index:
        # завдання іноді перезапускаються
        if rng.random() < 0.01:
            failed = rng.random() < 0.25
            df.at[i, "Останній запуск"] = now
            df.at[i, "Статус"] = "Помилка" if failed else "Успішно"
            df.at[i, "Розмір, ГБ"] = round(float(rng.uniform(20, 900)), 1)
            df.at[i, "Тривалість, хв"] = int(rng.integers(8, 95))
        elif df.at[i, "Статус"] == "Помилка" and rng.random() < 0.05:
            df.at[i, "Статус"] = "Успішно"
            df.at[i, "Останній запуск"] = now

    out = df.copy()
    out["Вік, год"] = ((now - out["Останній запуск"]).dt.total_seconds() / 3600).round(1)

    def _state(row) -> str:
        if row["Статус"] == "Помилка":
            return "🔴 Помилка"
        if row["Вік, год"] > row["Макс. вік, год"]:
            return "🟡 Прострочено"
        return "🟢 Актуально"

    out["Стан"] = out.apply(_state, axis=1)
    return out


# ----------------------------------------------------------------------------
# Аналітика безпеки
# ----------------------------------------------------------------------------
def analyze_security(df: pd.DataFrame, window_min: int, threshold: int):
    """Повертає (вікно логів, brute-force IP, список сповіщень)."""
    cutoff = datetime.now() - timedelta(minutes=window_min)
    w = df[df["time"] >= cutoff].copy()

    failed = w[w["result"] == "Невдало"]
    per_ip = (
        failed.groupby(["ip", "city", "country"])
        .agg(спроб=("user", "size"), логінів=("user", "nunique"), остання=("time", "max"))
        .reset_index()
    )
    brute = per_ip[per_ip["спроб"] >= threshold].sort_values("спроб", ascending=False)

    alerts = []
    brute_ips = set(brute["ip"])

    for _, r in brute.iterrows():
        alerts.append(
            {
                "Час": r["остання"],
                "Рівень": "🔴 Критично" if r["спроб"] >= threshold * 3 else "🟠 Високий",
                "Тип": "Brute-force атака",
                "Опис": f"{r['спроб']} невдалих спроб з {r['ip']} ({r['city']}, {r['country']}), "
                f"перебрано {r['логінів']} логінів",
            }
        )

    # успішний вхід з IP, що підбирав паролі — можливий злам
    comp = w[(w["result"] == "Успішно") & (w["ip"].isin(brute_ips))]
    for _, r in comp.iterrows():
        alerts.append(
            {
                "Час": r["time"],
                "Рівень": "🔴 Критично",
                "Тип": "Можливий злам облікового запису",
                "Опис": f"Успішний вхід «{r['user']}» з {r['ip']} ({r['city']}) після серії невдалих спроб",
            }
        )

    # успішні входи співробітників із-за кордону
    geo = w[(w["result"] == "Успішно") & (w["country"] != "Україна") & (~w["ip"].isin(brute_ips))]
    for _, r in geo.iterrows():
        alerts.append(
            {
                "Час": r["time"],
                "Рівень": "🟡 Середній",
                "Тип": "Незвична геолокація",
                "Опис": f"«{r['user']}» увійшов з {r['city']}, {r['country']} ({r['ip']}) → {r['system']}",
            }
        )

    alerts_df = pd.DataFrame(alerts, columns=["Час", "Рівень", "Тип", "Опис"])
    if not alerts_df.empty:
        order = {"🔴 Критично": 0, "🟠 Високий": 1, "🟡 Середній": 2}
        alerts_df["_o"] = alerts_df["Рівень"].map(order)
        alerts_df = alerts_df.sort_values(["_o", "Час"], ascending=[True, False]).drop(columns="_o")
    return w, brute, alerts_df


# ----------------------------------------------------------------------------
# UI-компоненти
# ----------------------------------------------------------------------------
CSS = """
<style>
.svc-card {border-radius: 14px; padding: 16px 18px; border: 1px solid rgba(128,128,128,.25);
           background: rgba(128,128,128,.07); height: 100%;}
.svc-title {font-size: 0.95rem; opacity: .8; margin-bottom: 6px;}
.svc-status {font-size: 1.35rem; font-weight: 700;}
.svc-meta {font-size: .8rem; opacity: .7; margin-top: 6px;}
.dot {display:inline-block; width:12px; height:12px; border-radius:50%; margin-right:8px;
      box-shadow: 0 0 8px currentColor;}
.overall {border-radius: 14px; padding: 14px 20px; font-size: 1.15rem; font-weight: 700;
          color: white; margin-bottom: 14px;}
</style>
"""


def render_overall_and_services() -> None:
    services = st.session_state.services
    statuses = [s["status"] for s in services.values()]
    down = statuses.count(STATUS_DOWN)
    warn = statuses.count(STATUS_WARN)

    if down:
        color, text = "#ef4444", f"🔴 КРИТИЧНО: недоступних сервісів — {down}"
    elif warn:
        color, text = "#f59e0b", f"🟡 УВАГА: сервісів із деградацією — {warn}"
    else:
        color, text = "#16a34a", "🟢 Усі критичні сервіси працюють штатно"

    st.markdown(
        f'<div class="overall" style="background:{color}">{text}'
        f'<span style="float:right;font-weight:400;font-size:.9rem">'
        f'оновлено {datetime.now():%H:%M:%S}</span></div>',
        unsafe_allow_html=True,
    )

    cols = st.columns(len(SERVICES))
    for col, (name, s) in zip(cols, services.items()):
        c = STATUS_COLOR[s["status"]]
        lat = "—" if s["status"] == STATUS_DOWN else f"{s['latency']:.0f} мс"
        col.markdown(
            f"""
            <div class="svc-card">
              <div class="svc-title">{name}</div>
              <div class="svc-status" style="color:{c}">
                <span class="dot" style="background:{c};color:{c}"></span>{s['status']}
              </div>
              <div class="svc-meta">Відгук: {lat}<br>
              Uptime: {s['uptime']:.3f}%<br>
              У цьому стані з {s['since']:%H:%M:%S}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_security(window_min: int, threshold: int) -> None:
    logs = st.session_state.logs
    w, brute, alerts = analyze_security(logs, window_min, threshold)

    total = len(w)
    ok = int((w["result"] == "Успішно").sum())
    bad = total - ok
    foreign = int(((w["result"] == "Успішно") & (w["country"] != "Україна")).sum())

    k1, k2, k3, k4, k5 = st.columns(5)
    k1.metric("Спроб авторизації", total)
    k2.metric("Успішних", ok)
    k3.metric("Невдалих", bad, delta=f"{bad / total * 100:.0f}%" if total else None, delta_color="inverse")
    k4.metric("IP під підозрою (brute-force)", len(brute))
    k5.metric("Входів із-за кордону", foreign)

    if not brute.empty:
        st.error(
            f"⚠️ Виявлено brute-force активність: {len(brute)} IP-адрес(и) "
            f"перевищили поріг {threshold} невдалих спроб за {window_min} хв."
        )

    left, right = st.columns([3, 2])

    # --- Карта
    with left:
        st.subheader("🗺️ Географія входів")
        if w.empty:
            st.info("Немає подій у вибраному вікні.")
        else:
            geo = (
                w.groupby(["city", "country", "lat", "lon", "result"])
                .size()
                .reset_index(name="n")
            )
            brute_cities = set(brute["city"]) if not brute.empty else set()

            fig = go.Figure()
            for res, color in [("Успішно", "#22c55e"), ("Невдало", "#ef4444")]:
                g = geo[geo["result"] == res]
                fig.add_trace(
                    go.Scattergeo(
                        lat=g["lat"],
                        lon=g["lon"],
                        text=g["city"] + ", " + g["country"] + " — " + g["n"].astype(str),
                        hoverinfo="text",
                        name=res,
                        marker=dict(
                            size=np.clip(g["n"] * 1.5 + 7, 8, 55),
                            color=color,
                            opacity=0.65,
                            line=dict(
                                width=[3 if c in brute_cities else 0.5 for c in g["city"]],
                                color=["#000000" if c in brute_cities else "white" for c in g["city"]],
                            ),
                        ),
                    )
                )
            fig.update_geos(
                projection_type="natural earth",
                showcountries=True,
                showland=True,
                landcolor="rgba(128,128,128,0.15)",
                countrycolor="rgba(128,128,128,0.4)",
                showocean=False,
                bgcolor="rgba(0,0,0,0)",
            )
            fig.update_layout(
                height=430,
                margin=dict(l=0, r=0, t=0, b=0),
                paper_bgcolor="rgba(0,0,0,0)",
                legend=dict(orientation="h", y=-0.05),
            )
            plotly_chart(fig, width="stretch", key="geo_map")

    # --- Динаміка
    with right:
        st.subheader("📈 Динаміка спроб")
        if not w.empty:
            t = w.copy()
            span = max(window_min, 1)
            freq = "1min" if span <= 60 else "5min"
            t["bin"] = t["time"].dt.floor(freq)
            ts = t.groupby(["bin", "result"]).size().reset_index(name="n")
            fig2 = px.bar(
                ts,
                x="bin",
                y="n",
                color="result",
                color_discrete_map={"Успішно": "#22c55e", "Невдало": "#ef4444"},
                labels={"bin": "", "n": "Кількість", "result": ""},
            )
            fig2.update_layout(
                height=430,
                margin=dict(l=0, r=0, t=10, b=0),
                legend=dict(orientation="h", y=1.08),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
            )
            plotly_chart(fig2, width="stretch", key="auth_timeline")

    # --- Сповіщення
    st.subheader("🚨 Сповіщення про підозрілу активність")
    if alerts.empty:
        st.success("Підозрілої активності не виявлено.")
    else:
        st.dataframe(
            alerts,
            hide_index=True,
            width="stretch",
            column_config={"Час": st.column_config.DatetimeColumn(format="HH:mm:ss")},
            height=min(400, 60 + 35 * len(alerts)),
        )

    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Топ IP за невдалими спробами")
        failed_ip = (
            w[w["result"] == "Невдало"]
            .groupby(["ip", "city", "country"])
            .size()
            .reset_index(name="Невдалих спроб")
            .sort_values("Невдалих спроб", ascending=False)
            .head(8)
            .rename(columns={"ip": "IP", "city": "Місто", "country": "Країна"})
        )
        if failed_ip.empty:
            st.caption("Немає невдалих спроб.")
        else:
            st.dataframe(
                failed_ip,
                hide_index=True,
                width="stretch",
                column_config={
                    "Невдалих спроб": st.column_config.ProgressColumn(
                        min_value=0, max_value=int(failed_ip["Невдалих спроб"].max()), format="%d"
                    )
                },
            )
    with c2:
        st.subheader("Останні події авторизації")
        last = (
            w.sort_values("time", ascending=False)
            .head(50)[["time", "user", "system", "ip", "city", "country", "result"]]
            .rename(
                columns={
                    "time": "Час",
                    "user": "Логін",
                    "system": "Система",
                    "ip": "IP",
                    "city": "Місто",
                    "country": "Країна",
                    "result": "Результат",
                }
            )
        )
        st.dataframe(
            last,
            hide_index=True,
            width="stretch",
            height=300,
            column_config={"Час": st.column_config.DatetimeColumn(format="HH:mm:ss")},
        )


def _threshold_color(v: float, warn: float, crit: float) -> str:
    return "#ef4444" if v >= crit else "#f59e0b" if v >= warn else "#22c55e"


def render_infrastructure() -> None:
    ss = st.session_state
    rows = []
    for name, m in ss.servers.items():
        rows.append(
            {
                "Сервер": name,
                "CPU, %": round(m["cpu"], 1),
                "RAM, %": round(m["ram"], 1),
                "Диск, %": round(m["disk"], 1),
                "Мережа, Мбіт/с": round(m["net"]),
            }
        )
    df = pd.DataFrame(rows)

    # KPI
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Середнє навантаження CPU", f"{df['CPU, %'].mean():.0f}%")
    k2.metric("Середнє використання RAM", f"{df['RAM, %'].mean():.0f}%")
    k3.metric("Найзаповненіший диск", f"{df['Диск, %'].max():.0f}%",
              help=df.loc[df["Диск, %"].idxmax(), "Сервер"])
    hot = int(((df["CPU, %"] > 85) | (df["RAM, %"] > 90) | (df["Диск, %"] > 90)).sum())
    k4.metric("Серверів у критичному стані", hot, delta_color="inverse",
              delta="потрібна увага" if hot else "норма")

    st.subheader("🖥️ Стан серверів")
    st.dataframe(
        df,
        hide_index=True,
        width="stretch",
        column_config={
            "CPU, %": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%.0f%%"),
            "RAM, %": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%.0f%%"),
            "Диск, %": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%.0f%%"),
            "Мережа, Мбіт/с": st.column_config.NumberColumn(format="%d"),
        },
    )

    # Графіки історії
    c1, c2 = st.columns(2)
    for col, hist, title, key in [
        (c1, ss.cpu_hist.tail(MAX_HISTORY), "Навантаження CPU, %", "cpu_chart"),
        (c2, ss.ram_hist.tail(MAX_HISTORY), "Використання RAM, %", "ram_chart"),
    ]:
        with col:
            st.subheader(title)
            long = hist.reset_index().melt(id_vars="index", var_name="Сервер", value_name="val")
            fig = px.line(long, x="index", y="val", color="Сервер",
                          labels={"index": "", "val": "%"})
            fig.add_hline(y=85, line_dash="dot", line_color="#ef4444", opacity=0.6)
            fig.update_yaxes(range=[0, 100])
            fig.update_layout(
                height=330,
                margin=dict(l=0, r=0, t=10, b=0),
                legend=dict(orientation="h", y=-0.2, title=""),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
            )
            plotly_chart(fig, width="stretch", key=key)

    # Бекапи
    st.subheader("💾 Резервне копіювання")
    b = get_backups()
    bad = int(b["Стан"].str.contains("Помилка|Прострочено").sum())
    if bad:
        st.warning(f"Завдань бекапу, що потребують уваги: {bad}")
    else:
        st.success("Усі завдання резервного копіювання виконані вчасно.")

    st.dataframe(
        b[["Стан", "Завдання", "Сервер", "Останній запуск", "Вік, год", "Розмір, ГБ", "Тривалість, хв"]],
        hide_index=True,
        width="stretch",
        column_config={
            "Останній запуск": st.column_config.DatetimeColumn(format="DD.MM HH:mm"),
            "Розмір, ГБ": st.column_config.NumberColumn(format="%.1f"),
        },
    )

    render_forecast()


# ----------------------------------------------------------------------------
# Збереження стану (SQLite за замовчуванням, PostgreSQL через DATABASE_URL)
# ----------------------------------------------------------------------------
if HAS_DB:
    _meta = MetaData()
    t_audit = Table(
        "audit", _meta,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("ts", DateTime, index=True),
        Column("role", String(64)),
        Column("action", String(64)),
        Column("detail", Text),
    )
    t_inc = Table(
        "incidents", _meta,
        Column("id", String(16), primary_key=True),
        Column("status", String(32)),
        Column("severity", String(16)),
        Column("created", DateTime),
        Column("payload", Text),  # повний інцидент у JSON (кроки плейбука, таймлайн)
    )
    t_doc = Table(
        "documents", _meta,
        Column("id", String(16), primary_key=True),
        Column("title", Text),
        Column("category", String(64)),
        Column("level", Integer),
        Column("version", String(32)),
        Column("owner", String(128)),
        Column("updated", DateTime),
        Column("filename", String(255)),
        Column("size", Integer),
        Column("sha", String(64)),
        Column("history", Text),
        Column("content", LargeBinary),
    )
    t_met = Table(
        "metrics", _meta,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("ts", DateTime, index=True),
        Column("server", String(64), index=True),
        Column("cpu", Float),
        Column("ram", Float),
        Column("disk", Float),
    )


if HAS_DB:
    t_swdev = Table(
        "switch_devices", _meta,
        Column("id", String(190), primary_key=True),
        Column("node", String(128)),
        Column("bay", String(64)),
        Column("name", String(128)),
        Column("kind", String(32)),
        Column("state", String(16)),
        Column("updated", DateTime),
        Column("updated_by", String(128)),
    )
    t_swlog = Table(
        "switch_log", _meta,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("ts", DateTime, index=True),
        Column("node", String(128), index=True),
        Column("device_id", String(190)),
        Column("device", String(128)),
        Column("kind", String(32)),
        Column("from_state", String(16)),
        Column("to_state", String(16)),
        Column("operator", String(128)),
        Column("role", String(64)),
        Column("order_no", String(64)),
        Column("reason", Text),
        Column("auto", Integer),
    )
    t_gis = Table(
        "gis_layers", _meta,
        Column("id", String(32), primary_key=True),
        Column("name", String(255)),
        Column("kind", String(16)),
        Column("source", String(255)),
        Column("uploaded", DateTime),
        Column("visible", Integer),
        Column("geojson", Text),
    )
    t_node = Table(
        "ot_nodes", _meta,
        Column("name", String(128), primary_key=True),
        Column("kind", String(64)),
        Column("lat", Float),
        Column("lon", Float),
        Column("parent", String(190)),
    )


def _json_default(o):
    if isinstance(o, datetime):
        return o.isoformat()
    return str(o)


def _dt(v):
    return datetime.fromisoformat(v) if isinstance(v, str) else v


def db_safe(default=None):
    """Помилки БД не повинні ламати дашборд: фіксуємо їх і працюємо далі в пам'яті."""

    def deco(fn):
        @functools.wraps(fn)
        def wrap(*args, **kwargs):
            if not HAS_DB:
                return default
            try:
                result = fn(*args, **kwargs)
                st.session_state.pop("db_error", None)
                return result
            except Exception as e:
                st.session_state["db_error"] = str(e)[:200]
                return default

        return wrap

    return deco


@st.cache_resource(show_spinner=False)
def get_engine():
    url = _secret("DATABASE_URL") or DB_URL_DEFAULT
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+psycopg2://", 1)
    elif url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+psycopg2://", 1)
    kwargs = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    engine = create_engine(url, **kwargs)
    _meta.create_all(engine)
    return engine


def db_status() -> tuple[bool, str]:
    if not HAS_DB:
        return False, "SQLAlchemy не встановлено — дані лише в пам'яті (pip install sqlalchemy)"
    err = st.session_state.get("db_error")
    if err:
        return False, f"Помилка БД: {err}"
    try:
        return True, get_engine().dialect.name
    except Exception as e:
        return False, f"БД недоступна: {str(e)[:150]}"


def _upsert(conn, table, key: str, values: dict) -> None:
    res = conn.execute(update(table).where(table.c[key] == values[key]).values(**values))
    if res.rowcount == 0:
        conn.execute(insert(table).values(**values))


# --- журнал дій
@db_safe()
def db_add_audit(entry: dict) -> None:
    with get_engine().begin() as c:
        c.execute(insert(t_audit).values(
            ts=entry["Час"], role=str(entry["Роль"]), action=entry["Дія"], detail=entry["Деталі"]))


@db_safe(None)
def db_load_audit(limit: int = 500):
    with get_engine().connect() as c:
        rows = c.execute(
            select(t_audit.c.ts, t_audit.c.role, t_audit.c.action, t_audit.c.detail)
            .order_by(t_audit.c.id.desc()).limit(limit)
        ).fetchall()
    return [{"Час": r[0], "Роль": r[1], "Дія": r[2], "Деталі": r[3]} for r in reversed(rows)]


# --- інциденти
@db_safe()
def db_save_incident(inc: dict) -> None:
    vals = dict(
        id=inc["id"], status=inc["status"], severity=inc["severity"], created=inc["created"],
        payload=json.dumps(inc, ensure_ascii=False, default=_json_default),
    )
    with get_engine().begin() as c:
        _upsert(c, t_inc, "id", vals)


@db_safe(None)
def db_load_incidents():
    with get_engine().connect() as c:
        rows = c.execute(select(t_inc.c.payload).order_by(t_inc.c.created)).fetchall()
    out = []
    for (payload,) in rows:
        d = json.loads(payload)
        for k in ("created", "acked", "closed"):
            d[k] = _dt(d.get(k))
        d["timeline"] = [(_dt(t), w, x) for t, w, x in d["timeline"]]
        d["alert_id"] = None  # ID сповіщень не зберігаються між запусками — зв'язок скидаємо
        out.append(d)
    return out


# --- документи (разом із вмістом файлів)
@db_safe()
def db_save_doc(d: dict) -> None:
    vals = dict(
        id=d["id"], title=d["title"], category=d["category"], level=d["level"], version=d["version"],
        owner=d["owner"], updated=d["updated"], filename=d["filename"], size=d["size"], sha=d["sha"],
        history=json.dumps(d["history"], ensure_ascii=False, default=_json_default),
        content=d["content"],
    )
    with get_engine().begin() as c:
        _upsert(c, t_doc, "id", vals)


@db_safe(None)
def db_count_docs():
    with get_engine().connect() as c:
        return int(c.execute(select(func.count()).select_from(t_doc)).scalar())


@db_safe(None)
def db_load_docs():
    with get_engine().connect() as c:
        rows = c.execute(select(t_doc).order_by(t_doc.c.id)).mappings().all()
    docs = []
    for r in rows:
        hist = json.loads(r["history"] or "[]")
        for h in hist:
            h["Оновлено"] = _dt(h.get("Оновлено"))
        docs.append({
            "id": r["id"], "title": r["title"], "category": r["category"], "level": r["level"],
            "version": r["version"], "owner": r["owner"], "updated": r["updated"],
            "content": bytes(r["content"]), "filename": r["filename"], "size": r["size"],
            "sha": r["sha"], "history": hist,
        })
    return docs


# --- метрики серверів (для прогнозу, щоб історія переживала перезапуск)
@db_safe()
def db_save_metrics(ts: datetime, servers: dict) -> None:
    rows = [dict(ts=ts, server=n, cpu=float(m["cpu"]), ram=float(m["ram"]), disk=float(m["disk"]))
            for n, m in servers.items()]
    with get_engine().begin() as c:
        c.execute(insert(t_met), rows)


@db_safe()
def db_prune_metrics(days: int = 14) -> None:
    with get_engine().begin() as c:
        c.execute(delete(t_met).where(t_met.c.ts < datetime.now() - timedelta(days=days)))


@db_safe(None)
def db_load_metrics(n_rows: int):
    with get_engine().connect() as c:
        rows = c.execute(
            select(t_met.c.ts, t_met.c.server, t_met.c.cpu, t_met.c.ram, t_met.c.disk)
            .order_by(t_met.c.ts.desc()).limit(n_rows)
        ).fetchall()
    return pd.DataFrame([tuple(r) for r in rows], columns=["ts", "server", "cpu", "ram", "disk"])


@db_safe()
def db_clear_all() -> None:
    with get_engine().begin() as c:
        for t in (t_audit, t_inc, t_doc, t_met, t_swdev, t_swlog, t_gis, t_node):
            c.execute(delete(t))


def load_persistent_state() -> None:
    """Підвантажує збережений стан після (пере)запуску. Порожня БД заповнюється початковими даними."""
    ss = st.session_state
    if not HAS_DB:
        return
    n_docs = db_count_docs()
    if n_docs is None:  # БД недоступна — працюємо в пам'яті
        return
    load_persistent_ot()

    if n_docs == 0:
        for d in ss.docs:
            db_save_doc(d)
    else:
        docs = db_load_docs()
        if docs:
            ss.docs = docs
            ss.doc_seq = max(int(d["id"].split("-")[1]) for d in docs)

    incs = db_load_incidents()
    if incs:
        ss.incidents = incs
        ss.inc_seq = max(int(i["id"].split("-")[1]) for i in incs)

    audit = db_load_audit()
    if audit:
        ss.audit = audit

    m = db_load_metrics(MAX_FC_HISTORY * len(SERVERS))
    if m is not None and not m.empty:
        m["ts"] = pd.to_datetime(m["ts"])
        last = m.sort_values("ts").groupby("server").tail(1)
        for _, r in last.iterrows():
            if r["server"] in ss.servers:
                ss.servers[r["server"]].update(cpu=float(r["cpu"]), ram=float(r["ram"]), disk=float(r["disk"]))

        def piv(col: str) -> pd.DataFrame:
            p = m.pivot_table(index="ts", columns="server", values=col, aggfunc="mean").sort_index()
            p = p.reindex(columns=SERVERS)
            p.index.name, p.columns.name = None, None  # reset_index() у графіках очікує колонку "index"
            return p

        if m["ts"].nunique() >= 2:
            ss.cpu_hist = piv("cpu").tail(MAX_FC_HISTORY)
            ss.ram_hist = piv("ram").tail(MAX_FC_HISTORY)
            ss.disk_hist = piv("disk").tail(MAX_FC_HISTORY)


# ----------------------------------------------------------------------------
# Розділ 11: Прогноз заповнення дисків та виявлення аномалій
# ----------------------------------------------------------------------------
def fmt_eta(td: timedelta | None) -> str:
    if td is None:
        return "не заповниться (тренд ≤ 0)"
    h = td.total_seconds() / 3600
    if h < 1:
        return f"{int(h * 60)} хв"
    if h < 48:
        return f"{h:.1f} год"
    if h < 365 * 24:
        return f"{h / 24:.1f} дн"
    return "> 1 року"


def forecast_disk(series: pd.Series, window: int = 120, min_points: int = 15) -> dict | None:
    """Лінійний тренд заповнення диска. Враховує лише дані після останнього «очищення»."""
    s = series.dropna().tail(window)
    if len(s) >= 3:
        drops = np.where((s.diff() < -5).to_numpy())[0]
        if len(drops):
            s = s.iloc[drops[-1]:]
    if len(s) < min_points:
        return None
    x = np.asarray((s.index - s.index[0]).total_seconds(), dtype=float)
    y = s.to_numpy(dtype=float)
    if x[-1] <= 0:
        return None
    slope, icpt = np.polyfit(x, y, 1)  # % за секунду
    fit = slope * x + icpt
    ss_tot = float(((y - y.mean()) ** 2).sum())
    r2 = 1 - float(((y - fit) ** 2).sum()) / ss_tot if ss_tot > 0 else 0.0
    cur = float(y[-1])
    eta = timedelta(seconds=max((100 - cur) / slope, 0.0)) if slope > 1e-7 else None
    return {"cur": cur, "slope": float(slope), "slope_h": float(slope) * 3600, "r2": r2, "eta": eta, "n": len(s)}


def detect_anomalies(z_thr: float, recent_n: int = 10, base_n: int = 60) -> pd.DataFrame:
    """z-score: порівнюємо останні точки з базовим рівнем попередніх. Для диска аналізуємо приріст."""
    ss = st.session_state
    specs = [
        ("CPU, %", ss.cpu_hist, False, 0.5),
        ("RAM, %", ss.ram_hist, False, 0.5),
        ("Диск, приріст %/тік", ss.disk_hist, True, 0.002),
    ]
    rows = []
    for label, hist, use_diff, sd_floor in specs:
        for srv in SERVERS:
            if srv not in hist.columns:
                continue
            ser = hist[srv].dropna()
            if use_diff:
                ser = ser.diff().dropna()
            recent, base = ser.iloc[-recent_n:], ser.iloc[-(base_n + recent_n):-recent_n]
            if len(base) < 15 or len(recent) < 3:
                continue
            mu, sd = float(base.mean()), max(float(base.std(ddof=0)), sd_floor)
            z = (recent - mu) / sd
            i = int(np.argmax(np.abs(z.to_numpy())))
            zi = float(z.iloc[i])
            rows.append({
                "Статус": "🔴 Аномалія" if abs(zi) >= z_thr else "🟢 Норма",
                "Сервер": srv,
                "Метрика": label,
                "Значення": round(float(recent.iloc[i]), 3),
                "Базовий рівень": round(mu, 3),
                "σ": round(sd, 3),
                "z": round(zi, 1),
                "|z|": round(abs(zi), 1),
            })
    df = pd.DataFrame(rows, columns=["Статус", "Сервер", "Метрика", "Значення", "Базовий рівень", "σ", "z", "|z|"])
    return df.sort_values("|z|", ascending=False) if not df.empty else df


def check_disk_forecasts() -> None:
    """Створює сповіщення, коли диск, за прогнозом, заповниться швидше за заданий поріг."""
    ss = st.session_state
    if ss.tick_n % 6:
        return
    warn_h = ss.get("fc_warn_h", 24)
    for srv in SERVERS:
        fc = forecast_disk(ss.disk_hist[srv])
        eta_h = fc["eta"].total_seconds() / 3600 if fc and fc["eta"] is not None else None
        link = f"disk:{srv}"
        if eta_h is not None and eta_h <= warn_h:
            if srv not in ss.fc_alerted:
                sev = "Критично" if eta_h <= warn_h / 6 else "Високий"
                add_alert("Інфраструктура", sev,
                          f"Диск {srv} заповниться приблизно через {fmt_eta(fc['eta'])} (зараз {fc['cur']:.0f}%)",
                          link=link)
                ss.fc_alerted.add(srv)
        elif srv in ss.fc_alerted and (eta_h is None or eta_h > warn_h * 1.5):
            resolve_links(link)
            ss.fc_alerted.discard(srv)


def render_forecast() -> None:
    ss = st.session_state
    warn_h = ss.get("fc_warn_h", 24)
    z_thr = ss.get("z_thr", 3.0)
    now = datetime.now()

    st.divider()
    st.subheader("🔮 Прогноз заповнення дисків")
    rows, fcs = [], {}
    for srv in SERVERS:
        fc = forecast_disk(ss.disk_hist[srv])
        fcs[srv] = fc
        cur = round(ss.servers[srv]["disk"], 1)
        if fc is None:
            rows.append({"Ризик": "⚪ Недостатньо даних", "Сервер": srv, "Диск, %": cur, "Тренд, %/год": None,
                         "R²": None, "Заповниться через": "—", "Орієнтовна дата": pd.NaT})
            continue
        eta_h = fc["eta"].total_seconds() / 3600 if fc["eta"] is not None else None
        risk = ("🟢 Стабільно" if eta_h is None else "🔴 Критично" if eta_h <= warn_h / 6
                else "🟠 Увага" if eta_h <= warn_h else "🟢 Норма")
        when = now + fc["eta"] if fc["eta"] is not None and eta_h < 365 * 24 else pd.NaT
        rows.append({"Ризик": risk, "Сервер": srv, "Диск, %": cur, "Тренд, %/год": round(fc["slope_h"], 2),
                     "R²": round(fc["r2"], 2), "Заповниться через": fmt_eta(fc["eta"]), "Орієнтовна дата": when})
    df = pd.DataFrame(rows)

    at_risk = int(df["Ризик"].str.contains("Критично|Увага").sum())
    etas = [f["eta"] for f in fcs.values() if f and f["eta"] is not None]
    an = detect_anomalies(z_thr)
    n_anom = int((an["Статус"] == "🔴 Аномалія").sum()) if not an.empty else 0
    k1, k2, k3 = st.columns(3)
    k1.metric(f"Дисків під ризиком (< {warn_h} год)", at_risk, delta_color="inverse",
              delta="потрібна увага" if at_risk else "норма")
    k2.metric("Найближче заповнення", fmt_eta(min(etas)) if etas else "—")
    k3.metric("Активних аномалій", n_anom, delta_color="inverse", delta="перевірте" if n_anom else "норма")

    st.dataframe(
        df, hide_index=True, width="stretch",
        column_config={
            "Диск, %": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%.0f%%"),
            "Орієнтовна дата": st.column_config.DatetimeColumn(format="DD.MM.YYYY HH:mm"),
        },
    )
    st.caption("Прогноз — лінійна регресія по останніх вимірах (після останнього очищення диска). "
               "R² показує, наскільки тренд близький до прямої: при малому R² прогноз ненадійний.")

    sel = st.selectbox("Сервер для графіка", SERVERS, key="fc_srv")
    hist = ss.disk_hist[sel].dropna()
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=hist.index, y=hist.values, mode="lines", name="Факт"))
    fc = fcs[sel]
    if fc and fc["eta"] is not None and len(hist):
        horizon = min(fc["eta"], timedelta(days=30))
        end_y = min(fc["cur"] + fc["slope"] * horizon.total_seconds(), 100.0)
        fig.add_trace(go.Scatter(x=[hist.index[-1], hist.index[-1] + horizon], y=[fc["cur"], end_y],
                                 mode="lines", name="Прогноз", line=dict(dash="dash", color="#f59e0b")))
    fig.add_hline(y=100, line_dash="dot", line_color="#ef4444", opacity=0.7)
    fig.add_hline(y=90, line_dash="dot", line_color="#f59e0b", opacity=0.5)
    lo = float(hist.min()) - 5 if len(hist) else 0
    fig.update_yaxes(range=[max(0, lo), 105], title="%")
    fig.update_layout(height=320, margin=dict(l=0, r=0, t=10, b=0), legend=dict(orientation="h", y=1.1),
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
    plotly_chart(fig, width="stretch", key="disk_forecast_chart")

    st.subheader("🧪 Виявлення аномалій (z-score)")
    if an.empty:
        st.info("Накопичується історія для аналізу (потрібно ≈ 25 вимірів).")
    else:
        st.dataframe(
            an, hide_index=True, width="stretch", height=min(420, 60 + 35 * len(an)),
            column_config={"|z|": st.column_config.ProgressColumn(
                min_value=0, max_value=float(max(z_thr * 2, an["|z|"].max())), format="%.1f")},
        )
    st.caption(f"Останні 10 вимірів порівнюються з базовим рівнем попередніх точок; "
               f"|z| ≥ {z_thr} вважається аномалією. Для диска аналізується приріст між вимірами.")


# --- розділ 12–13: апарати, журнал переключень, шари GIS, координати вузлів
@db_safe()
def db_save_device(d: dict) -> None:
    vals = dict(id=d["id"], node=d["node"], bay=d["bay"], name=d["name"], kind=d["kind"], state=d["state"],
                updated=d["updated"], updated_by=d["updated_by"])
    with get_engine().begin() as c:
        _upsert(c, t_swdev, "id", vals)


@db_safe(None)
def db_count_devices():
    with get_engine().connect() as c:
        return int(c.execute(select(func.count()).select_from(t_swdev)).scalar())


@db_safe(None)
def db_load_devices():
    with get_engine().connect() as c:
        return [dict(r) for r in c.execute(select(t_swdev)).mappings().all()]


@db_safe()
def db_add_switch(e: dict) -> None:
    with get_engine().begin() as c:
        c.execute(insert(t_swlog).values(
            ts=e["ts"], node=e["node"], device_id=e["device_id"], device=e["device"], kind=e["kind"],
            from_state=e["from_state"], to_state=e["to_state"], operator=e["operator"], role=e["role"],
            order_no=e["order_no"], reason=e["reason"], auto=int(e["auto"])))


@db_safe(None)
def db_load_switch_log(limit: int = 1000):
    with get_engine().connect() as c:
        rows = c.execute(select(t_swlog).order_by(t_swlog.c.id.desc()).limit(limit)).mappings().all()
    return [{
        "ts": r["ts"], "node": r["node"], "device_id": r["device_id"], "device": r["device"], "kind": r["kind"],
        "from_state": r["from_state"], "to_state": r["to_state"], "operator": r["operator"], "role": r["role"],
        "order_no": r["order_no"], "reason": r["reason"] or "", "auto": bool(r["auto"]),
    } for r in reversed(rows)]


@db_safe()
def db_save_gis_layer(L: dict) -> None:
    vals = dict(id=L["id"], name=L["name"], kind=L["kind"], source=L["source"], uploaded=L["uploaded"],
                visible=int(L["visible"]), geojson=json.dumps(L["geojson"], ensure_ascii=False))
    with get_engine().begin() as c:
        _upsert(c, t_gis, "id", vals)


@db_safe()
def db_delete_gis_layer(layer_id: str) -> None:
    with get_engine().begin() as c:
        c.execute(delete(t_gis).where(t_gis.c.id == layer_id))


@db_safe(None)
def db_load_gis_layers():
    with get_engine().connect() as c:
        rows = c.execute(select(t_gis).order_by(t_gis.c.uploaded)).mappings().all()
    return [{"id": r["id"], "name": r["name"], "kind": r["kind"], "source": r["source"], "uploaded": r["uploaded"],
             "visible": bool(r["visible"]), "geojson": json.loads(r["geojson"])} for r in rows]


@db_safe()
def db_save_node(n: dict) -> None:
    vals = dict(name=n["name"], kind=n["kind"], lat=float(n["lat"]), lon=float(n["lon"]), parent=n["parent"])
    with get_engine().begin() as c:
        _upsert(c, t_node, "name", vals)


@db_safe()
def db_clear_nodes() -> None:
    with get_engine().begin() as c:
        c.execute(delete(t_node))


@db_safe(None)
def db_load_nodes():
    with get_engine().connect() as c:
        return [dict(r) for r in c.execute(select(t_node)).mappings().all()]


def load_persistent_ot() -> None:
    """Відновлення координат вузлів, станів апаратів, журналу переключень та шарів GIS."""
    ss = st.session_state
    rows = db_load_nodes()
    if rows:
        by = {n["name"]: n for n in ss.nodes}
        for r in rows:
            if r["name"] in by:
                by[r["name"]].update(lat=r["lat"], lon=r["lon"])
            elif r["parent"] in ss.ot:
                ss.nodes.append({"name": r["name"], "kind": r["kind"], "lat": r["lat"], "lon": r["lon"],
                                 "parent": r["parent"], "status": NODE_OK})
    for n in ss.nodes:
        ensure_node_devices(n)

    cnt = db_count_devices()
    if cnt == 0:
        for d in ss.sw_devices.values():
            db_save_device(d)
    elif cnt:
        for r in db_load_devices() or []:
            if r["id"] in ss.sw_devices:
                ss.sw_devices[r["id"]].update(state=r["state"], updated=r["updated"], updated_by=r["updated_by"])

    log = db_load_switch_log()
    if log:
        ss.sw_log = log
    layers = db_load_gis_layers()
    if layers:
        ss.gis_layers = layers


# ----------------------------------------------------------------------------
# Розділ 12: Оперативний журнал переключень
# ----------------------------------------------------------------------------
SW_ON, SW_OFF = "Увімкнено", "Вимкнено"
SW_KINDS = ("Вимикач", "Роз'єднувач", "Заземлювач")
AUTO_OPERATOR = "РЗА (автоматично)"


def state_text(kind: str, state: str) -> str:
    if kind == "Заземлювач":
        return "Заземлено" if state == SW_ON else "Знято"
    return state


def state_badge(kind: str, state: str) -> str:
    on = state == SW_ON
    if kind == "Заземлювач":
        return "⏚ Заземлено" if on else "— Знято"
    return "⚡ Увімкнено" if on else "⭕ Вимкнено"


def make_node_devices(node: dict) -> list[dict]:
    """Типовий склад комутаційних апаратів вузла (демо). Замініть даними з ОІК/паспорта підстанції."""
    if node["kind"].startswith("ПС"):
        bays = [("Т1 110 кВ", "110"), ("Л-35 №1", "35")]
    else:
        bays = [("Ф-1", "10"), ("Ф-2", "10")]
    devs = []
    for bay, kv in bays:
        for kind, prefix in zip(SW_KINDS, ("В", "Р", "ЗН")):
            name = f"{prefix}-{kv} ({bay})"
            devs.append({
                "id": f"{node['name']}::{name}", "node": node["name"], "bay": bay, "name": name,
                "kind": kind, "state": SW_OFF if kind == "Заземлювач" else SW_ON,
                "updated": datetime.now(), "updated_by": "початковий стан",
            })
    return devs


def ensure_node_devices(node: dict) -> None:
    ss = st.session_state
    for d in make_node_devices(node):
        ss.sw_devices.setdefault(d["id"], d)


def init_switch_state() -> None:
    ss = st.session_state
    ss.sw_devices = {}
    ss.sw_log = []
    ss.gis_layers = []
    ss.wx_alerted = set()
    ss.wx_risk = {}
    for n in ss.nodes:
        ensure_node_devices(n)


def check_interlock(dev: dict, target: str) -> tuple[bool, str]:
    """Оперативні блокування в межах комірки (bay) + контроль зв'язку з вузлом."""
    ss = st.session_state
    node = next((n for n in ss.nodes if n["name"] == dev["node"]), None)
    if node is not None and node_effective_status(node) == NODE_LOST:
        return False, "Немає зв'язку з вузлом телемеханіки — команда неможлива."
    bay = [d for d in ss.sw_devices.values() if d["node"] == dev["node"] and d["bay"] == dev["bay"]]
    brk = [d for d in bay if d["kind"] == "Вимикач"]
    dis = [d for d in bay if d["kind"] == "Роз'єднувач"]
    ear = [d for d in bay if d["kind"] == "Заземлювач"]
    if target == SW_ON:
        if dev["kind"] in ("Вимикач", "Роз'єднувач") and any(e["state"] == SW_ON for e in ear):
            return False, "Заблоковано: у комірці увімкнено заземлювач."
        if dev["kind"] == "Роз'єднувач" and any(b["state"] == SW_ON for b in brk):
            return False, "Заблоковано: роз'єднувач не можна вмикати при увімкненому вимикачі."
        if dev["kind"] == "Заземлювач" and any(d["state"] == SW_ON for d in brk + dis):
            return False, "Заблоковано: заземлити можна лише знеструмлену комірку (вимкніть вимикач і роз'єднувач)."
    else:
        if dev["kind"] == "Роз'єднувач" and any(b["state"] == SW_ON for b in brk):
            return False, "Заблоковано: роз'єднувач не можна вимикати під навантаженням (спочатку вимикач)."
    return True, ""


def _log_switch(dev: dict, frm: str, to: str, operator: str, role: str, order_no: str, reason: str, auto: bool) -> None:
    ss = st.session_state
    entry = {
        "ts": datetime.now(), "node": dev["node"], "device_id": dev["id"], "device": dev["name"],
        "kind": dev["kind"], "from_state": frm, "to_state": to, "operator": operator, "role": role,
        "order_no": order_no, "reason": reason, "auto": auto,
    }
    ss.sw_log.append(entry)
    ss.sw_log = ss.sw_log[-3000:]
    db_add_switch(entry)


def operate_switch(dev_id: str, target: str, operator: str, role: str, order_no: str, reason: str) -> tuple[bool, str]:
    ss = st.session_state
    dev = ss.sw_devices.get(dev_id)
    if dev is None:
        return False, "Апарат не знайдено."
    if dev["state"] == target:
        return False, "Апарат уже в цьому стані."
    ok, msg = check_interlock(dev, target)
    if not ok:
        return False, msg
    frm = dev["state"]
    dev.update(state=target, updated=datetime.now(), updated_by=f"{operator} ({role})")
    db_save_device(dev)
    _log_switch(dev, frm, target, operator, role, order_no, reason, auto=False)
    if dev["kind"] == "Вимикач" and target == SW_ON:
        resolve_links(f"sw:{dev['id']}")
    add_audit("Переключення", f"{dev['node']}: {dev['name']} {state_text(dev['kind'], frm)} → "
                              f"{state_text(dev['kind'], target)}; наряд {order_no}; {operator}")
    return True, f"{dev['name']}: {state_text(dev['kind'], frm)} → {state_text(dev['kind'], target)}"


def tick_switching() -> None:
    """Імітація спрацювання захисту: самовільне відключення вимикача (частіше за критичної погоди)."""
    ss = st.session_state
    rng = ss.rng
    if rng.random() > 0.01:
        return
    nodes = {n["name"]: n for n in ss.nodes}
    cands = [d for d in ss.sw_devices.values()
             if d["kind"] == "Вимикач" and d["state"] == SW_ON and d["node"] in nodes
             and node_effective_status(nodes[d["node"]]) != NODE_LOST]
    if not cands:
        return
    w = np.array([4.0 if ss.get("wx_risk", {}).get(d["node"]) == "Критично" else 1.0 for d in cands])
    dev = cands[int(rng.choice(len(cands), p=w / w.sum()))]
    dev.update(state=SW_OFF, updated=datetime.now(), updated_by=AUTO_OPERATOR)
    db_save_device(dev)
    _log_switch(dev, SW_ON, SW_OFF, AUTO_OPERATOR, "система", "—", "Спрацювання захисту (імітація)", auto=True)
    sev = "Критично" if nodes[dev["node"]]["kind"].startswith("ПС") else "Високий"
    add_alert("Телемеханіка", sev, f"Автоматичне відключення {dev['name']} на {dev['node']}", link=f"sw:{dev['id']}")


def journal_df(entries: list[dict]) -> pd.DataFrame:
    rows = [{
        "Час": e["ts"], "Вузол": e["node"], "Апарат": e["device"], "Тип": e["kind"],
        "Було": state_text(e["kind"], e["from_state"]), "Стало": state_text(e["kind"], e["to_state"]),
        "Хто виконав": e["operator"], "Роль": e["role"], "Наряд / розпорядження №": e["order_no"],
        "Підстава": e["reason"], "Джерело": "РЗА / автоматика" if e["auto"] else "Оператор",
    } for e in reversed(entries)]
    return pd.DataFrame(rows)


def render_switching(role: str) -> None:
    ss = st.session_state
    can = ROLES[role]["switch"]
    now = datetime.now()
    day = now - timedelta(hours=24)

    flash = ss.pop("sw_flash", None)
    if flash:
        (st.success if flash[0] == "ok" else st.error)(flash[1])

    ops24 = [e for e in ss.sw_log if e["ts"] >= day]
    devs_all = list(ss.sw_devices.values())
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Вимикачів увімкнено", f"{sum(d['kind'] == 'Вимикач' and d['state'] == SW_ON for d in devs_all)}"
                                      f" / {sum(d['kind'] == 'Вимикач' for d in devs_all)}")
    k2.metric("Заземлень увімкнено", sum(d["kind"] == "Заземлювач" and d["state"] == SW_ON for d in devs_all))
    k3.metric("Операцій за 24 год", sum(not e["auto"] for e in ops24))
    k4.metric("Автовідключень за 24 год", sum(e["auto"] for e in ops24), delta_color="inverse",
              delta="перевірте" if any(e["auto"] for e in ops24) else "норма")

    st.subheader("🔀 Стан комутаційних апаратів")
    node_names = [n["name"] for n in ss.nodes]
    node = st.selectbox("Вузол", node_names, key="sw_node")
    nobj = next(n for n in ss.nodes if n["name"] == node)
    eff = node_effective_status(nobj)
    st.caption(f"{nobj['kind']} · телеметрія: {NODE_ICON[eff]} {eff}"
               + (" · стани можуть бути застарілими" if eff != NODE_OK else ""))
    devs = [d for d in devs_all if d["node"] == node]
    st.dataframe(
        pd.DataFrame([{
            "Комірка": d["bay"], "Апарат": d["name"], "Тип": d["kind"], "Стан": state_badge(d["kind"], d["state"]),
            "Остання зміна": d["updated"], "Хто": d["updated_by"],
        } for d in devs]),
        hide_index=True, width="stretch",
        column_config={"Остання зміна": st.column_config.DatetimeColumn(format="DD.MM HH:mm:ss")},
    )

    st.subheader("✍️ Виконання переключення")
    if not can:
        st.info("Режим перегляду: виконувати переключення можуть «Диспетчер» та «Адміністратор».")
    elif devs:
        by_id = {d["id"]: d for d in devs}
        dev_id = st.selectbox(
            "Апарат", list(by_id), key="sw_dev",
            format_func=lambda i: f"{by_id[i]['bay']} · {by_id[i]['name']} — {state_text(by_id[i]['kind'], by_id[i]['state'])}",
        )
        dev = by_id[dev_id]
        target = SW_OFF if dev["state"] == SW_ON else SW_ON
        cmd = {("Заземлювач", SW_ON): "Заземлити", ("Заземлювач", SW_OFF): "Зняти заземлення",
               (None, SW_ON): "Увімкнути", (None, SW_OFF): "Вимкнути"}
        cmd_text = cmd.get((dev["kind"], target)) or cmd[(None, target)]
        ok_pre, msg_pre = check_interlock(dev, target)
        if not ok_pre:
            st.warning(f"Команда «{cmd_text}» зараз недоступна. {msg_pre}")
        with st.form("form_switch", clear_on_submit=False):
            c1, c2 = st.columns(2)
            operator = c1.text_input("Хто виконує (ПІБ / позивний)", ss.get("sw_operator", ""))
            order_no = c2.text_input("Наряд / розпорядження №")
            reason = st.text_input("Підстава / коментар")
            confirm = st.checkbox(f"Підтверджую команду: {cmd_text} — {dev['name']} ({node})")
            go_btn = st.form_submit_button(f"▶ {cmd_text}", disabled=not ok_pre)
        if go_btn:
            if not operator.strip() or not order_no.strip():
                st.error("Вкажіть виконавця та номер наряду/розпорядження.")
            elif not confirm:
                st.error("Підтвердіть команду.")
            else:
                ss.sw_operator = operator.strip()
                done, msg = operate_switch(dev_id, target, operator.strip(), role, order_no.strip(), reason.strip())
                if done:
                    ss.sw_flash = ("ok", f"✅ Виконано: {msg}")
                    st.rerun()
                else:
                    st.error(msg)

    st.divider()
    st.subheader("📒 Журнал переключень (незмінний, лише додавання записів)")
    f1, f2, f3, f4 = st.columns([2, 2, 1.2, 1.2])
    nodes_f = f1.multiselect("Вузли", node_names, key="swj_nodes")
    q = f2.text_input("Пошук (апарат, виконавець, наряд)", key="swj_q")
    period = f3.selectbox("Період", ["24 год", "7 днів", "Весь"], key="swj_period")
    only_auto = f4.toggle("Лише автоматика", key="swj_auto")
    horizon = {"24 год": timedelta(hours=24), "7 днів": timedelta(days=7)}.get(period)
    items = [
        e for e in ss.sw_log
        if (not nodes_f or e["node"] in nodes_f)
        and (horizon is None or e["ts"] >= now - horizon)
        and (not only_auto or e["auto"])
        and (not q or q.lower() in f"{e['device']} {e['operator']} {e['order_no']} {e['reason']}".lower())
    ]
    jdf = journal_df(items)
    if jdf.empty:
        st.info("Записів за вибраними фільтрами немає.")
    else:
        st.dataframe(jdf, hide_index=True, width="stretch", height=min(480, 60 + 35 * len(jdf)),
                     column_config={"Час": st.column_config.DatetimeColumn(format="DD.MM.YYYY HH:mm:ss")})
        if ROLES[role]["ack"]:
            buf = BytesIO()
            with pd.ExcelWriter(buf, engine="openpyxl") as w:
                jdf.to_excel(w, index=False, sheet_name="Журнал переключень")
            c1, c2 = st.columns(2)
            c1.download_button("📥 Експорт (Excel)", data=buf.getvalue(),
                               file_name=f"switch_journal_{now:%Y%m%d_%H%M}.xlsx",
                               mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                               width="stretch", on_click=add_audit, args=("Звіт", "Експорт журналу переключень"))
            c2.download_button("📄 Експорт (CSV)", data=jdf.to_csv(index=False).encode("utf-8-sig"),
                               file_name=f"switch_journal_{now:%Y%m%d_%H%M}.csv", mime="text/csv", width="stretch")


# ----------------------------------------------------------------------------
# Розділ 13: GIS — імпорт/експорт GeoJSON та KML
# ----------------------------------------------------------------------------
GIS_KINDS = {"lines": "Лінії електропередач", "zones": "Зони обслуговування", "points": "Об'єкти (точки)"}
GIS_COLOR = {"lines": "#2563eb", "zones": "#f97316", "points": "#9333ea"}
GEO_TYPES = {"Point", "MultiPoint", "LineString", "MultiLineString", "Polygon", "MultiPolygon"}
MAX_GIS_MB = 10
MAX_GIS_FEATURES = 20000


def _check_coords(c) -> None:
    if isinstance(c, (list, tuple)) and c and all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in c):
        if len(c) < 2:
            raise ValueError("Позиція має містити щонайменше довготу та широту.")
        if not (-180 <= c[0] <= 180 and -90 <= c[1] <= 90):
            raise ValueError("Координати поза діапазоном WGS84 (lon −180..180, lat −90..90) — імовірно інша проєкція.")
        return
    if isinstance(c, (list, tuple)) and c:
        for x in c:
            _check_coords(x)
        return
    raise ValueError("Некоректні координати у геометрії.")


def normalize_geojson(obj) -> dict:
    """Перевіряє GeoJSON і повертає FeatureCollection з обов'язковою властивістю name."""
    if not isinstance(obj, dict):
        raise ValueError("Очікується JSON-об'єкт GeoJSON.")
    t = obj.get("type")
    if t == "FeatureCollection":
        feats = obj.get("features") or []
    elif t == "Feature":
        feats = [obj]
    elif t in GEO_TYPES or t == "GeometryCollection":
        feats = [{"type": "Feature", "properties": {}, "geometry": obj}]
    else:
        raise ValueError(f"Невідомий тип GeoJSON: {t!r}.")
    out = []
    for f in feats:
        if not isinstance(f, dict) or not f.get("geometry"):
            continue
        g = f["geometry"]
        props = dict(f.get("properties") or {})
        geoms = g.get("geometries", []) if g.get("type") == "GeometryCollection" else [g]
        name = next((props[k] for k in ("name", "Name", "NAME", "title", "label") if props.get(k)), "")
        props["name"] = str(name)
        for gg in geoms:
            if gg.get("type") not in GEO_TYPES:
                raise ValueError(f"Непідтримуваний тип геометрії: {gg.get('type')!r}.")
            _check_coords(gg.get("coordinates"))
            out.append({"type": "Feature", "properties": props,
                        "geometry": {"type": gg["type"], "coordinates": gg["coordinates"]}})
        if len(out) > MAX_GIS_FEATURES:
            raise ValueError(f"Забагато об'єктів (ліміт {MAX_GIS_FEATURES}).")
    if not out:
        raise ValueError("У файлі не знайдено об'єктів з геометрією.")
    return {"type": "FeatureCollection", "features": out}


def _kml_coords(text: str) -> list[list[float]]:
    pts = []
    for tok in (text or "").split():
        parts = tok.split(",")
        if len(parts) >= 2:
            pts.append([float(parts[0]), float(parts[1])])
    return pts


def kml_to_geojson(data: bytes) -> dict:
    low = data.lower()
    if b"<!doctype" in low or b"<!entity" in low:
        raise ValueError("DTD/ENTITY у KML заборонені з міркувань безпеки.")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        raise ValueError(f"Некоректний XML/KML: {e}") from e

    def tag(el) -> str:
        return el.tag.rsplit("}", 1)[-1]

    feats = []
    for pm in root.iter():
        if tag(pm) != "Placemark":
            continue
        name = next((c.text or "" for c in pm if tag(c) == "name"), "").strip()
        desc = next((c.text or "" for c in pm if tag(c) == "description"), "").strip()
        props = {"name": name, "description": desc}
        for el in pm.iter():
            t = tag(el)
            if t == "Point":
                c = next((_kml_coords(x.text) for x in el.iter() if tag(x) == "coordinates"), [])
                if c:
                    feats.append({"type": "Feature", "properties": props, "geometry": {"type": "Point", "coordinates": c[0]}})
            elif t == "LineString":
                c = next((_kml_coords(x.text) for x in el.iter() if tag(x) == "coordinates"), [])
                if len(c) >= 2:
                    feats.append({"type": "Feature", "properties": props, "geometry": {"type": "LineString", "coordinates": c}})
            elif t == "Polygon":
                rings = []
                for b in el.iter():
                    if tag(b) in ("outerBoundaryIs", "innerBoundaryIs"):
                        c = next((_kml_coords(x.text) for x in b.iter() if tag(x) == "coordinates"), [])
                        if len(c) >= 4:
                            rings.append(c)
                if rings:
                    feats.append({"type": "Feature", "properties": props, "geometry": {"type": "Polygon", "coordinates": rings}})
    return {"type": "FeatureCollection", "features": feats}


@st.cache_data(show_spinner=False, max_entries=8)
def parse_gis_file(name: str, data: bytes):
    try:
        if len(data) > MAX_GIS_MB * 1024 * 1024:
            return None, f"Файл перевищує ліміт {MAX_GIS_MB} МБ."
        if name.lower().endswith(".kml"):
            fc = normalize_geojson(kml_to_geojson(data))
        else:
            fc = normalize_geojson(json.loads(data.decode("utf-8-sig")))
        return fc, None
    except Exception as e:
        return None, str(e)[:250]


def fc_stats(fc: dict) -> tuple[dict, list[float]]:
    counts: dict[str, int] = {}
    lons, lats = [], []

    def walk(c):
        if c and isinstance(c[0], (int, float)):
            lons.append(c[0]); lats.append(c[1])
        else:
            for x in c:
                walk(x)

    for f in fc["features"]:
        g = f["geometry"]
        counts[g["type"]] = counts.get(g["type"], 0) + 1
        walk(g["coordinates"])
    return counts, ([min(lats), min(lons), max(lats), max(lons)] if lats else [])


def detect_kind(fc: dict) -> str:
    types = {f["geometry"]["type"] for f in fc["features"]}
    if types <= {"Point", "MultiPoint"}:
        return "points"
    if types <= {"Polygon", "MultiPolygon"}:
        return "zones"
    return "lines"


def fc_to_kml(fc: dict, doc_name: str) -> str:
    def pos(c): return f"{c[0]},{c[1]}"
    def ring(r): return " ".join(pos(c) for c in r)

    def geom(g: dict) -> str:
        t, c = g["type"], g["coordinates"]
        if t == "Point":
            return f"<Point><coordinates>{pos(c)}</coordinates></Point>"
        if t == "LineString":
            return f"<LineString><coordinates>{ring(c)}</coordinates></LineString>"
        if t == "Polygon":
            inner = "".join(f"<innerBoundaryIs><LinearRing><coordinates>{ring(r)}</coordinates></LinearRing></innerBoundaryIs>"
                            for r in c[1:])
            return (f"<Polygon><outerBoundaryIs><LinearRing><coordinates>{ring(c[0])}</coordinates></LinearRing>"
                    f"</outerBoundaryIs>{inner}</Polygon>")
        sub = t[5:]  # Multi*
        return "<MultiGeometry>" + "".join(geom({"type": sub, "coordinates": x}) for x in c) + "</MultiGeometry>"

    body = "".join(
        f"<Placemark><name>{xml_escape(str(f['properties'].get('name', '')))}</name>"
        f"<description>{xml_escape(str(f['properties'].get('description', '')))}</description>{geom(f['geometry'])}</Placemark>"
        for f in fc["features"]
    )
    return ('<?xml version="1.0" encoding="UTF-8"?><kml xmlns="http://www.opengis.net/kml/2.2"><Document>'
            f"<name>{xml_escape(doc_name)}</name>{body}</Document></kml>")


def nodes_to_geojson() -> dict:
    ss = st.session_state
    return {"type": "FeatureCollection", "features": [{
        "type": "Feature",
        "properties": {"name": n["name"], "kind": n["kind"], "channel": n["parent"], "status": node_effective_status(n)},
        "geometry": {"type": "Point", "coordinates": [n["lon"], n["lat"]]},
    } for n in ss.nodes]}


def _norm(s: str) -> str:
    return re.sub(r"[\s«»\"'’`]+", " ", str(s).lower()).strip()


def apply_points_to_nodes(fc: dict, add_new: bool, parent: str, kind: str) -> tuple[int, int, list[str]]:
    """Оновлює координати вузлів телемеханіки з точкового шару (збіг за назвою)."""
    ss = st.session_state
    by = {_norm(n["name"]): n for n in ss.nodes}
    upd = add = 0
    unmatched: list[str] = []
    for f in fc["features"]:
        g = f["geometry"]
        if g["type"] != "Point":
            continue
        name = str(f["properties"].get("name", "")).strip()
        lon, lat = float(g["coordinates"][0]), float(g["coordinates"][1])
        key = _norm(name)
        node = by.get(key)
        if node is None and len(key) >= 4:
            cands = [n for k, n in by.items() if key in k or k in key]
            node = cands[0] if len(cands) == 1 else None
        if node is not None:
            node.update(lat=lat, lon=lon)
            db_save_node(node)
            upd += 1
        elif add_new and name:
            new = {"name": name, "kind": kind, "lat": lat, "lon": lon, "parent": parent, "status": NODE_OK}
            ss.nodes.append(new)
            by[key] = new
            ensure_node_devices(new)
            db_save_node(new)
            add += 1
        else:
            unmatched.append(name or "(без назви)")
    return upd, add, unmatched


def reset_nodes_to_demo() -> None:
    ss = st.session_state
    db_clear_nodes()
    ss.nodes = [{"name": n, "kind": k, "lat": la, "lon": lo, "parent": p, "status": NODE_OK}
                for n, k, la, lo, p in OT_NODES]
    names = {n["name"] for n in ss.nodes}
    ss.sw_devices = {i: d for i, d in ss.sw_devices.items() if d["node"] in names}


def render_gis(role: str) -> None:
    ss = st.session_state
    can = ROLES[role]["upload"]
    st.subheader("🗺️ Схеми мереж (GIS): імпорт та експорт")
    st.caption("Підтримуються GeoJSON (.geojson/.json) та KML у системі координат WGS84. "
               "KMZ спершу розпакуйте. Шари відображаються також на карті вкладки «Диспетчерський хаб».")
    render_ot_map(height=520, key="gis_map")

    flash = ss.pop("gis_flash", None)
    if flash:
        st.success(flash)

    st.subheader("📚 Шари")
    if not ss.gis_layers:
        st.info("Шарів поки немає. Імпортуйте GeoJSON або KML нижче.")
    for L in list(ss.gis_layers):
        counts, _ = fc_stats(L["geojson"])
        c = st.columns([3, 1, 1, 1, 1])
        c[0].markdown(f"**{L['name']}** · {GIS_KINDS.get(L['kind'], L['kind'])}")  # без unsafe_allow_html: назви з файлів
        c[0].caption(f"{L['source']} · {len(L['geojson']['features'])} об'єктів · {L['uploaded']:%d.%m.%Y %H:%M}")
        vis = c[1].checkbox("Показати", L["visible"], key=f"gis_vis_{L['id']}")
        if vis != L["visible"]:
            L["visible"] = vis
            db_save_gis_layer(L)
            st.rerun()
        c[2].download_button("GeoJSON", data=json.dumps(L["geojson"], ensure_ascii=False).encode("utf-8"),
                             file_name=f"{_safe_name(L['name'])}.geojson", mime="application/geo+json",
                             key=f"gis_dl_j_{L['id']}", width="stretch")
        c[3].download_button("KML", data=fc_to_kml(L["geojson"], L["name"]).encode("utf-8"),
                             file_name=f"{_safe_name(L['name'])}.kml", mime="application/vnd.google-earth.kml+xml",
                             key=f"gis_dl_k_{L['id']}", width="stretch")
        if can and c[4].button("🗑 Видалити", key=f"gis_del_{L['id']}", width="stretch"):
            ss.gis_layers = [x for x in ss.gis_layers if x["id"] != L["id"]]
            db_delete_gis_layer(L["id"])
            add_audit("GIS", f"Видалено шар «{L['name']}»")
            st.rerun()

    st.subheader("📤 Експорт вузлів телемеханіки")
    nfc = nodes_to_geojson()
    e1, e2 = st.columns(2)
    e1.download_button("Вузли → GeoJSON", data=json.dumps(nfc, ensure_ascii=False).encode("utf-8"),
                       file_name="telemechanics_nodes.geojson", mime="application/geo+json", width="stretch")
    e2.download_button("Вузли → KML", data=fc_to_kml(nfc, "Вузли телемеханіки").encode("utf-8"),
                       file_name="telemechanics_nodes.kml", mime="application/vnd.google-earth.kml+xml", width="stretch")

    st.subheader("📥 Імпорт")
    if not can:
        st.info("Імпортувати та видаляти шари можуть «Спеціаліст з ІБ» та «Адміністратор».")
        return
    up = st.file_uploader("Файл GeoJSON або KML", type=["geojson", "json", "kml"], key="gis_up")
    if up is None:
        return
    fc, err = parse_gis_file(up.name, up.getvalue())
    if err:
        st.error(f"Не вдалося прочитати файл: {err}")
        return
    counts, bbox = fc_stats(fc)
    st.success(f"Прочитано {len(fc['features'])} об'єктів: " + ", ".join(f"{k} × {v}" for k, v in counts.items()))
    if bbox:
        st.caption(f"Охоплення: lat {bbox[0]:.3f}…{bbox[2]:.3f}, lon {bbox[1]:.3f}…{bbox[3]:.3f}")

    c1, c2 = st.columns(2)
    name = c1.text_input("Назва шару", up.name.rsplit(".", 1)[0], key="gis_name")
    kinds = list(GIS_KINDS)
    kind = c2.selectbox("Тип шару", kinds, index=kinds.index(detect_kind(fc)),
                        format_func=lambda k: GIS_KINDS[k], key="gis_kind")
    if st.button("➕ Додати як шар на карту", key="gis_add_layer"):
        layer = {"id": datetime.now().strftime("%Y%m%d%H%M%S%f"), "name": name.strip() or up.name, "kind": kind,
                 "source": up.name, "uploaded": datetime.now(), "visible": True, "geojson": fc}
        ss.gis_layers.append(layer)
        db_save_gis_layer(layer)
        add_audit("GIS", f"Імпорт шару «{layer['name']}» ({len(fc['features'])} об'єктів, файл {up.name})")
        ss.gis_flash = f"Шар «{layer['name']}» додано."
        st.rerun()

    if counts.get("Point"):
        st.markdown("**Використати точки як координати вузлів телемеханіки** (збіг за назвою вузла)")
        a1, a2, a3 = st.columns(3)
        add_new = a1.checkbox("Додавати невідомі точки як нові вузли", key="gis_add_new")
        parent = a2.selectbox("Канал для нових вузлів", list(ss.ot), index=list(ss.ot).index(OT_RTU_RP), key="gis_parent")
        nkind = a3.text_input("Тип нових вузлів", "РП 10 кВ", key="gis_nkind")
        if st.button("📍 Застосувати до вузлів", key="gis_apply_nodes"):
            upd, add, unmatched = apply_points_to_nodes(fc, add_new, parent, nkind.strip() or "Вузол")
            add_audit("GIS", f"Координати вузлів з «{up.name}»: оновлено {upd}, додано {add}, без збігу {len(unmatched)}")
            msg = f"Оновлено вузлів: {upd}, додано нових: {add}."
            if unmatched:
                msg += f" Без збігу ({len(unmatched)}): " + ", ".join(unmatched[:10]) + ("…" if len(unmatched) > 10 else "")
            ss.gis_flash = msg
            st.rerun()
    with st.expander("⚠️ Повернути демо-координати вузлів"):
        if st.button("Скинути координати та додані вузли до демо", key="gis_reset_nodes"):
            reset_nodes_to_demo()
            add_audit("GIS", "Координати вузлів скинуто до демо")
            ss.gis_flash = "Координати вузлів повернуто до демо-значень."
            st.rerun()


# ----------------------------------------------------------------------------
# Розділ 14: Метеомоніторинг
# ----------------------------------------------------------------------------
WX_SOURCES = ["Демо-дані", "Open-Meteo (реальний прогноз)"]
WX_SCENARIOS = ["Випадковий", "Штиль", "Гроза", "Ожеледь", "Шторм"]
RISK_ORDER = {"Критично": 0, "Високий": 1, "Середній": 2, "Норма": 3}
RISK_ICON = {"Критично": "🔴", "Високий": "🟠", "Середній": "🟡", "Норма": "🟢"}
RISK_COLOR = {"Критично": "#ef4444", "Високий": "#f97316", "Середній": "#eab308", "Норма": "#22c55e"}


def wx_text(code: int) -> str:
    c = int(code)
    table = {0: "Ясно", 1: "Переважно ясно", 2: "Мінлива хмарність", 3: "Хмарно", 45: "Туман", 48: "Паморозь",
             56: "Крижана мряка", 57: "Крижана мряка", 66: "Крижаний дощ", 67: "Крижаний дощ",
             95: "Гроза", 96: "Гроза з градом", 99: "Гроза з градом"}
    if c in table:
        return table[c]
    if 51 <= c <= 55:
        return "Мряка"
    if 61 <= c <= 65:
        return "Дощ"
    if 71 <= c <= 77:
        return "Сніг"
    if 80 <= c <= 82:
        return "Зливи"
    if c in (85, 86):
        return "Снігові зливи"
    return "—"


def _wx_hours() -> pd.DatetimeIndex:
    base = datetime.now().replace(minute=0, second=0, microsecond=0)
    return pd.date_range(base, periods=48, freq="h")


def demo_weather_node(name: str, scenario: str) -> pd.DataFrame:
    hours = _wx_hours()
    n = len(hours)
    now = datetime.now()
    rng = np.random.default_rng(zlib.crc32(f"{name}|{scenario}|{now:%Y%m%d}|{now.hour // 6}".encode()))
    temp = 6 + 4 * np.sin((hours.hour.to_numpy() - 9) / 24 * 2 * np.pi) + rng.normal(0, 0.3, n)
    wind = np.clip(4 + rng.normal(0, 1, n), 0.5, None)
    gust = wind * 1.5 + rng.uniform(0, 1.5, n)
    precip, snow, code = np.zeros(n), np.zeros(n), np.full(n, 2)
    sc = scenario
    if sc == "Випадковий":
        sc = str(rng.choice(["Штиль", "Гроза", "Ожеледь", "Шторм"], p=[.78, .09, .07, .06]))
    elif rng.random() > 0.7:
        sc = "Штиль"  # явний сценарій торкається ~70% вузлів
    s = int(rng.integers(2, 14))
    w = slice(s, min(s + int(rng.integers(4, 9)), n))
    k = w.stop - w.start
    if sc == "Гроза":
        precip[w] = rng.uniform(6, 16, k)
        gust[w] = rng.uniform(18, 27, k)
        code[w] = 96 if rng.random() > 0.7 else 95
    elif sc == "Ожеледь":
        temp[w] = rng.uniform(-1.5, 0.3, k)
        precip[w] = rng.uniform(0.5, 2.5, k)
        wind[w] += 3
        gust[w] = wind[w] * 1.6
        code[w] = int(rng.choice([66, 67, 57]))
    elif sc == "Шторм":
        wind[w] = rng.uniform(13, 19, k)
        gust[w] = wind[w] * 1.5
    return pd.DataFrame({"time": hours, "temp": temp, "precip": precip, "snow": snow, "wind": wind,
                         "gust": gust, "code": code})


@st.cache_data(ttl=900, show_spinner=False)
def fetch_open_meteo(coords: tuple) -> list:
    """Прогноз Open-Meteo (без ключа). Координати округлено до 0.01° (~1 км)."""
    q = urllib.parse.urlencode({
        "latitude": ",".join(f"{c[0]:.2f}" for c in coords),
        "longitude": ",".join(f"{c[1]:.2f}" for c in coords),
        "hourly": "temperature_2m,precipitation,snowfall,wind_speed_10m,wind_gusts_10m,weather_code",
        "wind_speed_unit": "ms", "timezone": "auto", "forecast_days": 2,
    })
    with urllib.request.urlopen("https://api.open-meteo.com/v1/forecast?" + q, timeout=10) as r:
        data = json.loads(r.read())
    if isinstance(data, dict):
        data = [data]
    out = []
    for d in data:
        h = d["hourly"]
        out.append(pd.DataFrame({
            "time": pd.to_datetime(h["time"]), "temp": h["temperature_2m"], "precip": h["precipitation"],
            "snow": h["snowfall"], "wind": h["wind_speed_10m"], "gust": h["wind_gusts_10m"],
            "code": pd.Series(h["weather_code"]).fillna(0).astype(int),
        }))
    return out


def get_weather() -> tuple[dict, str, str | None]:
    """Повертає ({вузол: DataFrame}, джерело, помилка). Реальний запит — лише за явним вибором користувача."""
    ss = st.session_state
    now = datetime.now()
    err = None
    if ss.get("wx_source", WX_SOURCES[0]) == WX_SOURCES[1]:
        if ss.get("wx_fail_until", now) > now:
            err = "джерело тимчасово недоступне — показано демо-дані"
        else:
            try:
                coords = tuple((round(n["lat"], 2), round(n["lon"], 2)) for n in ss.nodes)
                dfs = fetch_open_meteo(coords)
                base = now.replace(minute=0, second=0, microsecond=0)
                data = {n["name"]: d[d["time"] >= base].reset_index(drop=True).head(48)
                        for n, d in zip(ss.nodes, dfs)}
                return data, "Open-Meteo", None
            except Exception as e:
                ss.wx_fail_until = now + timedelta(minutes=10)
                err = f"Open-Meteo недоступний ({str(e)[:80]}) — показано демо-дані"
    sc = ss.get("wx_scenario", WX_SCENARIOS[0])
    return {n["name"]: demo_weather_node(n["name"], sc) for n in ss.nodes}, "Демо", err


def assess_weather(df: pd.DataFrame, horizon_h: int = 24) -> dict:
    d = df.head(horizon_h).reset_index(drop=True)
    haz = []

    def first(mask) -> datetime | None:
        idx = np.where(np.asarray(mask))[0]
        return d["time"].iloc[int(idx[0])].to_pydatetime() if len(idx) else None

    gmax = float(d["gust"].max())
    if gmax >= 15:
        lvl = "Критично" if gmax >= 25 else "Високий" if gmax >= 20 else "Середній"
        haz.append({"level": lvl, "name": "Пориви вітру", "time": d["time"].iloc[int(d["gust"].argmax())].to_pydatetime(),
                    "value": f"{gmax:.0f} м/с"})
    t = first(d["code"].isin([56, 57, 66, 67]))
    if t:
        haz.append({"level": "Критично", "name": "Ожеледь (крижаний дощ/мряка)", "time": t, "value": ""})
    wet = (d["temp"].between(-3, 1)) & ((d["precip"] > 0.2) | (d["snow"] > 0.2))
    t = first(wet)
    if t:
        haz.append({"level": "Високий", "name": "Мокрий сніг / ризик ожеледі", "time": t, "value": ""})
    t = first(d["code"].isin([96, 99]))
    if t:
        haz.append({"level": "Критично", "name": "Гроза з градом", "time": t, "value": ""})
    else:
        t = first(d["code"] == 95)
        if t:
            haz.append({"level": "Високий", "name": "Гроза", "time": t, "value": ""})
    pmax = float(d["precip"].max())
    if pmax >= 5:
        haz.append({"level": "Високий" if pmax >= 10 else "Середній", "name": "Сильні опади",
                    "time": d["time"].iloc[int(d["precip"].argmax())].to_pydatetime(), "value": f"{pmax:.0f} мм/год"})
    tmin, tmax = float(d["temp"].min()), float(d["temp"].max())
    if tmax >= 35:
        haz.append({"level": "Середній", "name": "Спека", "time": first(d["temp"] >= 35), "value": f"{tmax:.0f} °C"})
    if tmin <= -25:
        haz.append({"level": "Середній", "name": "Сильний мороз", "time": first(d["temp"] <= -25), "value": f"{tmin:.0f} °C"})
    haz.sort(key=lambda h: (RISK_ORDER[h["level"]], h["time"]))
    return {"level": haz[0]["level"] if haz else "Норма", "hazards": haz, "gust": gmax, "tmin": tmin,
            "precip": float(d["precip"].sum())}


def check_weather_alerts() -> None:
    """Раз на ~хвилину оновлює карту ризиків і створює алерти про небезпеку в найближчі 12 годин."""
    ss = st.session_state
    if ss.tick_n % 12:
        return
    data, _, _ = get_weather()
    soon = datetime.now() + timedelta(hours=12)
    risks = {}
    for name, df in data.items():
        r = assess_weather(df)
        risks[name] = r["level"]
        near = [h for h in r["hazards"] if h["level"] in ("Критично", "Високий") and h["time"] <= soon]
        link = f"wx:{name}"
        if near and name not in ss.wx_alerted:
            h = near[0]
            add_alert("Метеомоніторинг", h["level"],
                      f"{name}: прогноз «{h['name']}» о {h['time']:%H:%M} {h['value']}".strip(), link=link)
            ss.wx_alerted.add(name)
        elif not near and name in ss.wx_alerted:
            resolve_links(link)
            ss.wx_alerted.discard(name)
    ss.wx_risk = risks


def render_weather(role: str) -> None:
    ss = st.session_state
    c1, c2, c3 = st.columns([2.2, 1.6, 1])
    c1.radio("Джерело прогнозу", WX_SOURCES, key="wx_source", horizontal=True)
    c2.selectbox("Демо-сценарій", WX_SCENARIOS, key="wx_scenario",
                 disabled=ss.get("wx_source", WX_SOURCES[0]) != WX_SOURCES[0])
    if c3.button("🔄 Оновити", width="stretch"):
        fetch_open_meteo.clear()
        ss.pop("wx_fail_until", None)
        st.rerun()
    st.caption("⚠️ Режим Open-Meteo надсилає координати вузлів (округлені до ≈1 км) стороннім сервісом. "
               "Для об'єктів критичної інфраструктури узгодьте це з політикою ІБ; за замовчуванням використовуються демо-дані.")

    data, label, err = get_weather()
    if err:
        st.warning(err)
    risks = {n: assess_weather(df) for n, df in data.items()}
    day = datetime.now() - timedelta(hours=24)
    trips = {}
    for e in ss.sw_log:
        if e["auto"] and e["ts"] >= day:
            trips[e["node"]] = trips.get(e["node"], 0) + 1

    n_crit = sum(r["level"] == "Критично" for r in risks.values())
    n_high = sum(r["level"] == "Високий" for r in risks.values())
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Вузлів із критичним ризиком", n_crit, delta_color="inverse", delta="потрібна увага" if n_crit else "норма")
    k2.metric("Вузлів із високим ризиком", n_high)
    k3.metric("Макс. пориви (24 год)", f"{max(r['gust'] for r in risks.values()):.0f} м/с")
    k4.metric("Мін. температура (24 год)", f"{min(r['tmin'] for r in risks.values()):.0f} °C")
    st.caption(f"Джерело: {label} · прогноз на найближчі 24 год · оновлено {datetime.now():%H:%M:%S}")

    rows = []
    for n in ss.nodes:
        r = risks[n["name"]]
        top = r["hazards"][0] if r["hazards"] else None
        rows.append({
            "Ризик": f"{RISK_ICON[r['level']]} {r['level']}", "Вузол": n["name"], "Тип": n["kind"],
            "Небезпеки": "; ".join(f"{h['name']} {h['value']}".strip() for h in r["hazards"][:3]) or "—",
            "Найближча": top["time"] if top else pd.NaT, "Пориви, м/с": round(r["gust"], 1),
            "Tмін, °C": round(r["tmin"], 1), "Опади 24 год, мм": round(r["precip"], 1),
            "Автовідключень 24 год": trips.get(n["name"], 0), "_o": RISK_ORDER[r["level"]],
        })
    df = pd.DataFrame(rows).sort_values(["_o", "Пориви, м/с"], ascending=[True, False]).drop(columns="_o")
    st.dataframe(df, hide_index=True, width="stretch",
                 column_config={"Найближча": st.column_config.DatetimeColumn(format="DD.MM HH:mm")})
    st.caption("«Автовідключень» — спрацювання захистів за останні 24 год з журналу переключень: "
               "допомагає зіставити погодні ризики з фактичними відключеннями.")

    left, right = st.columns([3, 2])
    with left:
        st.markdown("**Карта метеоризиків**")
        try:
            import folium
            from streamlit_folium import st_folium

            lats, lons = [n["lat"] for n in ss.nodes], [n["lon"] for n in ss.nodes]
            m = new_map(lats, lons, width_px=700, height_px=400)
            for n in ss.nodes:
                r = risks[n["name"]]
                col = RISK_COLOR[r["level"]]
                folium.CircleMarker(
                    location=[n["lat"], n["lon"]], radius=11 if n["kind"].startswith("ПС") else 7, color=col, weight=2,
                    fill=True, fill_color=col, fill_opacity=0.85,
                    tooltip=f"{n['name']} — {r['level']}",
                    popup=folium.Popup(f"<b>{n['name']}</b><br>Ризик: {r['level']}<br>Пориви: {r['gust']:.0f} м/с<br>"
                                       f"Tмін: {r['tmin']:.0f} °C", max_width=260),
                ).add_to(m)
            st_folium(m, height=400, use_container_width=True, returned_objects=[], key="wx_map")
        except ImportError:
            st.map(pd.DataFrame([{"lat": n["lat"], "lon": n["lon"], "color": RISK_COLOR[risks[n["name"]]["level"]]}
                                 for n in ss.nodes]), latitude="lat", longitude="lon", color="color", size=3000)
    with right:
        sel = st.selectbox("Вузол для детального прогнозу", [n["name"] for n in ss.nodes], key="wx_node")
        r = risks[sel]
        if r["hazards"]:
            for h in r["hazards"]:
                st.markdown(f"{RISK_ICON[h['level']]} **{h['name']}** — {h['time']:%d.%m %H:%M} {h['value']}")
        else:
            st.success("Небезпечних явищ на найближчі 24 год не прогнозується.")
        cur = data[sel].iloc[0]
        st.caption(f"Зараз: {cur['temp']:.0f} °C · вітер {cur['wind']:.0f} м/с (пориви {cur['gust']:.0f}) · {wx_text(cur['code'])}")

    d = data[sel]
    fig = make_subplots(specs=[[{"secondary_y": True}]])
    fig.add_trace(go.Bar(x=d["time"], y=d["precip"], name="Опади, мм/год", opacity=0.35), secondary_y=False)
    fig.add_trace(go.Scatter(x=d["time"], y=d["wind"], name="Вітер, м/с", mode="lines"), secondary_y=False)
    fig.add_trace(go.Scatter(x=d["time"], y=d["gust"], name="Пориви, м/с", mode="lines", line=dict(dash="dash")),
                  secondary_y=False)
    fig.add_trace(go.Scatter(x=d["time"], y=d["temp"], name="Температура, °C", mode="lines",
                             line=dict(color="#ef4444")), secondary_y=True)
    fig.add_hline(y=20, line_dash="dot", line_color="#ef4444", opacity=0.5)
    fig.update_yaxes(title_text="м/с · мм/год", secondary_y=False)
    fig.update_yaxes(title_text="°C", secondary_y=True)
    fig.update_layout(height=340, margin=dict(l=0, r=0, t=10, b=0), legend=dict(orientation="h", y=1.12),
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
    plotly_chart(fig, width="stretch", key="wx_chart")
    st.caption("Пунктирна червона лінія — 20 м/с (поріг «високого» ризику за поривами). "
               "Пороги в assess_weather() варто узгодити з нормативами ваших ліній (типи опор, ожеледне навантаження).")


# ----------------------------------------------------------------------------
# Розділ 15: Тема оформлення (темна / світла)
# ----------------------------------------------------------------------------
DEFAULT_DARK = True  # для оперативного центру за замовчуванням темна; змініть на False для світлої

THEME_VARS = {
    True: {"bg": "#0e1117", "bg2": "#161b26", "card": "#1a2030", "fg": "#e6e9ef", "muted": "#9aa4b2",
           "border": "#2b3445", "input": "#1b2231", "code": "#141a26"},
    False: {"bg": "#ffffff", "bg2": "#f3f5f9", "card": "#f8f9fc", "fg": "#1f2937", "muted": "#6b7280",
            "border": "#d5dbe5", "input": "#ffffff", "code": "#f3f4f6"},
}


def init_theme() -> None:
    """Початкове значення теми: ?theme=dark|light в URL, інакше DEFAULT_DARK."""
    ss = st.session_state
    if "dark_theme" not in ss:
        qp = st.query_params.get("theme")
        ss.dark_theme = (qp == "dark") if qp in ("dark", "light") else DEFAULT_DARK


def persist_theme() -> None:
    st.query_params["theme"] = "dark" if st.session_state.get("dark_theme", DEFAULT_DARK) else "light"


def is_dark() -> bool:
    return bool(st.session_state.get("dark_theme", DEFAULT_DARK))


def actual_theme() -> str | None:
    """Тема, яку реально малює Streamlit (потрібна для полотняних таблиць). None — невідомо."""
    try:
        base = st.get_option("theme.base")
        if base in ("light", "dark"):
            return base
    except Exception:
        pass
    try:
        t = st.context.theme.type
        return t if t in ("light", "dark") else None
    except Exception:
        return None


def theme_css() -> str:
    dark = is_dark()
    v = THEME_VARS[dark]
    # st.dataframe малюється на canvas за темою Streamlit: якщо вона відрізняється від обраної — інвертуємо
    grid = '[data-testid="stDataFrame"], [data-testid="stDataFrameResizable"]'
    flt = "filter: invert(0.92) hue-rotate(180deg);"
    actual = actual_theme()
    if actual is None:  # тему не визначено — орієнтуємось на системну (prefers-color-scheme)
        other = "light" if dark else "dark"
        grid_rule = f"@media (prefers-color-scheme: {other}) {{ {grid} {{ {flt} }} }}"
    elif (actual == "dark") != dark:
        grid_rule = f"{grid} {{ {flt} }}"
    else:
        grid_rule = ""
    return f"""
<style>
:root {{ color-scheme: {'dark' if dark else 'light'}; }}
.stApp, [data-testid="stAppViewContainer"] {{ background: {v['bg']}; color: {v['fg']}; }}
[data-testid="stHeader"] {{ background: {v['bg']}; }}
[data-testid="stHeader"] *, [data-testid="stToolbar"] * {{ color: {v['fg']}; }}
[data-testid="stSidebar"], [data-testid="stSidebar"] > div {{ background: {v['bg2']}; }}
.stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp p, .stApp label, .stApp li,
.stApp [data-testid="stMarkdownContainer"], .stApp [data-testid="stMetricValue"],
.stApp [data-testid="stMetricLabel"], .stApp [data-testid="stWidgetLabel"] * {{ color: {v['fg']}; }}
.stApp [data-testid="stCaptionContainer"], .stApp [data-testid="stCaptionContainer"] * {{ color: {v['muted']}; }}
.stApp hr {{ border-color: {v['border']}; }}
.stApp input, .stApp textarea, .stApp [data-baseweb="select"] > div, .stApp [data-baseweb="input"] > div,
.stApp [data-baseweb="textarea"] > div {{ background: {v['input']}; color: {v['fg']}; border-color: {v['border']}; }}
.stApp [data-baseweb="select"] *, .stApp [data-baseweb="input"] * {{ color: {v['fg']}; }}
[data-baseweb="popover"] > div, [data-baseweb="menu"], [data-baseweb="popover"] ul {{ background: {v['bg2']}; }}
[data-baseweb="menu"] li, [data-baseweb="popover"] li, [role="option"] {{ color: {v['fg']}; }}
.stApp .stButton > button, .stApp .stDownloadButton > button, .stApp [data-testid^="stBaseButton-secondary"] {{
    background: {v['card']}; color: {v['fg']}; border: 1px solid {v['border']}; }}
.stApp .stButton > button:hover, .stApp .stDownloadButton > button:hover {{ border-color: #3b82f6; }}
.stApp [data-baseweb="tab-list"] button, .stApp [data-baseweb="tab-list"] button * {{ color: {v['fg']}; }}
.stApp [data-baseweb="tab-border"] {{ background: {v['border']}; }}
.stApp [data-testid="stExpander"] {{ background: {v['card']}; border-color: {v['border']}; }}
.stApp [data-testid="stExpander"] summary, .stApp [data-testid="stExpander"] summary * {{ color: {v['fg']}; }}
.stApp [data-testid="stForm"] {{ border-color: {v['border']}; }}
.stApp [data-testid="stFileUploaderDropzone"] {{ background: {v['input']}; border-color: {v['border']}; }}
.stApp [data-testid="stFileUploaderDropzone"] * {{ color: {v['fg']}; }}
.stApp [data-testid="stCode"] pre, .stApp pre {{ background: {v['code']}; color: {v['fg']}; }}
.stApp [data-testid="stAlert"] * {{ color: {v['fg']}; }}
.stApp .svc-card {{ background: {v['card']}; border-color: {v['border']}; }}
{grid_rule}
</style>
"""


def map_tiles() -> dict:
    """Фонові тайли: стандартні OpenStreetMap (без API-ключа). Темна тема — CSS-фільтр у new_map()."""
    return {
        "tiles": "https://tile.openstreetmap.org/{z}/{x}/{y}.png",
        "attr": "&copy; OpenStreetMap contributors",
    }


def new_map(lats: list[float], lons: list[float], width_px: int = 700, height_px: int = 430):
    """Створює folium-карту з розрахованими центром і масштабом.

    fit_bounds не використовується: у прихованій вкладці контейнер має нульовий розмір,
    і Leaflet «віддаляє» карту до всього світу."""
    import folium

    lat_c, lon_c = (min(lats) + max(lats)) / 2, (min(lons) + max(lons)) / 2
    span_lon = max(max(lons) - min(lons), 0.02)
    span_lat = max(max(lats) - min(lats), 0.02)
    pad = 0.8  # запас по краях, щоб маркери не обрізались
    z_lon = np.log2(pad * width_px * 360 / (256 * span_lon))
    z_lat = np.log2(pad * height_px * 360 * max(np.cos(np.radians(lat_c)), 0.2) / (256 * span_lat))
    zoom = int(np.clip(np.floor(min(z_lon, z_lat) + 0.15), 3, 14))
    m = folium.Map(location=[lat_c, lon_c], zoom_start=zoom, control_scale=True, **map_tiles())

    css = ".leaflet-container{background:%s;}" % ("#1b1f27" if is_dark() else "#e5e7eb")
    if is_dark():  # затемнення растрових тайлів
        css += ".leaflet-tile-pane{filter:invert(1) hue-rotate(180deg) brightness(.92) contrast(.88);}"
    m.get_root().header.add_child(folium.Element(f"<style>{css}</style>"))
    # якщо карту відрисовано у прихованій вкладці — перерахувати розмір, коли вона стане видимою
    js = ("window.addEventListener('load',function(){var mp=window['%s'];if(!mp)return;"
          "setTimeout(function(){mp.invalidateSize();},200);"
          "if(window.ResizeObserver){new ResizeObserver(function(){mp.invalidateSize();}).observe(document.body);}});"
          % m.get_name())
    m.get_root().script.add_child(folium.Element(js))
    return m


def plotly_chart(fig, **kwargs) -> None:
    """st.plotly_chart із шаблоном поточної теми (theme=None, щоб Streamlit не перебивав кольори)."""
    fig.update_layout(template="plotly_dark" if is_dark() else "plotly_white")
    kwargs.setdefault("theme", None)
    st.plotly_chart(fig, **kwargs)


# ----------------------------------------------------------------------------
# Спільні допоміжні функції (журнал дій, сповіщення)
# ----------------------------------------------------------------------------
def add_audit(action: str, detail: str) -> None:
    ss = st.session_state
    entry = {
        "Час": datetime.now(),
        "Роль": ss.get("role_sel", "—"),
        "Дія": action,
        "Деталі": detail,
    }
    ss.audit.append(entry)
    ss.audit = ss.audit[-500:]
    db_add_audit(entry)


def add_alert(source: str, severity: str, message: str, link: str | None = None) -> None:
    ss = st.session_state
    ss.alert_seq += 1
    ss.alerts.append(
        {
            "id": ss.alert_seq,
            "time": datetime.now(),
            "source": source,
            "severity": severity,
            "message": message,
            "status": "Нова",
            "link": link,
            "by": "",
        }
    )
    ss.alerts = ss.alerts[-300:]


def resolve_links(link: str) -> None:
    """Автоматично закриває сповіщення, пов'язані з відновленим об'єктом."""
    for a in st.session_state.alerts:
        if a["link"] == link and a["status"] != "Вирішено":
            a["status"], a["by"] = "Вирішено", "авто"


def fmt_size(n: int) -> str:
    if n < 1024:
        return f"{n} Б"
    if n < 1024**2:
        return f"{n / 1024:.1f} КБ"
    return f"{n / 1024**2:.1f} МБ"


def make_doc(seq, title, category, level, version, owner, updated, data=None, filename=None) -> dict:
    if data is None:
        data = (
            f"{title}\nВерсія: {version}\nГриф доступу: {LEVELS[level]}\n\n"
            "Демонстраційний зміст документа."
        ).encode("utf-8")
        filename = f"DOC-{seq:03d}_v{version}.txt"
    return {
        "id": f"DOC-{seq:03d}",
        "title": title,
        "category": category,
        "level": level,
        "version": version,
        "owner": owner,
        "updated": updated,
        "content": data,
        "filename": filename,
        "size": len(data),
        "sha": hashlib.sha256(data).hexdigest()[:16],
        "history": [],
    }


def init_extra_state() -> None:
    """Стан для розділів 3 (ОТ-хаб) та 4 (API, реєстр документів)."""
    ss = st.session_state
    rng = ss.rng
    now = datetime.now()

    # --- ОТ-інтеграції
    ss.ot = {
        name: {
            "kind": kind,
            "proto": proto,
            "status": STATUS_OK,
            "latency": 45.0,
            "data_age": 3.0,
            "loss": 0.2,
            "since": now,
        }
        for name, kind, proto in OT_INTEGRATIONS
    }
    ss.nodes = [
        {"name": n, "kind": k, "lat": la, "lon": lo, "parent": p, "status": NODE_OK}
        for n, k, la, lo, p in OT_NODES
    ]

    # --- Аварійні сповіщення
    ss.alerts = []
    ss.alert_seq = 0
    add_alert("Мобільний застосунок бригад", "Середній", "Не вдалося передати GPS-трек бригади №7")
    add_alert("GIS", "Високий", "Тайли схеми електромереж не завантажуються (HTTP 503)")
    add_alert("ПЗ диспетчера (ОІК)", "Критично", "Затримка оновлення оперативної схеми понад 30 с")
    ss.alerts[0]["status"], ss.alerts[0]["by"] = "Вирішено", "авто"
    ss.alerts[1]["status"], ss.alerts[1]["by"] = "Підтверджено", "Диспетчер"

    # --- API-шлюзи
    ss.gateways = {}
    for name, path, proto, base, limit, lat in GATEWAYS:
        ss.gateways[name] = {
            "path": path,
            "proto": proto,
            "base": base,
            "limit": limit,
            "lat": lat,
            "enabled": True,
            "status": STATUS_OK,
            "rps": float(base),
            "p95": float(lat),
            "err": 0.3,
            "key_rotated": now - timedelta(days=int(rng.integers(5, 120))),
            "version": f"v{int(rng.integers(1, 3))}.{int(rng.integers(0, 9))}.{int(rng.integers(0, 20))}",
            "restarted": now - timedelta(hours=float(rng.uniform(2, 400))),
        }

    # --- Реєстр документів
    seeds = [
        ("Регламент оперативно-диспетчерського керування", "Внутрішній регламент", 2, "3.2", "Диспетчерська служба"),
        ("Інструкція з реагування на інциденти кібербезпеки", "Інструкція з кібербезпеки", 1, "2.0", "Відділ ІБ"),
        ("Політика паролів та керування доступом", "Інструкція з кібербезпеки", 1, "1.4", "Відділ ІБ"),
        ("Технічний регламент обміну даними SCADA/телемеханіка", "Технічний регламент", 3, "1.1", "Служба ОТ"),
        ("Схема сегментації ОТ-мережі та міжмережевих екранів", "Технічний регламент", 3, "2.3", "Відділ ІБ"),
        ("Порядок резервного копіювання та відновлення", "Технічний регламент", 2, "1.0", "ІТ-департамент"),
        ("Інструкція для бригад: мобільний застосунок нарядів", "Інструкція для бригад", 1, "1.6", "Служба ОТ"),
        ("План неперервності діяльності (BCP)", "Внутрішній регламент", 3, "1.2", "Керівництво"),
        ("Правила захисту персональних даних абонентів", "Внутрішній регламент", 2, "2.1", "Юридичний відділ"),
        ("Пам'ятка з кібергігієни для працівників", "Інструкція з кібербезпеки", 0, "1.3", "Відділ ІБ"),
        ("Наказ про порядок доступу до ОТ-систем", "Наказ / розпорядження", 2, "1.0", "Керівництво"),
    ]
    ss.docs = []
    for i, (title, cat, lvl, ver, owner) in enumerate(seeds, start=1):
        updated = now - timedelta(days=int(rng.integers(3, 300)))
        ss.docs.append(make_doc(i, title, cat, lvl, ver, owner, updated))
    ss.doc_seq = len(seeds)
    ss.audit = []


def init_ext_state() -> None:
    """Стан для розділів 6–9 (інциденти, активи, сповіщення). Викликати після init_extra_state()."""
    ss = st.session_state
    rng = ss.rng
    now = datetime.now()

    ss.incidents = []
    ss.inc_seq = 0
    ss.ext_cfg = {
        "auto_incident": True,
        "notify_min": "Критично",
        "dry_run": True,
        "last_alert_id": ss.alert_seq,  # уже наявні сповіщення не породжують інцидентів
    }
    ss.outbox = []

    assets = [
        ("SRV-BILLING-01", "Сервер", 3), ("SRV-DB-01", "Сервер", 3),
        ("SRV-MAIL-01", "Сервер", 2), ("SRV-APP-01", "Сервер", 2),
        ("SRV-FILE-01", "Сервер", 1), ("FW-EDGE-01", "Мережа", 3),
        ("FW-OT-01", "Мережа", 3), ("VPN-GW-01", "Мережа", 3),
        ("SCADA-SRV-01", "ОТ", 3), ("OIK-CLIENT-POOL", "ОТ", 2),
        ("GIS-SRV-01", "ОТ", 2), ("RTU-GW-GPRS-01", "ОТ", 2),
    ]
    ss.assets = [
        {
            "name": name,
            "kind": kind,
            "crit": crit,  # 1 - низька, 2 - середня, 3 - висока
            "os": str(rng.choice(["Ubuntu 22.04", "Windows Server 2019", "RHEL 9", "Cisco IOS", "Debian 12"])),
            "patched": now - timedelta(days=int(rng.integers(3, 140))),
            "cert_exp": now + timedelta(days=int(rng.integers(-5, 300))),
            "vuln_crit": int(rng.choice([0, 0, 0, 1, 2])),
            "vuln_high": int(rng.integers(0, 6)),
        }
        for name, kind, crit in assets
    ]


# ----------------------------------------------------------------------------
# Симуляція: ОТ-системи та API-шлюзи (замініть на реальні джерела)
# ----------------------------------------------------------------------------
def tick_ot() -> None:
    ss = st.session_state
    rng = ss.rng
    now = datetime.now()

    for name, s in ss.ot.items():
        prev = s["status"]
        r = rng.random()
        if prev == STATUS_OK and r < 0.02:
            new = STATUS_WARN
        elif prev == STATUS_OK and r < 0.026:
            new = STATUS_DOWN
        elif prev != STATUS_OK and r < 0.30:
            new = STATUS_OK
        else:
            new = prev

        if new != prev:
            s["status"], s["since"] = new, now
            if new == STATUS_DOWN:
                add_alert(s["kind"], "Критично", f"Втрачено зв'язок: {name}", link=name)
            elif new == STATUS_WARN:
                add_alert(s["kind"], "Високий", f"Деградація каналу/даних: {name}", link=name)
            else:
                resolve_links(name)

        if s["status"] == STATUS_OK:
            s["latency"] = max(5.0, float(rng.normal(45, 10)))
            s["data_age"] = float(rng.uniform(1, 8))
            s["loss"] = float(abs(rng.normal(0.2, 0.2)))
        elif s["status"] == STATUS_WARN:
            s["latency"] = max(50.0, float(rng.normal(420, 80)))
            s["data_age"] = float(rng.uniform(25, 90))
            s["loss"] = float(rng.uniform(3, 12))
        else:
            s["latency"] = 0.0
            s["data_age"] = s["data_age"] + 5
            s["loss"] = 100.0

    for n in ss.nodes:
        r = rng.random()
        link = f"node:{n['name']}"
        if n["status"] == NODE_OK and r < 0.02:
            n["status"] = NODE_STALE
        elif n["status"] == NODE_OK and r < 0.028:
            n["status"] = NODE_LOST
            sev = "Критично" if n["kind"].startswith("ПС") else "Високий"
            add_alert("Телемеханіка", sev, f"Немає зв'язку з RTU: {n['name']}", link=link)
        elif n["status"] != NODE_OK and r < 0.30:
            n["status"] = NODE_OK
            resolve_links(link)

    # програмні збої у ПЗ диспетчерів та бригад
    if rng.random() < 0.08:
        src, sev, msg = ALERT_TEMPLATES[int(rng.integers(len(ALERT_TEMPLATES)))]
        add_alert(src, sev, msg.format(n=int(rng.integers(1, 25))))


def tick_gateways() -> None:
    ss = st.session_state
    rng = ss.rng
    for name, g in ss.gateways.items():
        if not g["enabled"]:
            g.update(status=STATUS_OFF, rps=0.0, p95=0.0, err=0.0)
            continue

        prev = STATUS_OK if g["status"] == STATUS_OFF else g["status"]
        r = rng.random()
        if prev == STATUS_OK and r < 0.02:
            new = STATUS_WARN
        elif prev == STATUS_OK and r < 0.025:
            new = STATUS_DOWN
        elif prev != STATUS_OK and r < 0.30:
            new = STATUS_OK
        else:
            new = prev

        link = f"api:{name}"
        if new != prev:
            if new == STATUS_DOWN:
                add_alert("API-шлюз", "Критично", f"Шлюз недоступний: {name}", link=link)
            elif new == STATUS_WARN:
                add_alert("API-шлюз", "Високий", f"Зросла частка помилок/затримка: {name}", link=link)
            else:
                resolve_links(link)
        g["status"] = new

        if new == STATUS_OK:
            g["rps"] = max(0.0, float(rng.normal(g["base"], g["base"] * 0.1)))
            g["p95"] = max(5.0, float(rng.normal(g["lat"], g["lat"] * 0.15)))
            g["err"] = float(abs(rng.normal(0.4, 0.3)))
        elif new == STATUS_WARN:
            g["rps"] = max(0.0, float(rng.normal(g["base"] * 0.8, g["base"] * 0.1)))
            g["p95"] = g["lat"] * float(rng.uniform(2.5, 4))
            g["err"] = float(rng.uniform(4, 15))
        else:
            g["rps"], g["p95"], g["err"] = 0.0, 0.0, 100.0


def tick_all() -> None:
    tick_services()
    tick_auth_logs()
    tick_servers()
    tick_ot()
    tick_gateways()
    check_disk_forecasts()  # прогноз заповнення дисків (розділ 11)
    check_weather_alerts()  # метеоризики (розділ 14)
    tick_switching()  # імітація спрацювання захистів (розділ 12)
    process_new_alerts()  # автоінциденти та сповіщення (розділи 6 та 9)


def force_ot_outage() -> None:
    """Демо: аварія каналу зв'язку з SCADA/ОІК."""
    s = st.session_state.ot[OT_SCADA]
    if s["status"] != STATUS_DOWN:
        s["status"], s["since"] = STATUS_DOWN, datetime.now()
        add_alert(s["kind"], "Критично", f"Втрачено зв'язок: {OT_SCADA}", link=OT_SCADA)


# ----------------------------------------------------------------------------
# Загальні KPI (верх сторінки)
# ----------------------------------------------------------------------------
def render_global_kpis() -> None:
    ss = st.session_state
    active = [a for a in ss.alerts if a["status"] != "Вирішено"]
    crit = sum(1 for a in active if a["severity"] == "Критично")
    ot_bad = sum(1 for s in ss.ot.values() if s["status"] != STATUS_OK)
    api_bad = sum(1 for g in ss.gateways.values() if g["status"] in (STATUS_WARN, STATUS_DOWN))
    open_inc = sum(1 for i in ss.incidents if i["status"] != "Закрито")

    k1, k2, k3, k4, k5 = st.columns(5)
    k1.metric("Активні критичні алерти", crit, delta="потрібна реакція" if crit else "норма",
              delta_color="inverse")
    k2.metric("ОТ-інтеграцій із проблемами", f"{ot_bad} / {len(ss.ot)}")
    k3.metric("API-шлюзів із проблемами", f"{api_bad} / {len(ss.gateways)}")
    k4.metric("Відкритих інцидентів", open_inc)
    k5.metric("Документів у реєстрі", len(ss.docs))


# ----------------------------------------------------------------------------
# Розділ 3: Диспетчерський та технічний хаб
# ----------------------------------------------------------------------------
def node_effective_status(node: dict) -> str:
    parent = st.session_state.ot[node["parent"]]["status"]
    if parent == STATUS_DOWN:
        return NODE_LOST
    if parent == STATUS_WARN and node["status"] == NODE_OK:
        return NODE_STALE
    return node["status"]


def render_ot_map(height: int = 430, key: str = "ot_map") -> None:
    ss = st.session_state
    pts = []
    for n in ss.nodes:
        eff = node_effective_status(n)
        pts.append({**n, "eff": eff, "color": NODE_COLOR[eff]})

    try:
        import folium
        from streamlit_folium import st_folium
    except ImportError:
        st.map(pd.DataFrame(pts), latitude="lat", longitude="lon", color="color", size=3000)
        st.caption("Для інтерактивної карти та шарів GIS встановіть: pip install folium streamlit-folium")
        return

    lats, lons = [p["lat"] for p in pts], [p["lon"] for p in pts]
    m = new_map(lats, lons, width_px=700 if height <= 450 else 1100, height_px=height)

    layers = [L for L in ss.get("gis_layers", []) if L.get("visible", True)]
    for L in layers:  # імпортовані шари GeoJSON/KML
        color = GIS_COLOR.get(L["kind"], "#2563eb")
        try:
            folium.GeoJson(
                L["geojson"],
                name=L["name"],
                style_function=lambda _f, c=color: {"color": c, "weight": 3, "fillColor": c, "fillOpacity": 0.12},
                marker=folium.CircleMarker(radius=4, color=color, fill=True, fill_opacity=0.8),
                tooltip=folium.GeoJsonTooltip(fields=["name"], labels=False),
            ).add_to(m)
        except Exception:
            pass

    for p in pts:
        folium.CircleMarker(
            location=[p["lat"], p["lon"]],
            radius=11 if p["kind"].startswith("ПС") else 7,
            color=p["color"],
            weight=2,
            fill=True,
            fill_color=p["color"],
            fill_opacity=0.85,
            tooltip=f"{p['name']} — {p['eff']}",
            popup=folium.Popup(
                f"<b>{p['name']}</b><br>{p['kind']}<br>Статус: {p['eff']}<br>Канал: {p['parent']}",
                max_width=280,
            ),
        ).add_to(m)
    if layers:
        folium.LayerControl(collapsed=True).add_to(m)
    st_folium(m, height=height, use_container_width=True, returned_objects=[], key=key)


def alert_action(kind: str, role: str, ids: set | None = None, only_ack: bool = False) -> int:
    n = 0
    for a in st.session_state.alerts:
        if ids is not None and a["id"] not in ids:
            continue
        if kind == "ack" and a["status"] == "Нова":
            a["status"], a["by"] = "Підтверджено", role
            n += 1
        elif kind == "close" and a["status"] != "Вирішено":
            if only_ack and a["status"] != "Підтверджено":
                continue
            a["status"], a["by"] = "Вирішено", role
            n += 1
    return n


def render_ot(role: str) -> None:
    ss = st.session_state
    can_ack = ROLES[role]["ack"]

    # ---- KPI
    ot_ok = sum(1 for s in ss.ot.values() if s["status"] == STATUS_OK)
    lost = sum(1 for n in ss.nodes if node_effective_status(n) == NODE_LOST)
    active = [a for a in ss.alerts if a["status"] != "Вирішено"]
    crit = sum(1 for a in active if a["severity"] == "Критично")

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Інтеграцій у нормі", f"{ot_ok} / {len(ss.ot)}")
    k2.metric("Вузлів телемеханіки без зв'язку", f"{lost} / {len(ss.nodes)}")
    k3.metric("Активних сповіщень", len(active))
    k4.metric("З них критичних", crit)

    # ---- З'єднання SCADA / GIS
    st.subheader("🔌 Контроль з'єднань SCADA / GIS / телемеханіка")
    rows = []
    for name, s in ss.ot.items():
        rows.append(
            {
                "Статус": f"{STATUS_ICON[s['status']]} {s['status']}",
                "Інтеграція": name,
                "Тип": s["kind"],
                "Протокол": s["proto"],
                "Відгук, мс": 0 if s["status"] == STATUS_DOWN else round(s["latency"]),
                "Вік даних, с": round(s["data_age"]),
                "Втрати пакетів, %": round(s["loss"], 1),
                "У стані з": s["since"],
            }
        )
    st.dataframe(
        pd.DataFrame(rows),
        hide_index=True,
        width="stretch",
        column_config={"У стані з": st.column_config.DatetimeColumn(format="HH:mm:ss")},
    )

    left, right = st.columns([3, 2])
    with left:
        st.markdown("**Карта вузлів телемеханіки (Вінницька область)**")
        render_ot_map()
        st.caption("🟢 на зв'язку · 🟡 застарілі дані · 🔴 немає зв'язку. "
                   "Назви та розташування вузлів — умовні (демо).")
    with right:
        st.markdown("**Вузли телемеханіки**")
        nd = pd.DataFrame(
            [
                {
                    "Стан": f"{NODE_ICON[node_effective_status(n)]} {node_effective_status(n)}",
                    "Вузол": n["name"],
                    "Тип": n["kind"],
                }
                for n in ss.nodes
            ]
        )
        st.dataframe(nd, hide_index=True, width="stretch", height=430)

    # ---- Панель аварійних сповіщень
    st.divider()
    st.subheader("🚨 Панель аварійних сповіщень (ПЗ диспетчерів та бригад)")
    if crit:
        st.error(f"Активних критичних сповіщень: {crit}. Потрібна негайна реакція диспетчера.")

    f1, f2, f3 = st.columns([2, 2, 1])
    sev_f = f1.multiselect("Критичність", SEVERITIES, default=SEVERITIES, key="alert_sev")
    src_f = f2.multiselect("Джерело", ALERT_SOURCES, key="alert_src")
    show_res = f3.toggle("Вирішені", value=False, key="alert_show_resolved")

    order = {s: i for i, s in enumerate(SEVERITIES)}
    items = [
        a
        for a in ss.alerts
        if a["severity"] in sev_f
        and (not src_f or a["source"] in src_f)
        and (show_res or a["status"] != "Вирішено")
    ]
    items.sort(key=lambda a: (order[a["severity"]], -a["id"]))

    if not items:
        st.success("Сповіщень за вибраними фільтрами немає.")
    else:
        df = pd.DataFrame(
            [
                {
                    "ID": a["id"],
                    "Час": a["time"],
                    "Критичність": f"{SEV_ICON[a['severity']]} {a['severity']}",
                    "Джерело": a["source"],
                    "Повідомлення": a["message"],
                    "Статус": a["status"],
                    "Хто обробив": a["by"],
                }
                for a in items
            ]
        )
        st.dataframe(
            df,
            hide_index=True,
            width="stretch",
            height=min(420, 60 + 35 * len(df)),
            column_config={"Час": st.column_config.DatetimeColumn(format="DD.MM HH:mm:ss")},
        )

    if not can_ack:
        st.caption("👁️ Режим перегляду: ваша роль не дозволяє обробляти сповіщення.")
        return

    b1, b2, b3, b4, b5 = st.columns([1.3, 1.3, 0.8, 1, 1])
    if b1.button("✅ Підтвердити всі нові", key="al_ack_all"):
        n = alert_action("ack", role)
        add_audit("Сповіщення", f"Підтверджено всі нові: {n}")
        st.rerun(scope="fragment")
    if b2.button("☑️ Закрити всі підтверджені", key="al_close_ack"):
        n = alert_action("close", role, only_ack=True)
        add_audit("Сповіщення", f"Закрито підтверджені: {n}")
        st.rerun(scope="fragment")
    aid = b3.number_input("ID", min_value=0, step=1, key="al_id", label_visibility="collapsed",
                          help="ID сповіщення для точкової дії")
    if b4.button("Підтвердити #ID", key="al_ack_one", disabled=aid == 0):
        alert_action("ack", role, ids={int(aid)})
        add_audit("Сповіщення", f"Підтверджено #{int(aid)}")
        st.rerun(scope="fragment")
    if b5.button("Закрити #ID", key="al_close_one", disabled=aid == 0):
        alert_action("close", role, ids={int(aid)})
        add_audit("Сповіщення", f"Закрито #{int(aid)}")
        st.rerun(scope="fragment")


# ----------------------------------------------------------------------------
# Розділ 4а: Управління внутрішніми API та шлюзами
# ----------------------------------------------------------------------------
def render_api(role: str) -> None:
    ss = st.session_state
    can_admin = ROLES[role]["upload"]  # ІБ та адміністратори
    now = datetime.now()

    rows = []
    for name, g in ss.gateways.items():
        key_age = (now - g["key_rotated"]).days
        rows.append(
            {
                "Статус": f"{STATUS_ICON[g['status']]} {g['status']}",
                "Шлюз / сервіс": name,
                "Ендпоінт": g["path"],
                "Протокол": g["proto"],
                "RPS": round(g["rps"], 1),
                "Ліміт RPS": g["limit"],
                "Навантаження, %": round(g["rps"] / g["limit"] * 100, 1),
                "p95, мс": round(g["p95"]),
                "Помилки, %": round(g["err"], 1),
                "Вік ключа, дн": key_age,
                "Версія": g["version"],
            }
        )
    df = pd.DataFrame(rows)

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Шлюзів активно", f"{sum(g['enabled'] for g in ss.gateways.values())} / {len(ss.gateways)}")
    k2.metric("Сумарний RPS", f"{df['RPS'].sum():.0f}")
    k3.metric("Шлюзів із помилками > 5%", int(((df["Помилки, %"] > 5)).sum()), delta_color="inverse")
    k4.metric("Ключів старше 90 днів", int((df["Вік ключа, дн"] > 90).sum()), delta_color="inverse")

    st.subheader("🔗 Внутрішні API та шлюзи обміну даними")
    st.dataframe(
        df,
        hide_index=True,
        width="stretch",
        column_config={
            "Навантаження, %": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%.0f%%"),
            "Помилки, %": st.column_config.NumberColumn(format="%.1f"),
        },
    )

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Частка помилок, %**")
        fig = px.bar(df, x="Помилки, %", y="Шлюз / сервіс", orientation="h",
                     labels={"Шлюз / сервіс": ""})
        fig.add_vline(x=5, line_dash="dot", line_color="#ef4444")
        fig.update_layout(height=320, margin=dict(l=0, r=0, t=10, b=0),
                          paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        plotly_chart(fig, width="stretch", key="api_err_chart")
    with c2:
        st.markdown("**Затримка p95, мс**")
        fig = px.bar(df, x="p95, мс", y="Шлюз / сервіс", orientation="h",
                     labels={"Шлюз / сервіс": ""})
        fig.update_layout(height=320, margin=dict(l=0, r=0, t=10, b=0),
                          paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        plotly_chart(fig, width="stretch", key="api_lat_chart")

    st.subheader("🔧 Керування шлюзами")
    if not can_admin:
        st.info("Режим перегляду: керувати шлюзами можуть «Спеціаліст з ІБ» та «Адміністратор».")
        return

    name = st.selectbox("Шлюз", list(ss.gateways), key="gw_sel")
    g = ss.gateways[name]
    a1, a2, a3, a4 = st.columns(4)

    if a1.button("⏸ Вимкнути" if g["enabled"] else "▶ Увімкнути", key="gw_toggle", width="stretch"):
        g["enabled"] = not g["enabled"]
        add_audit("API-шлюз", f"{'Увімкнено' if g['enabled'] else 'Вимкнено'}: {name}")
        st.rerun(scope="fragment")
    if a2.button("🔄 Перезапустити", key="gw_restart", width="stretch", disabled=not g["enabled"]):
        g["status"], g["restarted"] = STATUS_OK, datetime.now()
        resolve_links(f"api:{name}")
        add_audit("API-шлюз", f"Перезапуск: {name}")
        st.rerun(scope="fragment")
    if a3.button("🔑 Ротація ключа", key="gw_rotate", width="stretch"):
        g["key_rotated"] = datetime.now()
        add_audit("API-шлюз", f"Ротація API-ключа: {name}")
        st.rerun(scope="fragment")

    with a4:
        new_limit = st.number_input("Ліміт RPS", 1, 5000, int(g["limit"]), key=f"gw_limit_{name}",
                                    label_visibility="collapsed")
    if int(new_limit) != int(g["limit"]):
        if st.button(f"Застосувати ліміт {int(new_limit)} RPS", key="gw_limit_apply"):
            g["limit"] = int(new_limit)
            add_audit("API-шлюз", f"Ліміт {name}: {int(new_limit)} RPS")
            st.rerun(scope="fragment")

    st.caption(f"Останній перезапуск: {g['restarted']:%d.%m.%Y %H:%M} · версія {g['version']}")


# ----------------------------------------------------------------------------
# Розділ 4б: Реєстр нормативних документів
# ----------------------------------------------------------------------------
def _read_upload(up):
    data = up.getvalue()
    if len(data) == 0:
        return None, "Файл порожній."
    if len(data) > MAX_UPLOAD_MB * 1024 * 1024:
        return None, f"Файл перевищує ліміт {MAX_UPLOAD_MB} МБ."
    return data, None


def _safe_name(name: str) -> str:
    return name.replace("/", "_").replace("\\", "_")


def render_docs(role: str) -> None:
    ss = st.session_state
    info = ROLES[role]
    clear = info["clear"]
    allowed_levels = [lv for lv in LEVELS if lv <= clear]

    st.subheader("📚 Реєстр нормативних документів")
    st.caption(
        f"Роль: **{role}** · рівень допуску: **{LEVEL_ICON[clear]} {LEVELS[clear]}**. "
        "Документи вищого грифа приховані. Розмежування доступу тут демонстраційне: "
        "у продакшні використовуйте SSO/AD, серверну перевірку прав і захищене сховище файлів."
    )

    # ---- Завантаження / оновлення (тільки ІБ та адміністратори)
    if info["upload"]:
        with st.expander("➕ Завантажити новий документ або оновити версію"):
            t_new, t_upd = st.tabs(["Новий документ", "Оновити версію"])

            with t_new:
                with st.form("form_new_doc", clear_on_submit=True):
                    title = st.text_input("Назва документа")
                    c1, c2, c3 = st.columns(3)
                    cat = c1.selectbox("Категорія", CATEGORIES)
                    lvl = c2.selectbox(
                        "Гриф доступу", allowed_levels,
                        index=min(1, len(allowed_levels) - 1),
                        format_func=lambda lv: f"{LEVEL_ICON[lv]} {LEVELS[lv]}",
                    )
                    ver = c3.text_input("Версія", "1.0")
                    up = st.file_uploader("Файл", type=UPLOAD_TYPES)
                    submitted = st.form_submit_button("Завантажити в реєстр")
                if submitted:
                    data, err = (None, "Оберіть файл.") if up is None else _read_upload(up)
                    if not title.strip():
                        err = "Вкажіть назву документа."
                    if err:
                        st.error(err)
                    else:
                        ss.doc_seq += 1
                        doc = make_doc(ss.doc_seq, title.strip(), cat, lvl, ver.strip() or "1.0",
                                       role, datetime.now(), data, _safe_name(up.name))
                        ss.docs.append(doc)
                        db_save_doc(doc)
                        add_audit("Документ", f"Додано {doc['id']} «{doc['title']}» ({LEVELS[lvl]})")
                        st.success(f"Документ {doc['id']} додано до реєстру.")

            with t_upd:
                editable = {d["id"]: d for d in ss.docs if d["level"] <= clear}
                with st.form("form_upd_doc", clear_on_submit=True):
                    target = st.selectbox(
                        "Документ", list(editable),
                        format_func=lambda i: f"{i} · {editable[i]['title']} (v{editable[i]['version']})",
                    )
                    c1, c2 = st.columns(2)
                    new_ver = c1.text_input("Нова версія", placeholder="напр. 1.1")
                    new_lvl = c2.selectbox(
                        "Гриф доступу", [None] + allowed_levels,
                        format_func=lambda lv: "Без змін" if lv is None else f"{LEVEL_ICON[lv]} {LEVELS[lv]}",
                    )
                    note = st.text_input("Коментар до змін")
                    up2 = st.file_uploader("Файл нової версії", type=UPLOAD_TYPES, key="upd_file")
                    submitted2 = st.form_submit_button("Оновити документ")
                if submitted2:
                    d = editable[target]
                    data, err = (None, "Оберіть файл.") if up2 is None else _read_upload(up2)
                    if not err and (not new_ver.strip() or new_ver.strip() == d["version"]):
                        err = "Вкажіть нову версію, відмінну від поточної."
                    if err:
                        st.error(err)
                    else:
                        d["history"].append(
                            {
                                "Версія": d["version"],
                                "Оновлено": d["updated"],
                                "Автор": d["owner"],
                                "Розмір": fmt_size(d["size"]),
                                "SHA-256": d["sha"],
                            }
                        )
                        d.update(
                            version=new_ver.strip(),
                            updated=datetime.now(),
                            owner=role,
                            content=data,
                            filename=_safe_name(up2.name),
                            size=len(data),
                            sha=hashlib.sha256(data).hexdigest()[:16],
                        )
                        if new_lvl is not None:
                            d["level"] = new_lvl
                        db_save_doc(d)
                        add_audit("Документ", f"Оновлено {d['id']} до v{d['version']}. {note}".strip())
                        st.success(f"{d['id']} оновлено до версії {d['version']}.")

    # ---- Фільтри
    accessible = [d for d in ss.docs if d["level"] <= clear]
    hidden = len(ss.docs) - len(accessible)

    f1, f2, f3 = st.columns(3)
    q = f1.text_input("Пошук за назвою", key="doc_q")
    cats = f2.multiselect("Категорія", CATEGORIES, key=f"doc_cat_{role}")
    lvls = f3.multiselect("Гриф", allowed_levels, key=f"doc_lvl_{role}",
                          format_func=lambda lv: f"{LEVEL_ICON[lv]} {LEVELS[lv]}")
    shown = [
        d
        for d in accessible
        if (not q or q.lower() in d["title"].lower())
        and (not cats or d["category"] in cats)
        and (not lvls or d["level"] in lvls)
    ]

    df = pd.DataFrame(
        [
            {
                "Код": d["id"],
                "Назва": d["title"],
                "Категорія": d["category"],
                "Гриф": f"{LEVEL_ICON[d['level']]} {LEVELS[d['level']]}",
                "Версія": d["version"],
                "Оновлено": d["updated"],
                "Відповідальний": d["owner"],
                "Розмір": fmt_size(d["size"]),
            }
            for d in shown
        ]
    )
    if df.empty:
        st.info("Документів за вибраними фільтрами не знайдено.")
    else:
        st.dataframe(
            df, hide_index=True, width="stretch",
            column_config={"Оновлено": st.column_config.DatetimeColumn(format="DD.MM.YYYY")},
        )
    if hidden:
        st.caption(f"🔒 Ще {hidden} документ(ів) вищого грифа приховано — недостатній рівень допуску.")

    # ---- Завантаження файлу та історія версій
    if shown:
        by_id = {d["id"]: d for d in shown}
        c1, c2 = st.columns([3, 1])
        sel = c1.selectbox(
            "Документ для завантаження / перегляду історії", list(by_id),
            format_func=lambda i: f"{i} · {by_id[i]['title']} (v{by_id[i]['version']})",
        )
        d = by_id[sel]
        c2.download_button(
            "⬇️ Завантажити", data=d["content"], file_name=d["filename"],
            width="stretch",
            on_click=add_audit, args=("Завантаження", f"{d['id']} v{d['version']}"),
            key=f"dl_{d['id']}_{d['version']}",
        )
        st.caption(f"Файл: {d['filename']} · SHA-256 (скорочено): `{d['sha']}`")
        if d["history"]:
            with st.expander(f"🕓 Історія версій ({len(d['history'])})"):
                st.dataframe(pd.DataFrame(d["history"]), hide_index=True, width="stretch")

        buf = BytesIO()
        with pd.ExcelWriter(buf, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="Реєстр")
        st.download_button(
            "📥 Експорт переліку в Excel", data=buf.getvalue(), file_name="registry_documents.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )

    # ---- Журнал дій
    if info["audit"]:
        with st.expander(f"🧾 Журнал дій ({len(ss.audit)})"):
            if ss.audit:
                st.dataframe(
                    pd.DataFrame(ss.audit[::-1][:100]), hide_index=True, width="stretch",
                    column_config={"Час": st.column_config.DatetimeColumn(format="DD.MM HH:mm:ss")},
                )
            else:
                st.caption("Записів поки немає.")


# ----------------------------------------------------------------------------
# Розділ 6: Інциденти
# ----------------------------------------------------------------------------
def pick_playbook(source: str, message: str) -> str:
    text = f"{source} {message}".lower()
    if "диск" in text or "заповн" in text:
        return "Заповнення диска / ємність"
    if "brute" in text or "злам" in text or "авториз" in text:
        return "Brute-force / компрометація облікового запису"
    if "scada" in text or "rtu" in text or "телемех" in text or ("оік" in text and "зв'язок" in text):
        return "Втрата зв'язку SCADA / телемеханіки"
    if "api" in text or "шлюз" in text:
        return "Збій API-шлюзу"
    if "диспетчер" in text or "бригад" in text or "наряд" in text:
        return "Збій ПЗ диспетчера / бригад"
    return "Загальний інцидент"


def create_incident(title: str, severity: str, alert_id: int | None = None,
                    playbook: str | None = None, who: str = "авто") -> dict:
    ss = st.session_state
    ss.inc_seq += 1
    src, msg = "", title
    if alert_id:
        for a in ss.alerts:
            if a["id"] == alert_id:
                src, msg = a["source"], a["message"]
    pb = playbook or pick_playbook(src, msg)
    inc = {
        "id": f"INC-{ss.inc_seq:03d}",
        "title": title,
        "severity": severity,
        "status": "Відкрито",
        "assignee": "",
        "created": datetime.now(),
        "acked": None,
        "closed": None,
        "alert_id": alert_id,
        "playbook": pb,
        "steps": {s: False for s in PLAYBOOKS[pb]},
        "timeline": [(datetime.now(), who, f"Інцидент створено ({severity})")],
    }
    ss.incidents.append(inc)
    db_save_incident(inc)
    add_audit("Інцидент", f"Створено {inc['id']}: {title}")
    return inc


def _set_status(inc: dict, new: str, who: str) -> None:
    if new == inc["status"]:
        return
    now = datetime.now()
    if new != "Відкрито" and inc["acked"] is None:
        inc["acked"] = now
    if new == "Закрито":
        inc["closed"] = now
        for a in st.session_state.alerts:
            if a["id"] == inc["alert_id"] and a["status"] != "Вирішено":
                a["status"], a["by"] = "Вирішено", who
    else:
        inc["closed"] = None
    inc["timeline"].append((now, who, f"Статус: {inc['status']} → {new}"))
    inc["status"] = new
    db_save_incident(inc)
    add_audit("Інцидент", f"{inc['id']}: статус {new}")


def _fmt_minutes(values: list[float]) -> str:
    if not values:
        return "—"
    m = sum(values) / len(values)
    return f"{m:.0f} хв" if m < 120 else f"{m / 60:.1f} год"


def render_incidents(role: str) -> None:
    ss = st.session_state
    can = ROLES[role]["ack"]
    incs = ss.incidents
    open_ = [i for i in incs if i["status"] != "Закрито"]
    mtta = [(i["acked"] - i["created"]).total_seconds() / 60 for i in incs if i["acked"]]
    mttr = [(i["closed"] - i["created"]).total_seconds() / 60 for i in incs if i["closed"]]

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Відкритих інцидентів", len(open_))
    k2.metric("Критичних відкритих", sum(1 for i in open_ if i["severity"] == "Критично"))
    k3.metric("MTTA (середній час реакції)", _fmt_minutes(mtta))
    k4.metric("MTTR (середній час вирішення)", _fmt_minutes(mttr))

    if can:
        with st.expander("➕ Створити інцидент"):
            active = [a for a in ss.alerts if a["status"] != "Вирішено"]
            with st.form("form_new_inc", clear_on_submit=True):
                title = st.text_input("Назва інциденту")
                c1, c2, c3 = st.columns(3)
                sev = c1.selectbox("Критичність", SEVERITIES)
                alert_id = c2.selectbox(
                    "Пов'язане сповіщення", [None] + [a["id"] for a in active],
                    format_func=lambda i: "—" if i is None else
                    next(f"#{a['id']} · {a['message'][:50]}" for a in active if a["id"] == i),
                )
                pb = c3.selectbox("Плейбук", ["(авто)"] + list(PLAYBOOKS))
                ok = st.form_submit_button("Створити")
            if ok:
                if not title.strip():
                    st.error("Вкажіть назву.")
                else:
                    inc = create_incident(title.strip(), sev, alert_id,
                                          None if pb == "(авто)" else pb, who=role)
                    st.success(f"Створено {inc['id']}.")
                    st.rerun()

    st.subheader("🧯 Реєстр інцидентів")
    if not incs:
        st.info("Інцидентів поки немає. Критичні алерти створюють їх автоматично "
                "(налаштування — у вкладці «Сповіщення»).")
        return

    df = pd.DataFrame([
        {
            "Код": i["id"],
            "Критичність": f"{SEV_ICON[i['severity']]} {i['severity']}",
            "Назва": i["title"],
            "Статус": i["status"],
            "Відповідальний": i["assignee"] or "—",
            "Створено": i["created"],
            "Кроки плейбука": f"{sum(i['steps'].values())}/{len(i['steps'])}",
        }
        for i in sorted(incs, key=lambda x: (x["status"] == "Закрито", SEV_ORDER[x["severity"]], x["created"]))
    ])
    st.dataframe(df, hide_index=True, width="stretch",
                 column_config={"Створено": st.column_config.DatetimeColumn(format="DD.MM HH:mm")})

    by_id = {i["id"]: i for i in incs}
    sel = st.selectbox("Інцидент для роботи", list(by_id), key="inc_sel",
                       format_func=lambda k: f"{k} · {by_id[k]['title']}")
    inc = by_id[sel]

    left, right = st.columns([3, 2])
    with left:
        st.markdown(f"**Плейбук:** {inc['playbook']}")
        for n, step in enumerate(inc["steps"]):
            val = st.checkbox(step, value=inc["steps"][step], key=f"pb_{inc['id']}_{n}", disabled=not can)
            if val != inc["steps"][step]:
                inc["steps"][step] = val
                inc["timeline"].append((datetime.now(), role, f"{'Виконано' if val else 'Знято'}: {step}"))
                db_save_incident(inc)
        if can:
            with st.form(f"comment_{inc['id']}", clear_on_submit=True):
                text = st.text_input("Коментар")
                if st.form_submit_button("Додати коментар") and text.strip():
                    inc["timeline"].append((datetime.now(), role, text.strip()))
                    db_save_incident(inc)
                    st.rerun()
    with right:
        if can:
            new_status = st.selectbox("Статус", INC_STATUSES, index=INC_STATUSES.index(inc["status"]),
                                      key=f"st_{inc['id']}")
            assignee = st.text_input("Відповідальний", inc["assignee"], key=f"as_{inc['id']}")
            if st.button("Застосувати", key=f"apply_{inc['id']}", width="stretch"):
                if assignee != inc["assignee"]:
                    inc["timeline"].append((datetime.now(), role, f"Відповідальний: {assignee or '—'}"))
                    inc["assignee"] = assignee
                _set_status(inc, new_status, role)
                db_save_incident(inc)
                st.rerun()
        else:
            st.info("Режим перегляду: змінювати інциденти можуть диспетчери, ІБ та адміністратори.")

    with st.expander("🕓 Таймлайн", expanded=True):
        st.dataframe(
            pd.DataFrame(inc["timeline"][::-1], columns=["Час", "Хто", "Подія"]),
            hide_index=True, width="stretch",
            column_config={"Час": st.column_config.DatetimeColumn(format="DD.MM HH:mm:ss")},
        )


# ----------------------------------------------------------------------------
# Розділ 7: Активи та відповідність
# ----------------------------------------------------------------------------
def assets_df() -> pd.DataFrame:
    now = datetime.now()
    rows = []
    for a in st.session_state.assets:
        patch_age = (now - a["patched"]).days
        cert_left = (a["cert_exp"] - now).days
        risk = (a["vuln_crit"] * 5 + a["vuln_high"] * 2
                + (3 if patch_age > 60 else 0) + (4 if cert_left < 30 else 0)) * a["crit"]
        rows.append({
            "Актив": a["name"], "Тип": a["kind"], "ОС": a["os"],
            "Критичність": CRIT_LABEL[a["crit"]],
            "Вік патчу, дн": patch_age, "Сертифікат, дн до кінця": cert_left,
            "Крит. вразл.": a["vuln_crit"], "Висок. вразл.": a["vuln_high"],
            "Ризик-скор": risk,
        })
    return pd.DataFrame(rows).sort_values("Ризик-скор", ascending=False)


def render_assets(role: str) -> None:
    ss = st.session_state
    df = assets_df()

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Активів у реєстрі", len(df))
    k2.metric("Патч старше 60 днів", int((df["Вік патчу, дн"] > 60).sum()), delta_color="inverse")
    k3.metric("Сертифікатів < 30 днів", int((df["Сертифікат, дн до кінця"] < 30).sum()), delta_color="inverse")
    k4.metric("Критичних вразливостей", int(df["Крит. вразл."].sum()), delta_color="inverse")

    expired = df[df["Сертифікат, дн до кінця"] < 0]
    if not expired.empty:
        st.error("Прострочені сертифікати: " + ", ".join(expired["Актив"]))

    st.subheader("🧩 Реєстр активів і стан відповідності")
    st.dataframe(
        df, hide_index=True, width="stretch",
        column_config={"Ризик-скор": st.column_config.ProgressColumn(
            min_value=0, max_value=max(int(df["Ризик-скор"].max()), 1), format="%d")},
    )

    fig = px.bar(df.head(8), x="Ризик-скор", y="Актив", orientation="h", color="Тип",
                 labels={"Актив": ""})
    fig.update_yaxes(autorange="reversed")
    fig.update_layout(height=320, margin=dict(l=0, r=0, t=10, b=0),
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
    plotly_chart(fig, width="stretch", key="asset_risk")

    if not ROLES[role]["upload"]:
        st.info("Режим перегляду: змінювати статус активів можуть «Спеціаліст з ІБ» та «Адміністратор».")
        return

    st.subheader("🔧 Дії з активом")
    name = st.selectbox("Актив", [a["name"] for a in ss.assets], key="asset_sel")
    asset = next(a for a in ss.assets if a["name"] == name)
    c1, c2 = st.columns(2)
    if c1.button("🩹 Позначити пропатченим", width="stretch"):
        asset.update(patched=datetime.now(), vuln_crit=0, vuln_high=0)
        add_audit("Актив", f"Пропатчено: {name}")
        st.rerun()
    if c2.button("🔐 Сертифікат оновлено (+365 дн)", width="stretch"):
        asset["cert_exp"] = datetime.now() + timedelta(days=365)
        add_audit("Актив", f"Оновлено сертифікат: {name}")
        st.rerun()


# ----------------------------------------------------------------------------
# Розділ 8: Звіти та SLA
# ----------------------------------------------------------------------------
def build_summary() -> str:
    ss = st.session_state
    active = [a for a in ss.alerts if a["status"] != "Вирішено"]
    crit = [a for a in active if a["severity"] == "Критично"]
    open_inc = [i for i in ss.incidents if i["status"] != "Закрито"]
    bad_svc = [n for n, s in ss.services.items() if s["status"] != STATUS_OK]
    bad_gw = [n for n, g in ss.gateways.items() if g["status"] in (STATUS_WARN, STATUS_DOWN)]
    lines = [
        f"Оперативне зведення на {datetime.now():%d.%m.%Y %H:%M}",
        "",
        f"Сервіси з проблемами: {', '.join(bad_svc) or 'немає'}",
        f"API-шлюзи з проблемами: {', '.join(bad_gw) or 'немає'}",
        f"Активних сповіщень: {len(active)} (критичних: {len(crit)})",
        f"Відкритих інцидентів: {len(open_inc)}",
    ]
    for a in crit[:10]:
        lines.append(f"  - #{a['id']} [{a['source']}] {a['message']}")
    return "\n".join(lines)


def build_report_xlsx() -> bytes:
    ss = st.session_state
    sheets = {
        "Алерти": pd.DataFrame(ss.alerts).drop(columns=["link"], errors="ignore"),
        "Інциденти": pd.DataFrame([
            {k: v for k, v in i.items() if k not in ("steps", "timeline")} for i in ss.incidents
        ]),
        "Шлюзи": pd.DataFrame([
            {"Шлюз": n, "Статус": g["status"], "RPS": round(g["rps"], 1), "p95": round(g["p95"]),
             "Помилки %": round(g["err"], 1)} for n, g in ss.gateways.items()
        ]),
        "Активи": assets_df(),
        "Журнал дій": pd.DataFrame(ss.audit),
    }
    buf = BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as w:
        for name, frame in sheets.items():
            # порожній DataFrame без колонок openpyxl записати не може — додаємо заглушку
            if frame.empty and len(frame.columns) == 0:
                frame = pd.DataFrame({"Дані": ["Записів немає"]})
            frame.to_excel(w, index=False, sheet_name=name)
    return buf.getvalue()


def render_reports(role: str) -> None:
    ss = st.session_state
    st.subheader("📈 SLA сервісів")
    rows = [
        {"Сервіс": n, "Uptime, %": round(s["uptime"], 3), "Ціль, %": SLA_TARGET,
         "SLA": "🟢 Виконано" if s["uptime"] >= SLA_TARGET else "🔴 Порушено"}
        for n, s in ss.services.items()
    ]
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")

    st.subheader("📝 Оперативне зведення")
    summary = build_summary()
    st.code(summary, language=None)

    c1, c2 = st.columns(2)
    c1.download_button("⬇️ Зведення (.txt)", data=summary.encode("utf-8"),
                       file_name=f"summary_{datetime.now():%Y%m%d_%H%M}.txt", width="stretch")
    if ROLES[role]["audit"]:
        c2.download_button(
            "📥 Повний звіт (Excel)", data=build_report_xlsx(),
            file_name=f"report_{datetime.now():%Y%m%d_%H%M}.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            width="stretch",
            on_click=add_audit, args=("Звіт", "Експорт повного звіту"),
        )
    else:
        c2.caption("Повний звіт доступний ролям ІБ та Адміністратор.")


# ----------------------------------------------------------------------------
# Розділ 9: Сповіщення (Telegram) + обробка нових алертів
# ----------------------------------------------------------------------------
def _secret(name: str) -> str:
    try:
        return str(st.secrets.get(name, "")) or os.environ.get(name, "")
    except Exception:
        return os.environ.get(name, "")


def send_telegram(text: str, token: str, chat_id: str) -> tuple[bool, str]:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=8) as r:
            return json.loads(r.read()).get("ok", False), "OK"
    except Exception as e:  # мережеві помилки не повинні ламати дашборд
        return False, str(e)[:120]


def notify(text: str, severity: str) -> None:
    ss = st.session_state
    cfg = ss.ext_cfg
    token = cfg.get("token") or _secret("TELEGRAM_BOT_TOKEN")
    chat = cfg.get("chat") or _secret("TELEGRAM_CHAT_ID")
    if cfg["dry_run"] or not (token and chat):
        status = "dry-run" if cfg["dry_run"] else "не налаштовано"
    else:
        ok, info = send_telegram(text, token, chat)
        status = "надіслано" if ok else f"помилка: {info}"
    ss.outbox.append({"Час": datetime.now(), "Критичність": severity, "Текст": text, "Статус": status})
    ss.outbox = ss.outbox[-200:]


def process_new_alerts() -> None:
    """Після кожного тіку: автоінциденти та сповіщення для нових алертів."""
    ss = st.session_state
    cfg = ss.ext_cfg
    new = [a for a in ss.alerts if a["id"] > cfg["last_alert_id"]]
    for a in new:
        dup = any(i["title"] == a["message"] and i["status"] != "Закрито" for i in ss.incidents)
        if (cfg["auto_incident"] and a["severity"] == "Критично"
                and a["source"] != "Метеомоніторинг" and not dup):  # прогноз погоди — не інцидент
            create_incident(a["message"], a["severity"], alert_id=a["id"])
        if SEV_ORDER[a["severity"]] <= SEV_ORDER[cfg["notify_min"]]:
            notify(f"[{a['severity']}] {a['source']}: {a['message']}", a["severity"])
    if new:
        cfg["last_alert_id"] = max(a["id"] for a in new)


def render_notifications(role: str) -> None:
    ss = st.session_state
    cfg = ss.ext_cfg
    admin = ROLES[role]["upload"]

    st.subheader("🔔 Правила автоматизації та сповіщень")
    if not admin:
        st.info("Налаштування доступні ролям ІБ та Адміністратор.")
    c1, c2, c3 = st.columns(3)
    cfg["auto_incident"] = c1.toggle("Автостворення інцидентів із критичних алертів",
                                     cfg["auto_incident"], disabled=not admin)
    cfg["notify_min"] = c2.selectbox("Надсилати від критичності", SEVERITIES,
                                     index=SEVERITIES.index(cfg["notify_min"]), disabled=not admin)
    cfg["dry_run"] = c3.toggle("Dry-run (не надсилати реально)", cfg["dry_run"], disabled=not admin)

    if admin:
        with st.expander("Telegram-бот"):
            st.caption("Краще задати TELEGRAM_BOT_TOKEN і TELEGRAM_CHAT_ID у .streamlit/secrets.toml "
                       "або змінних середовища. Значення нижче зберігаються лише в сесії.")
            cfg["token"] = st.text_input("Bot token", cfg.get("token", ""), type="password")
            cfg["chat"] = st.text_input("Chat ID", cfg.get("chat", ""))
            if st.button("Надіслати тестове повідомлення"):
                notify("Тестове сповіщення з Центру моніторингу", "Середній")
                add_audit("Сповіщення", "Тестове повідомлення")
                st.rerun()

    st.subheader("📤 Вихідна черга")
    if ss.outbox:
        st.dataframe(pd.DataFrame(ss.outbox[::-1][:100]), hide_index=True, width="stretch",
                     column_config={"Час": st.column_config.DatetimeColumn(format="DD.MM HH:mm:ss")})
    else:
        st.caption("Сповіщень поки не було.")


# ----------------------------------------------------------------------------
# Головна програма
# ----------------------------------------------------------------------------
def main() -> None:
    init_state()
    init_theme()
    st.markdown(CSS + theme_css(), unsafe_allow_html=True)

    # --- Бічна панель
    with st.sidebar:
        st.header("⚙️ Налаштування")
        st.toggle("🌙 Темна тема", key="dark_theme", on_change=persist_theme,
                  help="Перемикає вигляд інтерфейсу, графіків і карт. Вибір зберігається в адресі (?theme=dark|light).")
        auto = st.toggle("Автооновлення (реальний час)", value=True)
        interval = st.slider("Інтервал оновлення, с", 2, 30, 5, disabled=not auto)
        window_min = st.select_slider(
            "Вікно аналізу безпеки, хв", options=[5, 15, 30, 60], value=15
        )
        threshold = st.slider(
            "Поріг brute-force (невдалих спроб з 1 IP)", 5, 50, 15,
            help="Якщо з однієї IP-адреси за вибране вікно кількість невдалих спроб "
                 "перевищує поріг — генерується сповіщення.",
        )
        st.divider()
        st.subheader("🔮 Прогноз та аномалії")
        st.slider("Попереджати, якщо диск заповниться швидше ніж, год", 1, 168, 24, key="fc_warn_h")
        st.slider("Поріг аномалії (|z|)", 2.0, 6.0, 3.0, 0.5, key="z_thr",
                  help="Скільки стандартних відхилень від базового рівня вважати аномалією.")
        st.divider()
        st.subheader("👤 Доступ (демо)")
        role = st.selectbox("Роль користувача", list(ROLES), index=3, key="role_sel")
        st.caption(f"Допуск: {LEVEL_ICON[ROLES[role]['clear']]} {LEVELS[ROLES[role]['clear']]}")
        st.divider()
        st.subheader("🗄️ Сховище даних")
        db_ok, db_info = db_status()
        st.caption(f"✅ Збереження увімкнено: {db_info}" if db_ok else f"⚠️ {db_info}")
        if db_ok and db_info == "sqlite":
            st.caption("SQLite-файл у хмарі (Streamlit Community Cloud) скидається при перезапуску застосунку. "
                       "Для постійного збереження задайте DATABASE_URL (PostgreSQL) у Secrets.")
        if role == "Адміністратор" and db_ok:
            with st.expander("Небезпечна зона"):
                wipe_ok = st.checkbox("Підтверджую повне очищення БД", key="db_wipe_ok")
                if st.button("Очистити БД і скинути", disabled=not wipe_ok, width="stretch"):
                    db_clear_all()
                    for k in list(st.session_state.keys()):
                        del st.session_state[k]
                    st.rerun()
        st.divider()
        st.subheader("🧪 Демонстрація")
        if st.button("Симулювати brute-force атаку", width="stretch"):
            st.session_state.attack_ticks = 6
            st.session_state.attacker = None
        st.button("Симулювати збій каналу SCADA", width="stretch", on_click=force_ot_outage)
        if st.button("Скинути дані симуляції", width="stretch"):
            for k in list(st.session_state.keys()):
                del st.session_state[k]
            st.rerun()
        st.caption("Дані симульовані. Для продакшну підключіть реальні джерела "
                   "(Zabbix/Prometheus, SIEM, Active Directory, Veeam, SCADA/ОІК, GIS тощо).")

    st.title("🛡️ Центр моніторингу, диспетчерський хаб та адміністрування")

    run_every = f"{interval}s" if auto else None

    # Верхня панель: тік симуляції + загальний стан
    @st.fragment(run_every=run_every)
    def header_live() -> None:
        tick_all()
        st.subheader("Загальний стан критичних систем")
        render_overall_and_services()
        render_global_kpis()

    header_live()
    st.divider()

    (tab_sec, tab_infra, tab_ot, tab_api, tab_docs,
     tab_inc, tab_assets, tab_rep, tab_notif, tab_sw, tab_gis, tab_wx) = st.tabs(
        [
            "🔐 Кібербезпека та доступ",
            "🖥️ Інфраструктура",
            "📡 Диспетчерський хаб (ОТ)",
            "🔗 API та шлюзи",
            "📚 Реєстр документів",
            "🧯 Інциденти",
            "🧩 Активи",
            "📈 Звіти та SLA",
            "🔔 Сповіщення",
            "🔀 Журнал переключень",
            "🗺️ GIS: схеми мереж",
            "🌦️ Метеомоніторинг",
        ]
    )

    with tab_sec:
        @st.fragment(run_every=run_every)
        def sec_live() -> None:
            render_security(window_min, threshold)

        sec_live()

    with tab_infra:
        @st.fragment(run_every=run_every)
        def infra_live() -> None:
            render_infrastructure()

        infra_live()

    with tab_ot:
        @st.fragment(run_every=run_every)
        def ot_live() -> None:
            render_ot(role)

        ot_live()

    with tab_api:
        @st.fragment(run_every=run_every)
        def api_live() -> None:
            render_api(role)

        api_live()

    # Наступні вкладки — без автооновлення, щоб не збивати форми, чекбокси та завантаження
    with tab_docs:
        render_docs(role)

    with tab_inc:
        render_incidents(role)

    with tab_assets:
        render_assets(role)

    with tab_rep:
        render_reports(role)

    with tab_notif:
        render_notifications(role)

    with tab_sw:
        render_switching(role)

    with tab_gis:
        render_gis(role)

    with tab_wx:
        render_weather(role)


if __name__ == "__main__":
    main()
