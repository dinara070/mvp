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

Запуск:
    pip install streamlit pandas numpy plotly openpyxl folium streamlit-folium
    streamlit run security_ops_dashboard.py

Дані у цій версії СИМУЛЬОВАНІ (генеруються в реальному часі).
Щоб підключити реальні джерела, замініть функції-провайдери:
    tick_services(), tick_auth_logs(), tick_servers(), get_backups(),
    tick_ot(), tick_gateways()
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from io import BytesIO

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

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
    {t[0] for t in ALERT_TEMPLATES} | {i[1] for i in OT_INTEGRATIONS} | {"API-шлюз"}
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
# audit — бачить журнал дій
ROLES = {
    "Працівник": {"clear": 1, "upload": False, "ack": False, "audit": False},
    "Диспетчер": {"clear": 2, "upload": False, "ack": True, "audit": False},
    "Спеціаліст з ІБ": {"clear": 3, "upload": True, "ack": True, "audit": True},
    "Адміністратор": {"clear": 3, "upload": True, "ack": True, "audit": True},
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
        }
        for s in SERVERS
    }
    ss.cpu_hist = pd.DataFrame(
        {s: [ss.servers[s]["cpu"]] for s in SERVERS}, index=[now]
    )
    ss.ram_hist = pd.DataFrame(
        {s: [ss.servers[s]["ram"]] for s in SERVERS}, index=[now]
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
    for name, m in ss.servers.items():
        m["cpu"] = float(np.clip(m["cpu"] + rng.normal(0, 6) + (rng.random() < 0.03) * 30, 3, 100))
        m["cpu"] = m["cpu"] * 0.93 + 35 * 0.07  # повернення до середнього
        m["ram"] = float(np.clip(m["ram"] + rng.normal(0, 1.5), 15, 99))
        m["disk"] = float(np.clip(m["disk"] + abs(rng.normal(0.02, 0.05)), 10, 99))
        m["net"] = float(np.clip(m["net"] + rng.normal(0, 40), 5, 1000))

    ss.cpu_hist.loc[now] = [ss.servers[s]["cpu"] for s in SERVERS]
    ss.ram_hist.loc[now] = [ss.servers[s]["ram"] for s in SERVERS]
    ss.cpu_hist = ss.cpu_hist.tail(MAX_HISTORY)
    ss.ram_hist = ss.ram_hist.tail(MAX_HISTORY)


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
            st.plotly_chart(fig, width="stretch", key="geo_map")

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
            st.plotly_chart(fig2, width="stretch", key="auth_timeline")

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
        (c1, ss.cpu_hist, "Навантаження CPU, %", "cpu_chart"),
        (c2, ss.ram_hist, "Використання RAM, %", "ram_chart"),
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
            st.plotly_chart(fig, width="stretch", key=key)

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


# ----------------------------------------------------------------------------
# Спільні допоміжні функції (журнал дій, сповіщення)
# ----------------------------------------------------------------------------
def add_audit(action: str, detail: str) -> None:
    ss = st.session_state
    ss.audit.append(
        {
            "Час": datetime.now(),
            "Роль": ss.get("role_sel", "—"),
            "Дія": action,
            "Деталі": detail,
        }
    )
    ss.audit = ss.audit[-500:]


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
    if rng.random() < 0.22:
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


def render_ot_map() -> None:
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
        st.caption("Для інтерактивної карти встановіть: pip install folium streamlit-folium")
        return

    m = folium.Map(location=[49.05, 28.55], zoom_start=8, control_scale=True)
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
    st_folium(m, height=430, use_container_width=True, returned_objects=[], key="ot_map")


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
        st.plotly_chart(fig, width="stretch", key="api_err_chart")
    with c2:
        st.markdown("**Затримка p95, мс**")
        fig = px.bar(df, x="p95, мс", y="Шлюз / сервіс", orientation="h",
                     labels={"Шлюз / сервіс": ""})
        fig.update_layout(height=320, margin=dict(l=0, r=0, t=10, b=0),
                          paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig, width="stretch", key="api_lat_chart")

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
        if can:
            with st.form(f"comment_{inc['id']}", clear_on_submit=True):
                text = st.text_input("Коментар")
                if st.form_submit_button("Додати коментар") and text.strip():
                    inc["timeline"].append((datetime.now(), role, text.strip()))
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
    st.plotly_chart(fig, width="stretch", key="asset_risk")

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
        if cfg["auto_incident"] and a["severity"] == "Критично":
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
    st.markdown(CSS, unsafe_allow_html=True)

    # --- Бічна панель
    with st.sidebar:
        st.header("⚙️ Налаштування")
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
        st.subheader("👤 Доступ (демо)")
        role = st.selectbox("Роль користувача", list(ROLES), index=3, key="role_sel")
        st.caption(f"Допуск: {LEVEL_ICON[ROLES[role]['clear']]} {LEVELS[ROLES[role]['clear']]}")
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
     tab_inc, tab_assets, tab_rep, tab_notif) = st.tabs(
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


if __name__ == "__main__":
    main()
