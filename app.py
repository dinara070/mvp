"""
Центр моніторингу та безпеки (Security & Operations Dashboard)
Один файл, Streamlit.

Запуск:
    pip install streamlit pandas numpy plotly
    streamlit run security_ops_dashboard.py

Дані у цій версії СИМУЛЬОВАНІ (генеруються в реальному часі).
Щоб підключити реальні джерела, замініть функції-провайдери:
    tick_services(), tick_auth_logs(), tick_servers(), get_backups()
"""

from __future__ import annotations

from datetime import datetime, timedelta

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
            st.plotly_chart(fig, use_container_width=True, key="geo_map")

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
            st.plotly_chart(fig2, use_container_width=True, key="auth_timeline")

    # --- Сповіщення
    st.subheader("🚨 Сповіщення про підозрілу активність")
    if alerts.empty:
        st.success("Підозрілої активності не виявлено.")
    else:
        st.dataframe(
            alerts,
            hide_index=True,
            use_container_width=True,
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
                use_container_width=True,
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
            use_container_width=True,
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
        use_container_width=True,
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
            st.plotly_chart(fig, use_container_width=True, key=key)

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
        use_container_width=True,
        column_config={
            "Останній запуск": st.column_config.DatetimeColumn(format="DD.MM HH:mm"),
            "Розмір, ГБ": st.column_config.NumberColumn(format="%.1f"),
        },
    )


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
        st.subheader("🧪 Демонстрація")
        if st.button("Симулювати brute-force атаку", use_container_width=True):
            st.session_state.attack_ticks = 6
            st.session_state.attacker = None
        if st.button("Скинути дані симуляції", use_container_width=True):
            for k in list(st.session_state.keys()):
                del st.session_state[k]
            st.rerun()
        st.caption("Дані симульовані. Для продакшну підключіть реальні джерела "
                   "(Zabbix/Prometheus, SIEM, Active Directory, Veeam тощо).")

    st.title("🛡️ Центр моніторингу та безпеки")

    run_every = f"{interval}s" if auto else None

    @st.fragment(run_every=run_every)
    def live_dashboard() -> None:
        tick_services()
        tick_auth_logs()
        tick_servers()

        st.subheader("Загальний стан критичних систем")
        render_overall_and_services()
        st.divider()

        tab_sec, tab_infra = st.tabs(["🔐 Кібербезпека та доступ", "🖥️ Інфраструктура"])
        with tab_sec:
            render_security(window_min, threshold)
        with tab_infra:
            render_infrastructure()

    live_dashboard()


if __name__ == "__main__":
    main()
