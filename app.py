"""
app.py — "Єдине цифрове вікно співробітника" + "Інтелектуальна база технічних знань"

Запуск:
    pip install -r requirements.txt
    streamlit run app.py

Демо-облікові записи (див. seed_data.py):
    ivanenko / 1234      — диспетчер (employee)
    koval    / 1234      — інженер РЗА (employee)
    petrenko / 1234      — електромонтер (employee)
    hr_marchenko / 1234  — HR-менеджер (hr)
    op_bondar / 1234     — інженер з ОП (safety_admin)
    admin    / admin     — адміністратор системи (admin)
"""

import json
import datetime as dt

import streamlit as st
import pydeck as pdk
from streamlit_calendar import calendar as st_calendar

from db import get_conn, init_db, db_empty, now
from seed_data import seed
from kb_search import hybrid_search

st.set_page_config(page_title="Цифровий портал співробітника", page_icon="⚡", layout="wide")

# ---------------------------------------------------------------------------
# Ініціалізація БД
# ---------------------------------------------------------------------------
init_db()
if db_empty():
    seed()


# ---------------------------------------------------------------------------
# Допоміжні функції
# ---------------------------------------------------------------------------
def get_user(login, password):
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM users WHERE login=? AND password=?", (login, password)
    ).fetchone()
    conn.close()
    return row


def get_user_by_id(uid):
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    return row


ROLE_LABELS = {
    "employee": "Співробітник",
    "hr": "HR-менеджер",
    "safety_admin": "Інженер з ОП",
    "admin": "Адміністратор",
}


# ---------------------------------------------------------------------------
# Екран автентифікації (заглушка SSO/AD — див. Roadmap п.3)
# ---------------------------------------------------------------------------
def login_screen():
    st.title("⚡ Єдиний цифровий портал підприємства")
    st.caption("Демо-MVP · автентифікація тут імітує майбутній SSO через Active Directory / LDAP")

    col1, col2 = st.columns([1, 1])
    with col1:
        with st.form("login_form"):
            st.subheader("Вхід")
            login = st.text_input("Логін")
            password = st.text_input("Пароль", type="password")
            submitted = st.form_submit_button("Увійти", use_container_width=True)
            if submitted:
                user = get_user(login, password)
                if user:
                    st.session_state["user_id"] = user["id"]
                    st.rerun()
                else:
                    st.error("Невірний логін або пароль")

    with col2:
        st.subheader("Демо-облікові записи")
        st.markdown(
            """
| Логін | Пароль | Роль |
|---|---|---|
| `ivanenko` | `1234` | Диспетчер |
| `koval` | `1234` | Інженер РЗА |
| `petrenko` | `1234` | Електромонтер |
| `hr_marchenko` | `1234` | HR-менеджер |
| `op_bondar` | `1234` | Інженер з ОП |
| `admin` | `admin` | Адміністратор |
| `shevchenko` | `1234` | Новий співробітник (адаптація) |
            """
        )


# ---------------------------------------------------------------------------
# Модуль 1: Кадровий кабінет та табелювання
# ---------------------------------------------------------------------------
SHIFT_COLORS = {
    "08:00–20:00": "#2E7D32",
    "20:00–08:00": "#1565C0",
    "09:00–18:00": "#6A1B9A",
}


def page_schedule(user):
    st.subheader("🗓️ Розклад змін та табелювання")
    conn = get_conn()
    rows = conn.execute(
        "SELECT work_date, shift, location FROM schedules WHERE user_id=? ORDER BY work_date",
        (user["id"],)
    ).fetchall()
    conn.close()

    if not rows:
        st.info("Для вас поки не заплановано змін.")
        return

    events = []
    for r in rows:
        color = "#455A64"
        for prefix, c in SHIFT_COLORS.items():
            if r["shift"].startswith(prefix):
                color = c
                break
        events.append({
            "title": f"{r['shift']} · {r['location']}",
            "start": r["work_date"],
            "end": r["work_date"],
            "color": color,
            "allDay": True,
        })

    calendar_options = {
        "headerToolbar": {
            "left": "prev,next today",
            "center": "title",
            "right": "dayGridMonth,listMonth",
        },
        "initialView": "dayGridMonth",
        "height": 650,
        "locale": "uk",
        "firstDay": 1,
    }
    st_calendar(events=events, options=calendar_options, key=f"cal_{user['id']}")

    with st.expander("Показати у вигляді таблиці (для друку / експорту)"):
        st.dataframe(
            [{"Дата": r["work_date"], "Зміна": r["shift"], "Локація": r["location"]} for r in rows],
            use_container_width=True, hide_index=True,
        )


def page_certificates(user):
    st.subheader("📄 Замовлення довідок")
    with st.form("cert_form"):
        cert_type = st.selectbox("Тип довідки", ["З місця роботи", "Про доходи"])
        submitted = st.form_submit_button("Замовити довідку")
        if submitted:
            conn = get_conn()
            conn.execute(
                "INSERT INTO certificate_requests (user_id, cert_type, status, created_at) VALUES (?,?,?,?)",
                (user["id"], cert_type, "В обробці", now())
            )
            conn.commit()
            conn.close()
            st.success(f"Заявку на довідку «{cert_type}» подано.")
            st.rerun()

    conn = get_conn()
    rows = conn.execute(
        "SELECT cert_type, status, created_at FROM certificate_requests WHERE user_id=? ORDER BY id DESC",
        (user["id"],)
    ).fetchall()
    conn.close()
    st.markdown("**Мої заявки:**")
    if rows:
        st.dataframe(
            [{"Тип": r["cert_type"], "Статус": r["status"], "Дата": r["created_at"]} for r in rows],
            use_container_width=True, hide_index=True,
        )
    else:
        st.caption("Заявок ще немає.")


def page_leave(user):
    st.subheader("🏖️ Заява на відпустку / відгул")
    conn = get_conn()
    approvers = conn.execute(
        "SELECT full_name FROM users WHERE department=? AND id!=?",
        (user["department"], user["id"])
    ).fetchall()
    conn.close()
    approver_names = [a["full_name"] for a in approvers] or ["Керівник підрозділу"]

    with st.form("leave_form"):
        req_type = st.selectbox("Тип заяви", ["Відпустка", "Відгул"])
        c1, c2 = st.columns(2)
        date_from = c1.date_input("Дата з", dt.date.today())
        date_to = c2.date_input("Дата по", dt.date.today())
        approver = st.selectbox("Погоджувач (електронний підбір за підрозділом)", approver_names)
        comment = st.text_area("Коментар (необов'язково)")
        submitted = st.form_submit_button("Подати заяву")
        if submitted:
            if date_to < date_from:
                st.error("Дата «по» не може бути раніше дати «з».")
            else:
                conn = get_conn()
                conn.execute(
                    "INSERT INTO leave_requests (user_id, req_type, date_from, date_to, comment, approver, status, created_at) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (user["id"], req_type, date_from.isoformat(), date_to.isoformat(),
                     comment, approver, "На розгляді", now())
                )
                conn.commit()
                conn.close()
                st.success(f"Заяву на {req_type.lower()} подано на погодження до {approver}.")
                st.rerun()

    conn = get_conn()
    rows = conn.execute(
        "SELECT req_type, date_from, date_to, approver, status FROM leave_requests WHERE user_id=? ORDER BY id DESC",
        (user["id"],)
    ).fetchall()
    conn.close()
    st.markdown("**Мої заяви:**")
    if rows:
        st.dataframe(
            [{"Тип": r["req_type"], "З": r["date_from"], "По": r["date_to"],
              "Погоджувач": r["approver"], "Статус": r["status"]} for r in rows],
            use_container_width=True, hide_index=True,
        )
    else:
        st.caption("Заяв ще немає.")


def page_notifications(user):
    st.subheader("🔔 Корпоративний дайджест та сповіщення")
    conn = get_conn()
    rows = conn.execute("SELECT * FROM notifications ORDER BY id DESC").fetchall()
    conn.close()
    for r in rows:
        targeted = r["department"] and r["department"] != user["department"]
        if targeted:
            continue  # таргетована розсилка — показуємо лише релевантні філії/підрозділи
        icon = "🚨" if r["urgent"] else "📢"
        with st.container(border=True):
            st.markdown(f"{icon} **{r['title']}**  \n{r['body']}")
            scope = r["branch"] or r["department"] or "Усі філії"
            st.caption(f"{scope} · {r['created_at']}")


# ---------------------------------------------------------------------------
# Модуль 3 (розширення): Заявки на обладнання / ЗІЗ
# ---------------------------------------------------------------------------
EQUIPMENT_TYPES = ["Спецодяг/ЗІЗ", "Інструмент", "Несправність обладнання"]


def page_equipment_requests(user):
    st.subheader("🧰 Заявки на обладнання / ЗІЗ")
    st.caption("Замовлення спецодягу, інструменту або повідомлення про несправність обладнання.")

    with st.form("equipment_form", clear_on_submit=True):
        c1, c2 = st.columns(2)
        rtype = c1.selectbox("Тип заявки", EQUIPMENT_TYPES)
        qty = c2.number_input("Кількість", min_value=1, value=1, step=1)
        item = st.text_input("Найменування (напр. «Каска захисна», «Діелектричні рукавички розмір 10»)")
        desc = st.text_area("Опис / причина заявки (для несправності — опишіть проблему)")
        priority = st.selectbox(
            "Пріоритет", ["Звичайна", "Термінова"],
            help="Термінова — якщо несправність або відсутність ЗІЗ унеможливлює безпечне виконання робіт."
        )
        submitted = st.form_submit_button("Подати заявку", use_container_width=True)
        if submitted:
            if not item.strip():
                st.warning("Вкажіть найменування обладнання/ЗІЗ.")
            else:
                conn = get_conn()
                conn.execute(
                    "INSERT INTO equipment_requests (user_id, request_type, item_name, quantity, description, "
                    "priority, status, created_at) VALUES (?,?,?,?,?,?,?,?)",
                    (user["id"], rtype, item, int(qty), desc, priority, "Подано", now())
                )
                conn.commit()
                conn.close()
                st.success("Заявку подано.")
                st.rerun()

    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM equipment_requests WHERE user_id=? ORDER BY id DESC", (user["id"],)
    ).fetchall()
    conn.close()

    st.markdown("**Мої заявки:**")
    if not rows:
        st.caption("Заявок ще немає.")
        return
    for r in rows:
        icon = "🚨" if r["priority"] == "Термінова" else "📦"
        status_icon = {"Подано": "🕓", "На розгляді": "🔎", "Видано/Виконано": "✅", "Відхилено": "❌"}.get(r["status"], "🕓")
        with st.container(border=True):
            st.markdown(f"{icon} **{r['item_name']}** ({r['request_type']}, шт: {r['quantity']}) {status_icon} {r['status']}")
            if r["description"]:
                st.caption(r["description"])
            st.caption(f"Пріоритет: {r['priority']} · Подано: {r['created_at']}")


# ---------------------------------------------------------------------------
# Модуль 3 (розширення): Адаптація (Onboarding) для новачків
# ---------------------------------------------------------------------------
def page_onboarding(user):
    st.subheader("🧭 Програма адаптації нового співробітника")
    conn = get_conn()
    tasks = conn.execute(
        "SELECT * FROM onboarding_tasks WHERE user_id=? ORDER BY order_index", (user["id"],)
    ).fetchall()

    if not tasks:
        st.info("Для вас не сформовано персонального плану адаптації.")
        conn.close()
        return

    total = len(tasks)
    done = sum(1 for t in tasks if t["status"] == "Виконано")
    st.progress(done / total, text=f"Виконано {done} з {total} кроків")

    icons = {"Інструктаж": "🦺", "Регламент": "📄", "Ментор": "🤝", "Інше": "📌"}

    unlocked = True  # перший крок завжди доступний, далі — послідовно (ланцюжок завдань)
    for t in tasks:
        is_done = t["status"] == "Виконано"

        # авто-перевірка для завдань типу "Інструктаж": зараховано, якщо тест складено
        if not is_done and t["task_type"] == "Інструктаж" and t["related_instruction_id"]:
            passed = conn.execute(
                "SELECT 1 FROM test_results WHERE user_id=? AND instruction_id=? AND passed=1",
                (user["id"], t["related_instruction_id"])
            ).fetchone()
            if passed:
                conn.execute(
                    "UPDATE onboarding_tasks SET status='Виконано', completed_at=? WHERE id=?",
                    (now(), t["id"])
                )
                conn.commit()
                is_done = True

        label = f"{icons.get(t['task_type'], '📌')} Крок {t['order_index']}: {t['title']}"
        with st.container(border=True):
            if is_done:
                st.markdown(f"✅ ~~{label}~~")
            elif unlocked:
                st.markdown(f"**{label}**")
            else:
                st.markdown(f"🔒 {label}")
                st.caption("Доступно після виконання попереднього кроку.")
                continue

            st.write(t["description"] or "")

            if not is_done and unlocked:
                if t["task_type"] == "Інструктаж" and t["related_instruction_id"]:
                    instr = conn.execute(
                        "SELECT * FROM safety_instructions WHERE id=?", (t["related_instruction_id"],)
                    ).fetchone()
                    with st.expander("Перейти до інструктажу та тестування"):
                        st.write(instr["content"])
                        st.caption("Пройдіть тест у розділі «Інструктажі та ОП» — крок буде зараховано автоматично.")
                elif t["task_type"] == "Регламент" and t["related_document_id"]:
                    doc = conn.execute(
                        "SELECT * FROM kb_documents WHERE id=?", (t["related_document_id"],)
                    ).fetchone()
                    with st.expander(f"Відкрити документ: {doc['title']}"):
                        st.write(doc["content"])
                    if st.button("Позначити ознайомленим(ою)", key=f"onb_{t['id']}"):
                        conn.execute(
                            "UPDATE onboarding_tasks SET status='Виконано', completed_at=? WHERE id=?",
                            (now(), t["id"])
                        )
                        conn.commit()
                        st.rerun()
                elif t["task_type"] == "Ментор":
                    if t["mentor_name"]:
                        st.caption(f"Ментор: **{t['mentor_name']}**")
                    if st.button("Зустріч відбулася", key=f"onb_{t['id']}"):
                        conn.execute(
                            "UPDATE onboarding_tasks SET status='Виконано', completed_at=? WHERE id=?",
                            (now(), t["id"])
                        )
                        conn.commit()
                        st.rerun()
                else:
                    if st.button("Позначити виконаним", key=f"onb_{t['id']}"):
                        conn.execute(
                            "UPDATE onboarding_tasks SET status='Виконано', completed_at=? WHERE id=?",
                            (now(), t["id"])
                        )
                        conn.commit()
                        st.rerun()

        if not is_done:
            unlocked = False  # наступний крок заблокований, доки цей не виконано

    conn.close()
    if done == total:
        st.success("🎉 Програму адаптації повністю пройдено!")


# ---------------------------------------------------------------------------
# Модуль 1 (продовження): Техніка безпеки та охорона праці
# ---------------------------------------------------------------------------
def page_safety(user):
    st.subheader("🦺 Інструктажі з техніки безпеки та тестування")

    conn = get_conn()
    instructions = conn.execute(
        "SELECT * FROM safety_instructions WHERE required_for_role IN ('Усі', ?) ",
        (user["position"],)
    ).fetchall()

    for instr in instructions:
        last = conn.execute(
            "SELECT * FROM test_results WHERE user_id=? AND instruction_id=? ORDER BY taken_at DESC LIMIT 1",
            (user["id"], instr["id"])
        ).fetchone()

        status = "🔴 Не пройдено"
        if last:
            days_since = (dt.date.today() - dt.datetime.strptime(last["taken_at"], "%Y-%m-%d %H:%M").date()).days
            if last["passed"] and days_since <= instr["valid_days"]:
                status = f"🟢 Пройдено ({last['score']:.0f}%), дійсно ще {instr['valid_days'] - days_since} дн."
            elif last["passed"]:
                status = "🟡 Термін дії сплив — потрібно перепройти"
            else:
                status = f"🔴 Останній результат: {last['score']:.0f}% (не зараховано)"

        with st.expander(f"{instr['title']} — {status}"):
            st.caption(f"Категорія: {instr['category']}")
            st.write(instr["content"])

            questions = conn.execute(
                "SELECT * FROM quiz_questions WHERE instruction_id=?", (instr["id"],)
            ).fetchall()

            if questions:
                with st.form(f"quiz_{instr['id']}"):
                    st.markdown("**Контрольне тестування**")
                    answers = {}
                    for q in questions:
                        opts = json.loads(q["options"])
                        answers[q["id"]] = st.radio(q["question"], opts, key=f"q_{instr['id']}_{q['id']}", index=None)
                    go = st.form_submit_button("Здати тест")
                    if go:
                        if any(v is None for v in answers.values()):
                            st.warning("Дайте відповідь на всі питання.")
                        else:
                            correct = 0
                            for q in questions:
                                opts = json.loads(q["options"])
                                if opts.index(answers[q["id"]]) == q["correct_index"]:
                                    correct += 1
                            score = correct / len(questions) * 100
                            passed = score >= 70
                            conn.execute(
                                "INSERT INTO test_results (user_id, instruction_id, score, passed, taken_at) "
                                "VALUES (?,?,?,?,?)",
                                (user["id"], instr["id"], score, int(passed), now())
                            )
                            conn.commit()
                            if passed:
                                st.success(f"Тест зараховано! Результат: {score:.0f}%. "
                                           "Результат зафіксовано в системі для аудиту Держпраці.")
                            else:
                                st.error(f"Тест не зараховано ({score:.0f}%). Мінімум для зарахування — 70%.")
                            st.rerun()
            else:
                st.caption("Для цього інструктажу тестові питання ще не додано.")

    conn.close()


# ---------------------------------------------------------------------------
# Модуль 2: Інтелектуальна база технічних знань
# ---------------------------------------------------------------------------
def page_knowledge_base(user):
    st.subheader("📚 Інтелектуальна база технічних знань")
    st.caption(
        "Гібридний пошук: TF-IDF семантичний пошук у цьому демо симулює RAG-архітектуру "
        "(у проді — векторна БД Qdrant/pgvector + локальна LLM). Показані лише документи, "
        "доступні за вашим рівнем допуску."
    )

    conn = get_conn()
    all_docs = conn.execute("SELECT * FROM kb_documents").fetchall()
    conn.close()

    docs = [d for d in all_docs if d["min_access_level"] <= user["access_level"]]
    hidden_count = len(all_docs) - len(docs)

    categories = ["Усі"] + sorted({d["category"] for d in docs if d["category"]})

    c1, c2 = st.columns([3, 1])
    query = c1.text_input(
        "Пошуковий запит природною мовою",
        placeholder='напр. "Який порядок підключення генератора при аварії на підстанції 110кВ?"'
    )
    category = c2.selectbox("Категорія", categories)

    results = hybrid_search(query, docs, category=category)

    if hidden_count:
        st.caption(f"🔒 Ще {hidden_count} документ(и) приховано — недостатній рівень допуску "
                   f"(поточний: {user['access_level']}).")

    if not results:
        st.info("Нічого не знайдено. Спробуйте переформулювати запит.")
        return

    for r in results:
        d = r["doc"]
        score_label = f" · релевантність {r['score']*100:.0f}%" if r["score"] is not None else ""
        with st.container(border=True):
            st.markdown(f"**{d['title']}**  \n`{d['category']}`{score_label}")
            st.write(f"💡 {r['snippet']}")
            with st.expander("Показати повний текст документа"):
                st.write(d["content"])
            st.caption(f"Власник: {d['owner']} · Оновлено: {d['updated_at']} · "
                       f"Мін. рівень допуску: {d['min_access_level']}")


# ---------------------------------------------------------------------------
# Модуль 4: Енергетична та диспетчерська специфіка (обленерго/енергокомпанії)
# ---------------------------------------------------------------------------

STATUS_COLOR = {
    "В роботі": [46, 160, 67],           # зелений
    "Планове відключення": [230, 168, 23],  # жовтий
    "Аварія": [217, 45, 32],              # червоний
}

EVENT_TYPES = ["Аварійне відключення", "Планове відключення", "Спрацювання захисту", "Виїзд ОВБ", "Інше"]


def page_operational_log(user):
    """Журнал оперативних розпоряджень / аварійних заяв для диспетчерів та бригад ОВБ."""
    st.subheader("📒 Журнал оперативних розпоряджень та аварійних заяв")
    st.caption("Фіксація оперативних подій, відключень та виїздів оперативно-виїзних бригад (ОВБ) у реальному часі.")

    conn = get_conn()
    substations = conn.execute("SELECT * FROM substations ORDER BY name").fetchall()
    sub_options = {s["name"]: s["id"] for s in substations}

    with st.form("new_log_entry", clear_on_submit=True):
        st.markdown("**Новий запис**")
        c1, c2 = st.columns(2)
        sub_name = c1.selectbox("Підстанція / об'єкт", list(sub_options.keys()))
        event_type = c2.selectbox("Тип події", EVENT_TYPES)
        description = st.text_area("Опис оперативної події / розпорядження")
        brigade = st.text_input("Бригада ОВБ (склад/номер)", value="")
        submitted = st.form_submit_button("Зафіксувати подію", use_container_width=True)
        if submitted:
            if not description.strip():
                st.warning("Опишіть подію перед збереженням.")
            else:
                conn.execute(
                    "INSERT INTO operational_log (user_id, substation_id, event_type, description, status, brigade, created_at, resolved_at) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (user["id"], sub_options[sub_name], event_type, description, "Відкрито",
                     brigade or None, now(), None)
                )
                # аварійна подія одразу відображається на статусі підстанції на карті
                if event_type in ("Аварійне відключення", "Спрацювання захисту"):
                    conn.execute("UPDATE substations SET status='Аварія' WHERE id=?", (sub_options[sub_name],))
                elif event_type == "Планове відключення":
                    conn.execute("UPDATE substations SET status='Планове відключення' WHERE id=?", (sub_options[sub_name],))
                conn.commit()
                st.success("Подію зафіксовано в журналі.")
                st.rerun()

    st.divider()
    st.markdown("**Стрічка подій**")

    c1, c2 = st.columns(2)
    status_filter = c1.selectbox("Фільтр за статусом", ["Усі", "Відкрито", "В роботі", "Закрито"])
    branch_filter = c2.selectbox(
        "Фільтр за філією",
        ["Усі"] + sorted({s["branch"] for s in substations if s["branch"]})
    )

    query = (
        "SELECT ol.*, s.name AS sub_name, s.branch AS sub_branch, u.full_name AS author "
        "FROM operational_log ol "
        "LEFT JOIN substations s ON s.id = ol.substation_id "
        "JOIN users u ON u.id = ol.user_id "
        "ORDER BY ol.id DESC"
    )
    rows = conn.execute(query).fetchall()

    for r in rows:
        if status_filter != "Усі" and r["status"] != status_filter:
            continue
        if branch_filter != "Усі" and r["sub_branch"] != branch_filter:
            continue

        icon = {"Аварійне відключення": "🚨", "Планове відключення": "🛠️",
                "Спрацювання захисту": "⚡", "Виїзд ОВБ": "🚐", "Інше": "📝"}.get(r["event_type"], "📝")
        with st.container(border=True):
            sub_label = r["sub_name"] or "без прив'язки до об'єкта"
            st.markdown(f"{icon} **{r['event_type']}** · {sub_label}")
            st.write(r["description"])
            meta = f"Автор: {r['author']}"
            if r["brigade"]:
                meta += f" · Бригада: {r['brigade']}"
            meta += f" · {r['created_at']} · Статус: **{r['status']}**"
            st.caption(meta)

            if r["status"] != "Закрито":
                bc1, bc2 = st.columns(2)
                if r["status"] == "Відкрито" and bc1.button("Взяти в роботу", key=f"work_{r['id']}"):
                    conn.execute("UPDATE operational_log SET status='В роботі' WHERE id=?", (r["id"],))
                    conn.commit()
                    st.rerun()
                if bc2.button("Закрити подію", key=f"close_{r['id']}"):
                    conn.execute(
                        "UPDATE operational_log SET status='Закрито', resolved_at=? WHERE id=?",
                        (now(), r["id"])
                    )
                    if r["substation_id"]:
                        conn.execute("UPDATE substations SET status='В роботі' WHERE id=?", (r["substation_id"],))
                    conn.commit()
                    st.rerun()

    conn.close()


def page_substations_map(user):
    """Карта підстанцій (pydeck) з прив'язаними паспортами/схемами/інструкціями з бази знань."""
    st.subheader("🗺️ Карта підстанцій")
    st.caption(
        "Геодані об'єктів мережі (pydeck). Оберіть підстанцію нижче, щоб побачити прив'язані документи "
        "з бази знань та останні оперативні події по ній."
    )

    conn = get_conn()
    substations = conn.execute("SELECT * FROM substations ORDER BY name").fetchall()
    conn.close()
    if not substations:
        st.info("Підстанції ще не додані в систему.")
        return

    data = [
        {
            "name": s["name"],
            "branch": s["branch"],
            "voltage_class": s["voltage_class"],
            "status": s["status"],
            "lat": s["latitude"],
            "lon": s["longitude"],
            "color": STATUS_COLOR.get(s["status"], [100, 100, 100]),
        }
        for s in substations
    ]

    layer = pdk.Layer(
        "ScatterplotLayer",
        data=data,
        get_position="[lon, lat]",
        get_fill_color="color",
        get_radius=350,
        radius_min_pixels=8,
        radius_max_pixels=40,
        pickable=True,
        stroked=True,
        get_line_color=[255, 255, 255],
        line_width_min_pixels=1,
    )
    view_state = pdk.ViewState(
        latitude=sum(d["lat"] for d in data) / len(data),
        longitude=sum(d["lon"] for d in data) / len(data),
        zoom=10, pitch=0,
    )
    deck = pdk.Deck(
        layers=[layer],
        initial_view_state=view_state,
        map_style=None,  # без стороннього API-ключа для мап; використовується вбудований стиль
        tooltip={"text": "{name}\n{voltage_class} · {status}\nФілія: {branch}"},
    )
    st.pydeck_chart(deck, use_container_width=True)

    legend_cols = st.columns(len(STATUS_COLOR))
    for col, (label, color) in zip(legend_cols, STATUS_COLOR.items()):
        col.markdown(
            f"<span style='color:rgb{tuple(color)}'>●</span> {label}", unsafe_allow_html=True
        )

    st.divider()
    sub_names = [s["name"] for s in substations]
    selected_name = st.selectbox("Обрати підстанцію для деталей", sub_names)
    selected = next(s for s in substations if s["name"] == selected_name)

    conn = get_conn()
    docs = conn.execute(
        "SELECT * FROM kb_documents WHERE substation_id=? AND min_access_level<=?",
        (selected["id"], user["access_level"])
    ).fetchall()
    events = conn.execute(
        "SELECT * FROM operational_log WHERE substation_id=? ORDER BY id DESC LIMIT 5",
        (selected["id"],)
    ).fetchall()
    conn.close()

    c1, c2 = st.columns(2)
    with c1:
        st.markdown(f"**📄 Документи бази знань для «{selected_name}»**")
        if docs:
            for d in docs:
                with st.expander(f"{d['title']} ({d['category']})"):
                    st.write(d["content"])
        else:
            st.caption("До цього об'єкта ще не прив'язано документів (або немає доступу за рівнем допуску).")

    with c2:
        st.markdown(f"**📒 Останні оперативні події**")
        if events:
            for e in events:
                st.write(f"• {e['event_type']} — {e['status']} ({e['created_at']})")
        else:
            st.caption("Подій по цьому об'єкту ще не зафіксовано.")


# ---------------------------------------------------------------------------
# HR-панель (для ролі hr / admin)
# ---------------------------------------------------------------------------
def page_hr_panel():
    st.subheader("🗂️ HR-панель: заявки співробітників")
    conn = get_conn()

    st.markdown("**Заяви на відпустку / відгул**")
    leaves = conn.execute(
        "SELECT lr.id, u.full_name, lr.req_type, lr.date_from, lr.date_to, lr.status "
        "FROM leave_requests lr JOIN users u ON u.id=lr.user_id ORDER BY lr.id DESC"
    ).fetchall()
    for lv in leaves:
        c1, c2, c3, c4 = st.columns([3, 2, 2, 2])
        c1.write(f"**{lv['full_name']}** — {lv['req_type']}")
        c2.write(f"{lv['date_from']} → {lv['date_to']}")
        c3.write(lv["status"])
        if lv["status"] == "На розгляді":
            if c4.button("Погодити", key=f"ok_{lv['id']}"):
                conn.execute("UPDATE leave_requests SET status='Погоджено' WHERE id=?", (lv["id"],))
                conn.commit()
                st.rerun()
            if c4.button("Відхилити", key=f"no_{lv['id']}"):
                conn.execute("UPDATE leave_requests SET status='Відхилено' WHERE id=?", (lv["id"],))
                conn.commit()
                st.rerun()

    st.divider()
    st.markdown("**Заявки на довідки**")
    certs = conn.execute(
        "SELECT cr.id, u.full_name, cr.cert_type, cr.status FROM certificate_requests cr "
        "JOIN users u ON u.id=cr.user_id ORDER BY cr.id DESC"
    ).fetchall()
    for cr in certs:
        c1, c2, c3 = st.columns([3, 2, 2])
        c1.write(f"**{cr['full_name']}** — {cr['cert_type']}")
        c2.write(cr["status"])
        if cr["status"] != "Видано":
            if c3.button("Позначити виданою", key=f"cert_{cr['id']}"):
                conn.execute("UPDATE certificate_requests SET status='Видано' WHERE id=?", (cr["id"],))
                conn.commit()
                st.rerun()

    st.divider()
    st.markdown("**Заявки на обладнання / ЗІЗ**")
    eqs = conn.execute(
        "SELECT er.*, u.full_name FROM equipment_requests er JOIN users u ON u.id=er.user_id "
        "ORDER BY (er.priority='Термінова') DESC, er.id DESC"
    ).fetchall()
    for eq in eqs:
        c1, c2, c3, c4 = st.columns([3, 2, 2, 2])
        pr = "🚨 " if eq["priority"] == "Термінова" else ""
        c1.write(f"{pr}**{eq['full_name']}** — {eq['item_name']} ({eq['request_type']}, {eq['quantity']} шт)")
        c2.write(eq["status"])
        c3.write(eq["priority"])
        if eq["status"] not in ("Видано/Виконано", "Відхилено"):
            if c4.button("Видано/Виконано", key=f"eq_ok_{eq['id']}"):
                conn.execute("UPDATE equipment_requests SET status='Видано/Виконано', resolved_at=? WHERE id=?",
                             (now(), eq["id"]))
                conn.commit()
                st.rerun()
            if c4.button("Відхилити", key=f"eq_no_{eq['id']}"):
                conn.execute("UPDATE equipment_requests SET status='Відхилено', resolved_at=? WHERE id=?",
                             (now(), eq["id"]))
                conn.commit()
                st.rerun()
    conn.close()


# ---------------------------------------------------------------------------
# Панель ОП: зведення по тестуванню всього персоналу (для safety_admin / admin)
# ---------------------------------------------------------------------------
def page_safety_admin():
    st.subheader("📋 Зведення проходження інструктажів (для аудиту Держпраці)")
    conn = get_conn()
    rows = conn.execute(
        "SELECT u.full_name, u.position, u.branch, si.title, tr.score, tr.passed, tr.taken_at "
        "FROM test_results tr JOIN users u ON u.id=tr.user_id "
        "JOIN safety_instructions si ON si.id=tr.instruction_id ORDER BY tr.taken_at DESC"
    ).fetchall()
    conn.close()
    if rows:
        st.dataframe(
            [{"Співробітник": r["full_name"], "Посада": r["position"], "Філія": r["branch"],
              "Інструктаж": r["title"], "Результат, %": r["score"],
              "Зараховано": "✅" if r["passed"] else "❌", "Дата": r["taken_at"]} for r in rows],
            use_container_width=True, hide_index=True,
        )
    else:
        st.info("Жоден співробітник ще не проходив тестування.")

    st.divider()
    st.markdown("**Додати нове сповіщення / попередження**")
    with st.form("new_notif"):
        title = st.text_input("Заголовок")
        body = st.text_area("Текст")
        branch = st.text_input("Філія (порожньо = усі)")
        urgent = st.checkbox("Термінове (аварійне)")
        if st.form_submit_button("Опублікувати"):
            conn = get_conn()
            conn.execute(
                "INSERT INTO notifications (title, body, department, branch, urgent, created_at) "
                "VALUES (?,?,?,?,?,?)",
                (title, body, None, branch or None, int(urgent), now())
            )
            conn.commit()
            conn.close()
            st.success("Сповіщення опубліковано.")
            st.rerun()


# ---------------------------------------------------------------------------
# Модуль 5: Управління системою (розширена роль Адміністратора)
# ---------------------------------------------------------------------------
# Адміністратор бачить і може керувати всім, що недоступно з UI іншим ролям:
# користувачами, розкладами будь-кого, базою знань, підстанціями та планами
# адаптації — тобто закриває прогалини, яких не вистачало окремим ролям.

ONBOARDING_TASK_TYPES = ["Інструктаж", "Регламент", "Ментор", "Інше"]


def page_admin_overview():
    st.subheader("📊 Загальний огляд системи")
    conn = get_conn()

    n_users = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    n_open_leave = conn.execute("SELECT COUNT(*) c FROM leave_requests WHERE status='На розгляді'").fetchone()["c"]
    n_open_cert = conn.execute("SELECT COUNT(*) c FROM certificate_requests WHERE status!='Видано'").fetchone()["c"]
    n_open_equip = conn.execute(
        "SELECT COUNT(*) c FROM equipment_requests WHERE status NOT IN ('Видано/Виконано','Відхилено')"
    ).fetchone()["c"]
    n_open_incidents = conn.execute("SELECT COUNT(*) c FROM operational_log WHERE status!='Закрито'").fetchone()["c"]
    n_docs = conn.execute("SELECT COUNT(*) c FROM kb_documents").fetchone()["c"]
    n_subs = conn.execute("SELECT COUNT(*) c FROM substations").fetchone()["c"]
    n_onboarding = conn.execute(
        "SELECT COUNT(DISTINCT user_id) c FROM onboarding_tasks WHERE user_id IN "
        "(SELECT id FROM onboarding_tasks GROUP BY user_id HAVING SUM(CASE WHEN status!='Виконано' THEN 1 ELSE 0 END) > 0)"
    ).fetchone()["c"]

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Співробітників", n_users)
    c2.metric("Відкриті заяви на відпустку", n_open_leave)
    c3.metric("Довідки в обробці", n_open_cert)
    c4.metric("Заявки на ЗІЗ в роботі", n_open_equip)

    c5, c6, c7, c8 = st.columns(4)
    c5.metric("Незакриті оперативні події", n_open_incidents, delta=None,
              delta_color="inverse" if n_open_incidents else "normal")
    c6.metric("Документів у базі знань", n_docs)
    c7.metric("Підстанцій у системі", n_subs)
    c8.metric("Новачків в адаптації", n_onboarding)

    st.divider()
    st.markdown("**🚨 Активні аварійні/незакриті оперативні події**")
    incidents = conn.execute(
        "SELECT ol.*, s.name AS sub_name FROM operational_log ol LEFT JOIN substations s ON s.id=ol.substation_id "
        "WHERE ol.status!='Закрито' ORDER BY ol.id DESC"
    ).fetchall()
    if incidents:
        st.dataframe(
            [{"Подія": r["event_type"], "Об'єкт": r["sub_name"] or "—", "Статус": r["status"],
              "Створено": r["created_at"]} for r in incidents],
            use_container_width=True, hide_index=True,
        )
    else:
        st.caption("Немає незакритих подій.")
    conn.close()


def page_admin_users():
    st.subheader("👥 Керування користувачами")
    conn = get_conn()
    users = conn.execute("SELECT * FROM users ORDER BY full_name").fetchall()

    st.dataframe(
        [{"ПІБ": u["full_name"], "Логін": u["login"], "Посада": u["position"], "Підрозділ": u["department"],
          "Філія": u["branch"], "Роль": ROLE_LABELS.get(u["role"], u["role"]),
          "Рівень допуску": u["access_level"], "Новачок": "✅" if u["is_new_hire"] else "",
          "Дата прийому": u["hire_date"]} for u in users],
        use_container_width=True, hide_index=True,
    )

    st.divider()
    with st.expander("➕ Додати нового співробітника"):
        with st.form("add_user_form", clear_on_submit=True):
            c1, c2 = st.columns(2)
            login = c1.text_input("Логін")
            password = c2.text_input("Тимчасовий пароль", value="1234")
            full_name = st.text_input("ПІБ")
            c3, c4 = st.columns(2)
            position = c3.text_input("Посада")
            department = c4.text_input("Підрозділ")
            c5, c6 = st.columns(2)
            branch = c5.text_input("Філія")
            role = c6.selectbox("Роль", list(ROLE_LABELS.keys()), format_func=lambda r: ROLE_LABELS[r])
            c7, c8 = st.columns(2)
            access_level = c7.number_input("Рівень допуску", min_value=1, max_value=5, value=1)
            hire_date = c8.date_input("Дата прийому на роботу", dt.date.today())
            is_new_hire = st.checkbox("Позначити як новачка (активувати модуль адаптації)")
            submitted = st.form_submit_button("Створити користувача", use_container_width=True)
            if submitted:
                if not login.strip() or not full_name.strip():
                    st.warning("Заповніть щонайменше логін та ПІБ.")
                elif conn.execute("SELECT 1 FROM users WHERE login=?", (login,)).fetchone():
                    st.error("Користувач з таким логіном вже існує.")
                else:
                    conn.execute(
                        "INSERT INTO users (login,password,full_name,position,department,branch,role,"
                        "access_level,hire_date,is_new_hire) VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (login, password, full_name, position, department, branch, role,
                         int(access_level), hire_date.isoformat(), int(is_new_hire))
                    )
                    conn.commit()
                    st.success(f"Користувача «{full_name}» створено.")
                    st.rerun()

    st.divider()
    st.markdown("**✏️ Редагувати / деактивувати доступ співробітника**")
    names = {u["full_name"]: u["id"] for u in users}
    selected_name = st.selectbox("Оберіть співробітника", list(names.keys()), key="edit_user_select")
    sel = conn.execute("SELECT * FROM users WHERE id=?", (names[selected_name],)).fetchone()

    with st.form("edit_user_form"):
        c1, c2 = st.columns(2)
        position = c1.text_input("Посада", value=sel["position"] or "")
        department = c2.text_input("Підрозділ", value=sel["department"] or "")
        c3, c4 = st.columns(2)
        branch = c3.text_input("Філія", value=sel["branch"] or "")
        role = c4.selectbox("Роль", list(ROLE_LABELS.keys()),
                             index=list(ROLE_LABELS.keys()).index(sel["role"]),
                             format_func=lambda r: ROLE_LABELS[r])
        c5, c6 = st.columns(2)
        access_level = c5.number_input("Рівень допуску", min_value=1, max_value=5, value=sel["access_level"])
        is_new_hire = c6.checkbox("Новачок (модуль адаптації активний)", value=bool(sel["is_new_hire"]))
        new_password = st.text_input("Новий пароль (залиште порожнім, щоб не змінювати)")
        save = st.form_submit_button("Зберегти зміни", use_container_width=True)
        if save:
            conn.execute(
                "UPDATE users SET position=?, department=?, branch=?, role=?, access_level=?, is_new_hire=? "
                "WHERE id=?",
                (position, department, branch, role, int(access_level), int(is_new_hire), sel["id"])
            )
            if new_password.strip():
                conn.execute("UPDATE users SET password=? WHERE id=?", (new_password.strip(), sel["id"]))
            conn.commit()
            st.success("Зміни збережено.")
            st.rerun()
    conn.close()


def page_admin_schedules():
    st.subheader("🗓️ Розклади змін — перегляд і редагування для будь-кого")
    conn = get_conn()
    users = conn.execute("SELECT * FROM users ORDER BY full_name").fetchall()
    names = {u["full_name"]: u["id"] for u in users}
    selected_name = st.selectbox("Оберіть співробітника", list(names.keys()), key="sched_user_select")
    target_id = names[selected_name]

    rows = conn.execute(
        "SELECT * FROM schedules WHERE user_id=? ORDER BY work_date", (target_id,)
    ).fetchall()

    events = [{
        "title": f"{r['shift']} · {r['location']}", "start": r["work_date"], "end": r["work_date"],
        "allDay": True,
    } for r in rows]
    st_calendar(events=events, options={
        "headerToolbar": {"left": "prev,next today", "center": "title", "right": "dayGridMonth,listMonth"},
        "initialView": "dayGridMonth", "height": 550, "locale": "uk", "firstDay": 1,
    }, key=f"admin_cal_{target_id}")

    st.markdown("**➕ Додати зміну**")
    with st.form("add_shift_form", clear_on_submit=True):
        c1, c2, c3 = st.columns(3)
        work_date = c1.date_input("Дата", dt.date.today())
        shift = c2.text_input("Зміна (напр. «08:00–20:00»)")
        location = c3.text_input("Локація")
        if st.form_submit_button("Додати зміну"):
            if not shift.strip():
                st.warning("Вкажіть час зміни.")
            else:
                conn.execute(
                    "INSERT INTO schedules (user_id, work_date, shift, location) VALUES (?,?,?,?)",
                    (target_id, work_date.isoformat(), shift, location)
                )
                conn.commit()
                st.success("Зміну додано.")
                st.rerun()
    conn.close()


def page_admin_kb():
    st.subheader("📚 Керування базою технічних знань")
    conn = get_conn()
    substations = conn.execute("SELECT id, name FROM substations ORDER BY name").fetchall()
    sub_options = {"— не прив'язано —": None}
    sub_options.update({s["name"]: s["id"] for s in substations})

    docs = conn.execute("SELECT * FROM kb_documents ORDER BY title").fetchall()
    st.markdown(f"**Усього документів: {len(docs)}**")
    for d in docs:
        with st.expander(f"{d['title']} ({d['category']})"):
            with st.form(f"edit_doc_{d['id']}"):
                title = st.text_input("Назва", value=d["title"])
                c1, c2 = st.columns(2)
                category = c1.text_input("Категорія", value=d["category"] or "")
                tags = c2.text_input("Теги (через кому)", value=d["tags"] or "")
                content = st.text_area("Зміст", value=d["content"], height=150)
                c3, c4, c5 = st.columns(3)
                min_access = c3.number_input("Мін. рівень допуску", min_value=1, max_value=5,
                                              value=d["min_access_level"])
                owner = c4.text_input("Власник", value=d["owner"] or "")
                cur_sub_name = next((n for n, i in sub_options.items() if i == d["substation_id"]),
                                     "— не прив'язано —")
                sub_name = c5.selectbox("Підстанція", list(sub_options.keys()),
                                         index=list(sub_options.keys()).index(cur_sub_name),
                                         key=f"sub_sel_{d['id']}")
                if st.form_submit_button("Зберегти"):
                    conn.execute(
                        "UPDATE kb_documents SET title=?, category=?, tags=?, content=?, min_access_level=?, "
                        "owner=?, substation_id=?, updated_at=? WHERE id=?",
                        (title, category, tags, content, int(min_access), owner,
                         sub_options[sub_name], now(), d["id"])
                    )
                    conn.commit()
                    st.success("Документ оновлено.")
                    st.rerun()

    st.divider()
    with st.expander("➕ Додати новий документ"):
        with st.form("add_doc_form", clear_on_submit=True):
            title = st.text_input("Назва документа")
            c1, c2 = st.columns(2)
            category = c1.text_input("Категорія (Регламент/Схема/Паспорт обладнання/Інструкція/НПАОП)")
            tags = c2.text_input("Теги (через кому)")
            content = st.text_area("Зміст документа", height=150)
            c3, c4, c5 = st.columns(3)
            min_access = c3.number_input("Мін. рівень допуску", min_value=1, max_value=5, value=1)
            owner = c4.text_input("Власник (підрозділ)")
            sub_name = c5.selectbox("Прив'язати до підстанції", list(sub_options.keys()), key="new_doc_sub")
            if st.form_submit_button("Додати документ", use_container_width=True):
                if not title.strip() or not content.strip():
                    st.warning("Вкажіть назву та зміст документа.")
                else:
                    conn.execute(
                        "INSERT INTO kb_documents (title, category, tags, content, min_access_level, owner, "
                        "updated_at, substation_id) VALUES (?,?,?,?,?,?,?,?)",
                        (title, category, tags, content, int(min_access), owner, now(), sub_options[sub_name])
                    )
                    conn.commit()
                    st.success("Документ додано до бази знань.")
                    st.rerun()
    conn.close()


def page_admin_substations():
    st.subheader("⚡ Керування підстанціями")
    conn = get_conn()
    substations = conn.execute("SELECT * FROM substations ORDER BY name").fetchall()

    for s in substations:
        with st.container(border=True):
            c1, c2, c3, c4 = st.columns([3, 2, 2, 2])
            c1.markdown(f"**{s['name']}**")
            c2.caption(f"{s['branch']} · {s['voltage_class']}")
            new_status = c3.selectbox(
                "Статус", list(STATUS_COLOR.keys()),
                index=list(STATUS_COLOR.keys()).index(s["status"]) if s["status"] in STATUS_COLOR else 0,
                key=f"sub_status_{s['id']}", label_visibility="collapsed"
            )
            if c4.button("Оновити статус", key=f"sub_upd_{s['id']}"):
                conn.execute("UPDATE substations SET status=? WHERE id=?", (new_status, s["id"]))
                conn.commit()
                st.success(f"Статус «{s['name']}» оновлено.")
                st.rerun()

    st.divider()
    with st.expander("➕ Додати нову підстанцію"):
        with st.form("add_sub_form", clear_on_submit=True):
            name = st.text_input("Назва підстанції")
            c1, c2 = st.columns(2)
            branch = c1.text_input("Філія")
            voltage_class = c2.text_input("Клас напруги (напр. «110/10 кВ»)")
            c3, c4 = st.columns(2)
            lat = c3.number_input("Широта", value=48.4647, format="%.4f")
            lon = c4.number_input("Довгота", value=35.0462, format="%.4f")
            status = st.selectbox("Початковий статус", list(STATUS_COLOR.keys()))
            if st.form_submit_button("Додати підстанцію", use_container_width=True):
                if not name.strip():
                    st.warning("Вкажіть назву підстанції.")
                else:
                    conn.execute(
                        "INSERT INTO substations (name, branch, voltage_class, latitude, longitude, status) "
                        "VALUES (?,?,?,?,?,?)",
                        (name, branch, voltage_class, lat, lon, status)
                    )
                    conn.commit()
                    st.success("Підстанцію додано.")
                    st.rerun()
    conn.close()


def page_admin_onboarding():
    st.subheader("🧭 Плани адаптації новачків")
    conn = get_conn()

    progress_rows = conn.execute(
        "SELECT u.id, u.full_name, u.position, u.branch, "
        "COUNT(t.id) AS total, SUM(CASE WHEN t.status='Виконано' THEN 1 ELSE 0 END) AS done "
        "FROM onboarding_tasks t JOIN users u ON u.id=t.user_id GROUP BY u.id ORDER BY u.full_name"
    ).fetchall()

    if progress_rows:
        st.markdown("**Прогрес по всіх активних планах адаптації**")
        for r in progress_rows:
            pct = (r["done"] / r["total"]) if r["total"] else 0
            st.write(f"**{r['full_name']}** — {r['position']} ({r['branch']})")
            st.progress(pct, text=f"{r['done']} / {r['total']} кроків виконано")
    else:
        st.caption("Наразі жодного плану адаптації не створено.")

    st.divider()
    st.markdown("**➕ Створити / доповнити план адаптації**")

    users = conn.execute("SELECT * FROM users ORDER BY full_name").fetchall()
    names = {u["full_name"]: u["id"] for u in users}
    selected_name = st.selectbox("Співробітник", list(names.keys()), key="onb_user_select")
    target = conn.execute("SELECT * FROM users WHERE id=?", (names[selected_name],)).fetchone()

    existing = conn.execute(
        "SELECT * FROM onboarding_tasks WHERE user_id=? ORDER BY order_index", (target["id"],)
    ).fetchall()
    if existing:
        st.markdown("Поточні кроки:")
        for t in existing:
            mark = "✅" if t["status"] == "Виконано" else "⬜"
            st.write(f"{mark} Крок {t['order_index']}: {t['title']} ({t['task_type']})")

    instructions = conn.execute("SELECT id, title FROM safety_instructions ORDER BY title").fetchall()
    documents = conn.execute("SELECT id, title FROM kb_documents ORDER BY title").fetchall()

    with st.form("add_onboarding_step", clear_on_submit=True):
        task_type = st.selectbox("Тип кроку", ONBOARDING_TASK_TYPES)
        title = st.text_input("Назва кроку")
        description = st.text_area("Опис")
        instr_choice = None
        doc_choice = None
        mentor_name = ""
        if task_type == "Інструктаж" and instructions:
            instr_map = {i["title"]: i["id"] for i in instructions}
            instr_choice = st.selectbox("Пов'язаний інструктаж", list(instr_map.keys()))
        elif task_type == "Регламент" and documents:
            doc_map = {d["title"]: d["id"] for d in documents}
            doc_choice = st.selectbox("Пов'язаний документ", list(doc_map.keys()))
        elif task_type == "Ментор":
            mentor_name = st.text_input("ПІБ ментора")

        submitted = st.form_submit_button("Додати крок до плану", use_container_width=True)
        if submitted:
            if not title.strip():
                st.warning("Вкажіть назву кроку.")
            else:
                next_order = (max((t["order_index"] for t in existing), default=0)) + 1
                related_instr = instr_map[instr_choice] if task_type == "Інструктаж" and instructions else None
                related_doc = doc_map[doc_choice] if task_type == "Регламент" and documents else None
                conn.execute(
                    "INSERT INTO onboarding_tasks (user_id, order_index, task_type, title, description, "
                    "related_instruction_id, related_document_id, mentor_name, status) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (target["id"], next_order, task_type, title, description,
                     related_instr, related_doc, mentor_name or None, "Не виконано")
                )
                conn.execute("UPDATE users SET is_new_hire=1 WHERE id=?", (target["id"],))
                conn.commit()
                st.success(f"Крок додано до плану адаптації «{selected_name}».")
                st.rerun()
    conn.close()


def page_system_admin():
    tabs = st.tabs(["Огляд", "Користувачі", "Розклади", "База знань", "Підстанції", "Адаптація новачків"])
    with tabs[0]:
        page_admin_overview()
    with tabs[1]:
        page_admin_users()
    with tabs[2]:
        page_admin_schedules()
    with tabs[3]:
        page_admin_kb()
    with tabs[4]:
        page_admin_substations()
    with tabs[5]:
        page_admin_onboarding()


# ---------------------------------------------------------------------------
# Основний layout
# ---------------------------------------------------------------------------
def main():
    if "user_id" not in st.session_state:
        login_screen()
        return

    user = get_user_by_id(st.session_state["user_id"])
    if user is None:
        del st.session_state["user_id"]
        st.rerun()
        return

    with st.sidebar:
        st.markdown(f"### 👤 {user['full_name']}")
        st.caption(f"{user['position']} · {ROLE_LABELS.get(user['role'], user['role'])}")
        st.caption(f"{user['branch']}")
        if user["is_new_hire"]:
            st.info("🧭 Новий співробітник — активна програма адаптації")
        st.divider()

        menu = ["Кабінет співробітника", "База технічних знань",
                "Журнал оперативних подій", "Карта підстанцій"]
        if user["role"] in ("hr", "admin"):
            menu.append("HR-панель")
        if user["role"] in ("safety_admin", "admin"):
            menu.append("Адміністрування ОП")
        if user["role"] == "admin":
            menu.append("🛠️ Управління системою")

        choice = st.radio("Розділи", menu, label_visibility="collapsed")

        st.divider()
        if st.button("Вийти", use_container_width=True):
            del st.session_state["user_id"]
            st.rerun()

    if choice == "Кабінет співробітника":
        st.title("Кабінет співробітника")
        tab_names = ["Розклад / табель", "Довідки", "Відпустка / відгул",
                     "Інструктажі та ОП", "Заявки на ЗІЗ/обладнання", "Сповіщення"]
        if user["is_new_hire"]:
            tab_names.append("🧭 Адаптація")
        tabs = st.tabs(tab_names)
        with tabs[0]:
            page_schedule(user)
        with tabs[1]:
            page_certificates(user)
        with tabs[2]:
            page_leave(user)
        with tabs[3]:
            page_safety(user)
        with tabs[4]:
            page_equipment_requests(user)
        with tabs[5]:
            page_notifications(user)
        if user["is_new_hire"]:
            with tabs[6]:
                page_onboarding(user)

    elif choice == "База технічних знань":
        st.title("База технічних знань")
        page_knowledge_base(user)

    elif choice == "Журнал оперативних подій":
        st.title("Журнал оперативних розпоряджень")
        page_operational_log(user)

    elif choice == "Карта підстанцій":
        st.title("Карта підстанцій")
        page_substations_map(user)

    elif choice == "HR-панель":
        st.title("HR-панель")
        page_hr_panel()

    elif choice == "Адміністрування ОП":
        st.title("Адміністрування охорони праці")
        page_safety_admin()

    elif choice == "🛠️ Управління системою":
        st.title("Управління системою")
        st.caption("Повний адміністративний доступ: користувачі, розклади, база знань, підстанції, адаптація.")
        page_system_admin()


if __name__ == "__main__":
    main()
