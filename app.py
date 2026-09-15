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
            """
        )


# ---------------------------------------------------------------------------
# Модуль 1: Кадровий кабінет та табелювання
# ---------------------------------------------------------------------------
def page_schedule(user):
    st.subheader("🗓️ Розклад змін та табелювання")
    conn = get_conn()
    rows = conn.execute(
        "SELECT work_date, shift, location FROM schedules WHERE user_id=? ORDER BY work_date",
        (user["id"],)
    ).fetchall()
    conn.close()
    if rows:
        st.dataframe(
            [{"Дата": r["work_date"], "Зміна": r["shift"], "Локація": r["location"]} for r in rows],
            use_container_width=True, hide_index=True,
        )
    else:
        st.info("Для вас поки не заплановано змін.")


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
        st.divider()

        menu = ["Кабінет співробітника", "База технічних знань"]
        if user["role"] in ("hr", "admin"):
            menu.append("HR-панель")
        if user["role"] in ("safety_admin", "admin"):
            menu.append("Адміністрування ОП")

        choice = st.radio("Розділи", menu, label_visibility="collapsed")

        st.divider()
        if st.button("Вийти", use_container_width=True):
            del st.session_state["user_id"]
            st.rerun()

    if choice == "Кабінет співробітника":
        st.title("Кабінет співробітника")
        tabs = st.tabs(["Розклад / табель", "Довідки", "Відпустка / відгул", "Інструктажі та ОП", "Сповіщення"])
        with tabs[0]:
            page_schedule(user)
        with tabs[1]:
            page_certificates(user)
        with tabs[2]:
            page_leave(user)
        with tabs[3]:
            page_safety(user)
        with tabs[4]:
            page_notifications(user)

    elif choice == "База технічних знань":
        st.title("База технічних знань")
        page_knowledge_base(user)

    elif choice == "HR-панель":
        st.title("HR-панель")
        page_hr_panel()

    elif choice == "Адміністрування ОП":
        st.title("Адміністрування охорони праці")
        page_safety_admin()


if __name__ == "__main__":
    main()
