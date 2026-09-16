"""
audit.py — журнал аудиту дій користувачів (Audit Trail).

Критично для держпідприємств та енергетики: фіксує, хто й коли переглядав
документи (зокрема з обмеженим рівнем допуску), складав тести з ОП, змінював
статуси заявок, а також хто й коли звертався до AI-асистента.

Записи є незмінними (append-only) — у продакшн-версії таблицю варто додатково
захистити від UPDATE/DELETE на рівні прав БД (REVOKE UPDATE, DELETE ON audit_log).
"""

from db import get_conn, now


def log_action(user, action_type, object_type=None, object_id=None, description=None):
    """
    user: sqlite3.Row користувача (або None для системних дій) — очікує user['id'], user['full_name']
    action_type: LOGIN | VIEW_DOCUMENT | TAKE_TEST | CHANGE_STATUS | CREATE | UPDATE | DELETE | CHAT_QUERY | GENERATE_QUIZ
    """
    conn = get_conn()
    conn.execute(
        "INSERT INTO audit_log (user_id, user_name, action_type, object_type, object_id, description, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (
            user["id"] if user else None,
            user["full_name"] if user else "Система",
            action_type,
            object_type,
            object_id,
            description,
            now(),
        )
    )
    conn.commit()
    conn.close()


def get_log(limit=500, user_id=None, action_type=None, date_from=None, date_to=None):
    conn = get_conn()
    query = "SELECT * FROM audit_log WHERE 1=1"
    params = []
    if user_id:
        query += " AND user_id=?"
        params.append(user_id)
    if action_type and action_type != "Усі":
        query += " AND action_type=?"
        params.append(action_type)
    if date_from:
        query += " AND created_at>=?"
        params.append(date_from)
    if date_to:
        query += " AND created_at<=?"
        params.append(date_to)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return rows
