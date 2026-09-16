"""
auth.py — автентифікація користувачів.

За замовчуванням працює демо-режим (логін/пароль звіряються з таблицею
`users` у SQLite) — так застосунок можна одразу запустити без жодної
корпоративної інфраструктури.

Якщо задано змінну середовища LDAP_SERVER, застосунок переходить у режим
реального SSO через Active Directory / LDAP (бібліотека `ldap3`):
  1. Обліковий запис аутентифікується прямим BIND до контролера домену.
  2. Після успішного bind профіль співробітника (посада, підрозділ, філія,
     роль, рівень допуску) все одно береться з локальної таблиці `users` —
     у продакшн-версії ці атрибути зазвичай синхронізуються з AD/HR-системою
     нічним job'ом (див. Roadmap, інтеграція з ERP/HR), а не редагуються
     вручну після кожного логіну.
  3. Якщо в LDAP користувача не знайдено серед відомих `users.login` —
     показуємо зрозумілу помилку замість мовчазного провалу.

Змінні середовища:
    LDAP_SERVER      напр. ldap://dc01.company.local
    LDAP_BASE_DN      напр. dc=company,dc=local
    LDAP_DOMAIN       напр. COMPANY  (для формату DOMAIN\\login)
    LDAP_USE_SSL      "1" щоб використовувати ldaps://
"""

import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from db import get_conn

LDAP_SERVER = os.environ.get("LDAP_SERVER", "").strip()
LDAP_BASE_DN = os.environ.get("LDAP_BASE_DN", "").strip()
LDAP_DOMAIN = os.environ.get("LDAP_DOMAIN", "").strip()
LDAP_USE_SSL = os.environ.get("LDAP_USE_SSL", "0") == "1"


def is_ldap_configured():
    return bool(LDAP_SERVER)


def _get_local_profile(login):
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE login=?", (login,)).fetchone()
    conn.close()
    return row


def _authenticate_ldap(login, password):
    """Повертає (user_row, error_message). Реальний BIND до Active Directory/LDAP."""
    try:
        from ldap3 import Server, Connection, ALL, NTLM
    except ImportError:
        return None, "Бібліотеку 'ldap3' не встановлено (pip install ldap3)."

    try:
        server = Server(LDAP_SERVER, get_info=ALL, use_ssl=LDAP_USE_SSL)
        user_dn = f"{LDAP_DOMAIN}\\{login}" if LDAP_DOMAIN else login
        conn = Connection(server, user=user_dn, password=password, authentication=NTLM, auto_bind=True)
    except Exception as e:
        return None, f"Не вдалося автентифікуватися в домені: {e}"

    conn.unbind()

    profile = _get_local_profile(login)
    if profile is None:
        return None, (
            "Пароль доменний коректний, але профіль співробітника не знайдено в системі. "
            "Зверніться до HR/адміністратора для створення профілю."
        )
    return profile, None


def _authenticate_demo(login, password):
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE login=? AND password=?", (login, password)).fetchone()
    conn.close()
    if row is None:
        return None, "Невірний логін або пароль."
    return row, None


def authenticate(login, password):
    """Єдина точка входу для UI. Повертає (user_row_or_None, error_message_or_None)."""
    if is_ldap_configured():
        return _authenticate_ldap(login, password)
    return _authenticate_demo(login, password)


def auth_mode_label():
    return "🔐 Active Directory / LDAP (production)" if is_ldap_configured() else "🧪 Демо-режим (локальна БД)"
