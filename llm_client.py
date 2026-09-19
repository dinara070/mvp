"""
llm_client.py — уніфікований клієнт для звернень до LLM.

Підтримує:
  - OpenAI API (хмарний) — за замовчуванням
  - Локальну Ollama (Llama/Mistral тощо) — Ollama надає OpenAI-сумісний
    ендпоінт `/v1`, тому достатньо вказати OPENAI_BASE_URL=http://localhost:11434/v1

Якщо жодного з них не налаштовано (немає ключа/хосту, чи бібліотека `openai`
не встановлена, чи виникла мережева помилка) — усі функції кидають
LLMUnavailableError, і виклики в rag_chat.py / quiz_generator.py
прозоро переходять на детерміністичний fallback без LLM. Це дозволяє
застосунку працювати "з коробки" навіть без доступу до жодної LLM.
"""

import os
import json
import logging
import time
from functools import lru_cache
from typing import Any

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger(__name__)

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "").strip()
OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").strip()
OPENAI_CHAT_MODEL = os.environ.get("OPENAI_CHAT_MODEL", "gpt-4o-mini").strip()

# Таймаут і кількість повторів для мережевих запитів (можна перевизначити через env)
OPENAI_TIMEOUT = float(os.environ.get("OPENAI_TIMEOUT", "30"))
OPENAI_MAX_RETRIES = int(os.environ.get("OPENAI_MAX_RETRIES", "2"))
_RETRY_BACKOFF_BASE = 1.5  # секунди, зростає експоненційно між спробами


class LLMUnavailableError(RuntimeError):
    """LLM не налаштовано або звернення до нього завершилось помилкою."""


def is_llm_configured() -> bool:
    """Ollama теж використовується через OpenAI-сумісний base_url — тому головна ознака
    доступності: або є ключ (хмарний OpenAI-сумісний провайдер), або base_url явно
    переналаштовано на локальний сервер (Ollama зазвичай не потребує ключа)."""
    return bool(OPENAI_API_KEY) or "localhost" in OPENAI_BASE_URL or "127.0.0.1" in OPENAI_BASE_URL


@lru_cache(maxsize=1)
def _get_client():
    """Клієнт створюється один раз і кешується (уникаємо повторного відкриття
    HTTP-з'єднань на кожен виклик)."""
    try:
        from openai import OpenAI
    except ImportError as e:
        raise LLMUnavailableError("Пакет 'openai' не встановлено (pip install openai).") from e

    if not is_llm_configured():
        raise LLMUnavailableError(
            "LLM не налаштовано: встановіть OPENAI_API_KEY (хмара) або OPENAI_BASE_URL "
            "на локальний Ollama-сервер, напр. http://localhost:11434/v1."
        )
    # Ollama не потребує реального ключа, але бібліотека openai вимагає непорожній рядок
    api_key = OPENAI_API_KEY or "ollama-local"
    return OpenAI(api_key=api_key, base_url=OPENAI_BASE_URL, timeout=OPENAI_TIMEOUT)


def chat_completion(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = 700,
    temperature: float = 0.2,
    json_mode: bool = False,
) -> str:
    """Повертає текст відповіді LLM. Кидає LLMUnavailableError при будь-якій проблемі —
    виклики мають ловити цей виняток і переходити на fallback без LLM.

    Робить до OPENAI_MAX_RETRIES повторних спроб з експоненційною затримкою
    при мережевих/тимчасових помилках, перш ніж здатись.
    """
    client = _get_client()
    kwargs: dict[str, Any] = {}
    if json_mode:
        kwargs["response_format"] = {"type": "json_object"}

    last_error: Exception | None = None
    for attempt in range(OPENAI_MAX_RETRIES + 1):
        try:
            response = client.chat.completions.create(
                model=OPENAI_CHAT_MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                max_tokens=max_tokens,
                temperature=temperature,
                **kwargs,
            )
            content = response.choices[0].message.content
            if not content:
                raise LLMUnavailableError("LLM повернула порожню відповідь.")
            return content
        except Exception as e:  # мережеві помилки, помилки провайдера, неправильна модель тощо
            last_error = e
            if attempt < OPENAI_MAX_RETRIES:
                delay = _RETRY_BACKOFF_BASE * (2 ** attempt)
                logger.warning(
                    "Спроба звернення до LLM %d/%d невдала (%s), повтор через %.1fс",
                    attempt + 1, OPENAI_MAX_RETRIES + 1, e, delay,
                )
                time.sleep(delay)
            else:
                logger.error("Усі спроби звернення до LLM вичерпано: %s", e)

    raise LLMUnavailableError(f"Помилка звернення до LLM: {last_error}") from last_error


def chat_completion_json(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = 1200,
    temperature: float = 0.2,
) -> dict:
    """Просить LLM повернути валідний JSON і парсить його. Кидає LLMUnavailableError,
    якщо LLM недоступна АБО повернула щось, що не парситься як JSON."""
    raw = chat_completion(
        system_prompt, user_prompt,
        max_tokens=max_tokens, temperature=temperature, json_mode=True,
    )
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:]
        cleaned = cleaned.strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as e:
        raise LLMUnavailableError(f"LLM повернула не-JSON відповідь: {e}") from e
