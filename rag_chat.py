"""
rag_chat.py — RAG-асистент технічної підтримки.

Пайплайн класичний retrieval-augmented generation:
  1. Retrieval: активний бекенд векторного пошуку (vector_store.py) знаходить
     top-k релевантних документів бази знань (з урахуванням рівня допуску
     користувача — фільтрація відбувається до виклику цього модуля).
  2. Augmentation: знайдені фрагменти складаються в контекстний промпт.
  3. Generation: LLM (llm_client.py) генерує відповідь СУВОРО на основі
     наданого контексту, з посиланнями на назви документів.

Якщо LLM не налаштована/недоступна — модуль не "мовчить", а повертає чесну
екстрактивну відповідь, зібрану з найрелевантніших знайдених фрагментів
(без вигадування фактів), з явною позначкою, що це відповідь без LLM.
"""

import llm_client
from vector_store import get_active_backend

SYSTEM_PROMPT = (
    "Ти — технічний асистент енергокомпанії. Відповідай на запитання співробітників "
    "ВИКЛЮЧНО на основі наданого нижче контексту з бази технічних знань (регламенти, "
    "інструкції, паспорти обладнання, схеми, НПАОП). "
    "Якщо в контексті немає достатньо інформації для відповіді — чесно скажи про це, "
    "не вигадуй факти. Відповідай українською мовою, чітко та по кроках, якщо це "
    "порядок дій. Обов'язково вказуй, з якого документа взято інформацію, у форматі "
    "«[Джерело: назва документа]» після відповідного твердження."
)


def _build_context(results):
    blocks = []
    for r in results:
        d = r["doc"]
        blocks.append(f"### Документ: {d['title']} (категорія: {d['category']})\n{d['content']}")
    return "\n\n".join(blocks)


def _fallback_answer(query, results):
    """Екстрактивна відповідь без LLM: показуємо найрелевантніші знайдені фрагменти як є."""
    if not results:
        return (
            "На жаль, у доступній вам базі знань не знайдено документів, що відповідають "
            "на це запитання. Спробуйте переформулювати запит або зверніться до відповідальної служби."
        )
    lines = [
        "*(LLM не налаштована — показую найрелевантніші фрагменти з бази знань без узагальнення LLM.)*",
        "",
    ]
    for r in results:
        d = r["doc"]
        lines.append(f"**{d['title']}** ({d['category']}):")
        lines.append(r["snippet"])
        lines.append(f"_[Джерело: {d['title']}]_")
        lines.append("")
    return "\n".join(lines)


def answer_query(query, documents, top_k=4):
    """
    documents: список kb_documents (уже відфільтрований за рівнем допуску користувача)
    Повертає dict: {answer: str, sources: [titles], llm_used: bool}
    """
    backend = get_active_backend()
    results = backend.search(query, documents, category=None, top_k=top_k)
    sources = [r["doc"]["title"] for r in results]

    if not llm_client.is_llm_configured():
        return {"answer": _fallback_answer(query, results), "sources": sources, "llm_used": False}

    context = _build_context(results)
    user_prompt = f"Контекст з бази знань:\n\n{context}\n\n---\n\nЗапитання співробітника: {query}"

    try:
        answer = llm_client.chat_completion(SYSTEM_PROMPT, user_prompt, max_tokens=700)
        return {"answer": answer, "sources": sources, "llm_used": True}
    except llm_client.LLMUnavailableError:
        return {"answer": _fallback_answer(query, results), "sources": sources, "llm_used": False}
