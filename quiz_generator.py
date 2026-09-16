"""
quiz_generator.py — автогенерація тестових питань з техніки безпеки з
завантаженого документа (PDF правил безпеки тощо).

Пайплайн:
  1. Текст документа (вже витягнутий з PDF через pdf_reader.py) передається в LLM
     із чіткою інструкцією повернути JSON-масив питань з одним правильним
     варіантом і трьома дистракторами.
  2. Якщо LLM недоступна — детерміністичний евристичний генератор будує прості
     питання «оберіть правильне продовження речення» на основі найінформативніших
     речень документа, з дистракторами з інших речень того самого тексту.
     Це не замінює якість LLM, але дозволяє інженеру з ОП одразу отримати
     чернетку тесту навіть без налаштованого LLM-провайдера.
"""

import re
import random

import llm_client

SYSTEM_PROMPT = (
    "Ти — методист з охорони праці на енергетичному підприємстві. На основі наданого "
    "тексту документа з техніки безпеки згенеруй тестові питання для перевірки знань "
    "персоналу. Питання мають перевіряти розуміння конкретних процедур і цифр з тексту, "
    "а не загальні факти. Кожне питання — 4 варіанти відповіді, лише один правильний. "
    "Відповідай СТРОГО у форматі JSON без жодного тексту навколо: "
    '{"questions": [{"question": "...", "options": ["...", "...", "...", "..."], "correct_index": 0}, ...]}'
)


def _split_sentences(text):
    parts = re.split(r"(?<=[.!?])\s+", text)
    return [p.strip() for p in parts if len(p.strip()) > 25]


def generate_questions_llm(text, n_questions=5):
    if not llm_client.is_llm_configured():
        raise llm_client.LLMUnavailableError("LLM не налаштована.")
    truncated = text[:8000]  # обмеження контексту для економії токенів
    user_prompt = f"Кількість питань: {n_questions}\n\nТекст документа:\n\n{truncated}"
    data = llm_client.chat_completion_json(SYSTEM_PROMPT, user_prompt, max_tokens=1500)
    questions = data.get("questions", [])
    validated = []
    for q in questions:
        if (
            isinstance(q.get("question"), str)
            and isinstance(q.get("options"), list)
            and len(q["options"]) >= 2
            and isinstance(q.get("correct_index"), int)
            and 0 <= q["correct_index"] < len(q["options"])
        ):
            validated.append({
                "question": q["question"],
                "options": q["options"][:4],
                "correct_index": q["correct_index"],
            })
    if not validated:
        raise llm_client.LLMUnavailableError("LLM повернула порожній або невалідний список питань.")
    return validated[:n_questions]


def generate_questions_fallback(text, n_questions=5):
    """Проста евристика без LLM: 'заповни пропуск' на основі значущих речень документа."""
    sentences = _split_sentences(text)
    if not sentences:
        return []
    random.seed(42)  # детермінізм для передбачуваного демо-результату
    chosen = sentences[: min(len(sentences), max(n_questions * 3, n_questions))]
    random.shuffle(chosen)
    chosen = chosen[:n_questions]

    questions = []
    for sent in chosen:
        words = [w for w in re.findall(r"[А-Яа-яЇїІіЄєҐґ\w]{5,}", sent)]
        if not words:
            continue
        keyword = max(words, key=len)
        masked = sent.replace(keyword, "____", 1)

        distractors = set()
        pool = [w for s in sentences if s != sent for w in re.findall(r"[А-Яа-яЇїІіЄєҐґ\w]{5,}", s)]
        random.shuffle(pool)
        for w in pool:
            if w.lower() != keyword.lower() and len(distractors) < 3:
                distractors.add(w)
        options = [keyword] + list(distractors)
        while len(options) < 4:
            options.append("Немає правильної відповіді")
        random.shuffle(options)
        correct_index = options.index(keyword)

        questions.append({
            "question": f"Яке слово пропущено: «{masked}»?",
            "options": options,
            "correct_index": correct_index,
        })
    return questions


def generate_questions(text, n_questions=5):
    """Пробує LLM, при недоступності — прозорий fallback. Повертає (questions, used_llm: bool)."""
    try:
        return generate_questions_llm(text, n_questions), True
    except llm_client.LLMUnavailableError:
        return generate_questions_fallback(text, n_questions), False
