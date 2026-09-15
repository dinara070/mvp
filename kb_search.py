"""
kb_search.py — гібридний пошук по базі технічних знань.

У продакшн-версії (див. Технологічний стек у ТЗ) тут була б векторна БД
(Qdrant / Milvus / pgvector) з ембедингами від локально розгорнутої LLM
(Llama/Mistral через Ollama або vLLM) — тобто повноцінна RAG-архітектура.

У цьому демо-MVP роль "семантичного" пошуку виконує TF-IDF + косинусна
схожість (scikit-learn). Це не LLM-рівень розуміння запиту, але воно вже
дозволяє знаходити релевантні документи за змістом запиту природною мовою,
а не лише за точним збігом слів — і чесно показує користувачу, звідки
взято знайдений фрагмент (посилання на документ), як і має робити RAG.
"""

import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


def _split_paragraphs(text):
    # ділимо документ на речення/фрагменти, щоб повертати саме релевантний абзац, а не весь документ
    parts = re.split(r"(?<=[.!?])\s+", text)
    return [p.strip() for p in parts if p.strip()]


def hybrid_search(query, documents, category=None, top_k=5):
    """
    documents: список sqlite3.Row з полями id, title, category, tags, content, owner, updated_at
    Повертає список dict: {doc, score, snippet}
    """
    if not query or not query.strip():
        docs = [d for d in documents if (category in (None, "Усі") or d["category"] == category)]
        return [{"doc": d, "score": None, "snippet": _split_paragraphs(d["content"])[0]} for d in docs]

    pool = [d for d in documents if (category in (None, "Усі") or d["category"] == category)]
    if not pool:
        return []

    corpus = [f"{d['title']} {d['tags'] or ''} {d['content']}" for d in pool]
    corpus.append(query)

    vectorizer = TfidfVectorizer(
        lowercase=True,
        token_pattern=r"(?u)\b\w\w+\b",
    )
    try:
        tfidf = vectorizer.fit_transform(corpus)
    except ValueError:
        return []

    query_vec = tfidf[-1]
    doc_vecs = tfidf[:-1]
    sims = cosine_similarity(query_vec, doc_vecs).flatten()

    ranked = sorted(zip(pool, sims), key=lambda x: x[1], reverse=True)

    results = []
    for doc, score in ranked[:top_k]:
        if score <= 0:
            continue
        # знаходимо найрелевантніший абзац/речення всередині документа для "точного попадання"
        paragraphs = _split_paragraphs(doc["content"])
        if paragraphs:
            para_corpus = paragraphs + [query]
            try:
                pv = TfidfVectorizer(lowercase=True, token_pattern=r"(?u)\b\w\w+\b").fit_transform(para_corpus)
                psims = cosine_similarity(pv[-1], pv[:-1]).flatten()
                best_idx = psims.argmax()
                snippet = paragraphs[best_idx]
            except ValueError:
                snippet = paragraphs[0]
        else:
            snippet = doc["content"][:200]
        results.append({"doc": doc, "score": round(float(score), 3), "snippet": snippet})

    return results
