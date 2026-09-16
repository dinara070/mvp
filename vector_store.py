"""
vector_store.py — абстракція бекенду семантичного пошуку по базі знань.

Два бекенди:
  - TfidfBackend  — поточна реалізація за замовчуванням (kb_search.py), працює
    одразу "з коробки" без жодної зовнішньої інфраструктури.
  - QdrantBackend — справжній векторний пошук через Qdrant (реальний робочий
    клієнт qdrant-client), з ембедингами від OpenAI-сумісного API
    (text-embedding-3-small або локальна модель ембедингів через Ollama, якщо
    вона підтримує /v1/embeddings). Активується змінними середовища:

        VECTOR_BACKEND=qdrant
        QDRANT_URL=http://localhost:6333
        QDRANT_COLLECTION=kb_documents
        OPENAI_API_KEY=...            # потрібен для генерації ембедингів

    Якщо Qdrant або ембединги недоступні в момент запиту — QdrantBackend сам
    коректно "падає" на TfidfBackend (fail-safe), щоб пошук ніколи не ламав
    інтерфейс користувача.

Пояснення щодо PostgreSQL + pgvector: технічно це той самий підхід (вектори +
косинусна/inner-product відстань), лише сховище — таблиця Postgres з
розширенням `pgvector` замість окремого сервісу Qdrant. Обидва варіанти
взаємозамінні для цієї задачі; ми реалізували Qdrant як приклад, оскільки
він не вимагає розширення існуючої реляційної БД. Перехід на pgvector
означав би: `CREATE EXTENSION vector;`, колонку `embedding VECTOR(1536)` у
`kb_documents` та запит `ORDER BY embedding <=> :query_embedding LIMIT k`
замість викликів Qdrant-клієнта нижче.
"""

import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from kb_search import hybrid_search
import llm_client

VECTOR_BACKEND = os.environ.get("VECTOR_BACKEND", "tfidf").strip().lower()
QDRANT_URL = os.environ.get("QDRANT_URL", "http://localhost:6333").strip()
QDRANT_COLLECTION = os.environ.get("QDRANT_COLLECTION", "kb_documents").strip()
EMBEDDING_MODEL = os.environ.get("OPENAI_EMBEDDING_MODEL", "text-embedding-3-small").strip()


class TfidfBackend:
    """Бекенд за замовчуванням — TF-IDF + косинусна схожість, без зовнішніх залежностей."""

    name = "TF-IDF (вбудований)"

    def search(self, query, documents, category=None, top_k=5):
        return hybrid_search(query, documents, category=category, top_k=top_k)


class QdrantBackend:
    """Production-бекенд: справжній векторний пошук у Qdrant з ембедингами через LLM API.

    Індекс перебудовується "на льоту" при кожному запиті на невеликих обсягах
    документів (демо-масштаб). У продакшн-версії індексацію документів варто
    виносити в окремий фоновий job (напр. при збереженні/оновленні документа
    в адмін-панелі), а не робити на кожен пошуковий запит.
    """

    name = f"Qdrant ({QDRANT_URL})"

    def __init__(self):
        from qdrant_client import QdrantClient
        from qdrant_client.models import Distance, VectorParams, PointStruct
        self._QdrantClient = QdrantClient
        self._Distance = Distance
        self._VectorParams = VectorParams
        self._PointStruct = PointStruct
        self.client = QdrantClient(url=QDRANT_URL)

    def _embed(self, texts):
        from openai import OpenAI
        api_key = llm_client.OPENAI_API_KEY or "ollama-local"
        client = OpenAI(api_key=api_key, base_url=llm_client.OPENAI_BASE_URL)
        resp = client.embeddings.create(model=EMBEDDING_MODEL, input=texts)
        return [d.embedding for d in resp.data]

    def _ensure_collection(self, dim):
        collections = [c.name for c in self.client.get_collections().collections]
        if QDRANT_COLLECTION not in collections:
            self.client.create_collection(
                collection_name=QDRANT_COLLECTION,
                vectors_config=self._VectorParams(size=dim, distance=self._Distance.COSINE),
            )

    def search(self, query, documents, category=None, top_k=5):
        pool = [d for d in documents if (category in (None, "Усі") or d["category"] == category)]
        if not pool or not query or not query.strip():
            return TfidfBackend().search(query, documents, category=category, top_k=top_k)

        texts = [f"{d['title']} {d['tags'] or ''} {d['content']}" for d in pool]
        vectors = self._embed(texts + [query])
        doc_vectors, query_vector = vectors[:-1], vectors[-1]

        self._ensure_collection(dim=len(doc_vectors[0]))
        points = [
            self._PointStruct(id=pool[i]["id"], vector=doc_vectors[i], payload={"doc_id": pool[i]["id"]})
            for i in range(len(pool))
        ]
        self.client.upsert(collection_name=QDRANT_COLLECTION, points=points)

        hits = self.client.query_points(
            collection_name=QDRANT_COLLECTION, query=query_vector, limit=top_k
        ).points

        by_id = {d["id"]: d for d in pool}
        results = []
        for h in hits:
            doc = by_id.get(h.payload.get("doc_id") if h.payload else h.id)
            if not doc:
                continue
            paragraphs = doc["content"].split(". ")
            results.append({"doc": doc, "score": round(float(h.score), 3), "snippet": paragraphs[0]})
        return results


def get_active_backend():
    """Повертає активний бекенд пошуку. Fail-safe: будь-яка помилка ініціалізації
    Qdrant (сервіс не піднято, немає ключа для ембедингів тощо) прозоро повертає
    робочий TF-IDF бекенд, щоб пошук у застосунку не ламався."""
    if VECTOR_BACKEND == "qdrant":
        try:
            return QdrantBackend()
        except Exception:
            return TfidfBackend()
    return TfidfBackend()
