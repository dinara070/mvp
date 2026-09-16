"""pdf_reader.py — витягування тексту з PDF для автогенератора тестів з ОП."""


def extract_text(file_like):
    """file_like: файловий об'єкт (напр. з st.file_uploader), що підтримує .read()."""
    from pypdf import PdfReader
    reader = PdfReader(file_like)
    parts = []
    for page in reader.pages:
        try:
            parts.append(page.extract_text() or "")
        except Exception:
            continue
    return "\n".join(parts).strip()
