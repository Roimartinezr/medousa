import time
import asyncio
from typing import Any, Dict, Generator

import whois
from opensearchpy import OpenSearch, helpers

# Importa el cliente de DonDominio
from backend.scrap.dondominio import DonDominioAsync   # <--- tu archivo

OPENSEARCH_HOST = "localhost"
OPENSEARCH_PORT = 9200
INDEX_NAME = "known_brands"


# ------------------------------------------------------
# 1) Conexión a OpenSearch
# ------------------------------------------------------

def get_client() -> OpenSearch:
    return OpenSearch(
        hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
        http_compress=True,
        timeout=30,
    )


def iter_docs(client: OpenSearch, index: str):
    """Itera todos los documentos via scroll."""
    page = client.search(
        index=index,
        body={"query": {"match_all": {}}},
        scroll="2m",
        size=100,
    )
    scroll_id = page.get("_scroll_id")
    hits = page["hits"]["hits"]

    while hits:
        for h in hits:
            yield h

        page = client.scroll(scroll_id=scroll_id, scroll="2m")
        scroll_id = page.get("_scroll_id")
        hits = page["hits"]["hits"]

    client.clear_scroll(scroll_id=scroll_id)


# ------------------------------------------------------
# 2) EXTRAER COUNTRY CODE DE python-whois
# ------------------------------------------------------

def extract_country_python_whois(w: Any) -> str:
    if not w:
        return ""

    try:
        data = dict(w)
    except Exception:
        data = w

    keys = [
        "country_code", "country",
        "registrant_country", "registrant_country_code",
        "registrant_country_code2"
    ]

    for k in keys:
        if k in data and data[k]:
            val = data[k]
            if isinstance(val, (list, tuple)):
                val = val[0] if val else None
            if val:
                return str(val).strip()

    # fallback: escanear raw
    raw = getattr(w, "text", None) or data.get("raw", None)
    if raw and isinstance(raw, str):
        for ln in raw.splitlines():
            if "country" in ln.lower():
                parts = ln.split(":")
                if len(parts) >= 2:
                    return parts[1].strip()

    return ""


def normalize_cc(cc: str) -> str:
    if not cc:
        return ""
    cc = cc.strip()
    if len(cc) == 2:
        return cc.lower()
    return cc.lower()


# ------------------------------------------------------
# 3) EXTRAER COUNTRY CODE DE DONDOMINIO
# ------------------------------------------------------

async def extract_country_dondominio(domain: str) -> str:
    """
    DonDominio devuelve WHOIS plano.
    Buscamos líneas como:
    "Registrant Country : ES"
    "Country: ES"
    """
    async with DonDominioAsync(debug=False) as api:
        whois_text = await api.domain_whois(domain)

    if not whois_text:
        return ""

    lines = whois_text.splitlines()

    for ln in lines:
        lower = ln.lower()
        if "country" in lower:
            if ":" in ln:
                val = ln.split(":", 1)[1].strip()
                if val:
                    return val

    return ""


# ------------------------------------------------------
# 4) ACTUALIZAR OPENSEARCH
# ------------------------------------------------------

def update_country_code(client: OpenSearch, doc_id: str, cc: str):
    client.update(
        index=INDEX_NAME,
        id=doc_id,
        body={"doc": {"country_code": cc}}
    )


# ------------------------------------------------------
# 5) MAIN LOGIC
# ------------------------------------------------------

async def process_all():
    client = get_client()
    print("Conectado a OpenSearch")

    total = updated = skipped = errors = 0

    for hit in iter_docs(client, INDEX_NAME):
        total += 1

        doc_id = hit["_id"]
        src = hit.get("_source", {})
        existing = src.get("country_code")

        if existing:   # si ya tiene cc, skip
            print(f"[SKIP] {doc_id}: ya tiene country_code='{existing}'")
            skipped += 1
            continue

        domain = f"{doc_id}.com"
        print(f"[WHOIS] python-whois: {domain}")

        # ---------- 1) python-whois ----------
        try:
            w = whois.whois(domain)
            cc = normalize_cc(extract_country_python_whois(w))
        except Exception as e:
            print(f"[python-whois ERROR] {domain}: {e}")
            cc = ""

        # ---------- 2) Fallback DonDominio ----------
        if not cc:
            try:
                print(f"[DONDOMINIO fallback] {domain}")
                cc = normalize_cc(await extract_country_dondominio(domain))
            except Exception as e:
                print(f"[DonDominio ERROR] {domain}: {e}")
                cc = ""

        # ---------- si se sigue sin país ----------
        if not cc:
            print(f"[WARN] {doc_id}: no se pudo obtener country_code")
            errors += 1
            continue

        # ---------- actualizar ----------
        try:
            update_country_code(client, doc_id, cc)
            print(f"[OK] {doc_id}: country_code='{cc}'")
            updated += 1
        except Exception as e:
            print(f"[ERROR UPDATE] {doc_id}: {e}")
            errors += 1

        time.sleep(0.5)  # evita baneo de whois

    print("\n---- RESUMEN ----")
    print("Total:", total)
    print("Actualizados:", updated)
    print("Saltados:", skipped)
    print("Errores:", errors)


# ------------------------------------------------------
# EJECUCIÓN
# ------------------------------------------------------

if __name__ == "__main__":
    asyncio.run(process_all())
