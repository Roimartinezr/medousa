#!/usr/bin/env python
"""
Script independiente para nutrir inicialmente OpenSearch con:

- OMIT_WORDS  -> índice 'omit_words'
- MAIL_NAMES  -> índice 'mail_names'

Uso:
    OPENSEARCH_HOST=localhost OPENSEARCH_PORT=9200 python seed_opensearch.py
    (por defecto host=localhost, port=9200)
"""

import os
from opensearchpy import OpenSearch, helpers

# ==========================
# CONFIG
# ==========================

OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))

INDEX_OMIT_WORDS = "omit_words"
INDEX_MAIL_NAMES = "mail_names"

OMIT_WORDS = {
    "www", "mail", "secure", "info", "login", "cliente", "clientes",
    "web", "app", "email", "alerta", "soporte", "acceso", "online",
    "account", "accounts", "seguridad", "support", "admin",
    "beta", "portal", "service", "services", "system", "verify",
    "verification", "update", "updates", "user", "users"
}

MAIL_NAMES = {
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "yahoo.com",
    "ymail.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "proton.me",
    "protonmail.com",
    "zoho.com",
    "zohomail.com",
    "aol.com",
    "gmx.com",
    "mail.com",
}


# ==========================
# CLIENT
# ==========================

def get_client() -> OpenSearch:
    return OpenSearch(
        hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
        http_compress=True,
        use_ssl=False,
        verify_certs=False,
        ssl_show_warn=False,
    )


# ==========================
# CREACIÓN ÍNDICES
# ==========================

def ensure_omit_words_index(client: OpenSearch) -> None:
    if client.indices.exists(index=INDEX_OMIT_WORDS):
        print(f"[omit_words] Índice ya existe")
        return

    body = {
        "mappings": {
            "properties": {
                "word": {"type": "keyword"},
                "lang": {"type": "keyword"},
                "scope": {"type": "keyword"},
            }
        }
    }

    client.indices.create(index=INDEX_OMIT_WORDS, body=body)
    print(f"[omit_words] Índice creado")


def ensure_mail_names_index(client: OpenSearch) -> None:
    if client.indices.exists(index=INDEX_MAIL_NAMES):
        print(f"[mail_names] Índice ya existe")
        return

    body = {
        "mappings": {
            "properties": {
                "domain": {"type": "keyword"},
                "base_name": {"type": "keyword"},
                "tags": {"type": "keyword"},
            }
        }
    }

    client.indices.create(index=INDEX_MAIL_NAMES, body=body)
    print(f"[mail_names] Índice creado")


# ==========================
# SEED DATA
# ==========================

def seed_omit_words(client: OpenSearch) -> None:
    actions = []
    for w in OMIT_WORDS:
        actions.append({
            "_index": INDEX_OMIT_WORDS,
            "_id": w,  # palabra como id
            "_source": {
                "word": w,
                "lang": "mixed",
                "scope": "domain",
            }
        })

    if not actions:
        print("[omit_words] No hay datos para insertar")
        return

    helpers.bulk(client, actions)
    print(f"[omit_words] Insertadas {len(actions)} palabras omisibles")


def seed_mail_names(client: OpenSearch) -> None:
    actions = []
    for domain in MAIL_NAMES:
        base_name = domain.split(".")[0]
        actions.append({
            "_index": INDEX_MAIL_NAMES,
            "_id": domain,  # el propio dominio como id
            "_source": {
                "domain": domain,
                "base_name": base_name,
                "tags": ["general-supplier", "personal-mail"],
            }
        })

    if not actions:
        print("[mail_names] No hay datos para insertar")
        return

    helpers.bulk(client, actions)
    print(f"[mail_names] Insertados {len(actions)} dominios personales")


# ==========================
# MAIN
# ==========================

def main():
    print(f"Conectando a OpenSearch en {OPENSEARCH_HOST}:{OPENSEARCH_PORT} ...")
    client = get_client()

    # Asegurar índices
    ensure_omit_words_index(client)
    ensure_mail_names_index(client)

    # Seed inicial
    seed_omit_words(client)
    seed_mail_names(client)

    print("✅ Seed inicial completado.")


if __name__ == "__main__":
    main()
