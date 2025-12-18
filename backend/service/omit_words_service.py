# app/services/domain_sanitizer_service/omit_words_service.py

from typing import List, Optional
from opensearchpy import OpenSearch, helpers

from opensearch_client import get_opensearch_client

INDEX_OMIT_WORDS = "omit_words"

def __get_client() -> OpenSearch:
        return OpenSearch(
            hosts=[{"host": "localhost", "port": "9200"}],
            http_compress=True,
            use_ssl=False,
            verify_certs=False,
            ssl_show_warn=False,
        )

def ensure_omit_words_index() -> None:
    """
    Crea el índice 'omit_words' si no existe.
    Guarda palabras que se deben ignorar al extraer la company del dominio.
    """
    client: OpenSearch = get_opensearch_client()
    if client.indices.exists(index=INDEX_OMIT_WORDS):
        return

    body = {
        "mappings": {
            "properties": {
                "word": {          # "mail", "secure", "cliente", etc.
                    "type": "keyword"
                },
                "lang": {         # opcional: "es", "en", ...
                    "type": "keyword"
                },
                "scope": {        # opcional: "domain", "subdomain", ...
                    "type": "keyword"
                },
                "active": {       # para poder desactivar sin borrar
                    "type": "boolean"
                }
            }
        }
    }

    client.indices.create(index=INDEX_OMIT_WORDS, body=body)


def upsert_omit_word(word: str,
                    lang: Optional[str] = None,
                    scope: Optional[str] = None,
                    active: bool = True) -> None:
    """
    Crea o actualiza una palabra omitible.
    Usa la propia palabra como _id para no duplicar.
    """
    client = get_opensearch_client()

    doc_id = word.lower().strip()
    payload = {
        "word": doc_id,
        "lang": lang or "mixed",
        "scope": scope or "domain",
        "active": active,
    }

    client.index(index=INDEX_OMIT_WORDS, id=doc_id, body=payload)


def bulk_seed_omit_words(words: List[str]) -> None:
    """
    Carga inicial masiva de palabras omitibles.
    """
    if not words:
        return

    client = get_opensearch_client()
    actions = []

    for w in words:
        w_norm = w.lower().strip()
        actions.append({
            "_index": INDEX_OMIT_WORDS,
            "_id": w_norm,
            "_source": {
                "word": w_norm,
                "lang": "mixed",
                "scope": "domain",
                "active": True,
            }
        })

    helpers.bulk(client, actions)


def get_all_omit_words(active_only: bool = True, dev = False) -> List[str]:
    """
    Devuelve todas las palabras omitibles (por defecto solo las activas).
    """

    if dev:
        client = __get_client()
    else:
        client = get_opensearch_client()

    query: dict
    if active_only:
        query = {"term": {"active": True}}
    else:
        query = {"match_all": {}}

    resp = client.search(
        index=INDEX_OMIT_WORDS,
        body={
            "size": 1000,    # suficiente para empezar
            "_source": ["word"],
            "query": query,
        }
    )

    hits = resp.get("hits", {}).get("hits", [])
    return [h["_source"]["word"] for h in hits]
