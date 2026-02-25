# app/services/domain_sanitizer_service/omit_words_service.py

"""
PARA QUE UNA OMIT WORD SE CARGUE, DEBE ESTAR MARCADA COMO 'active' en OpenSearch
"""

from typing import List, Optional
from opensearchpy import OpenSearch, helpers
from opensearch_client import get_opensearch_client

DEV = False

INDEX_OMIT_WORDS = "omit_words"

def __get_client(dev=DEV) -> OpenSearch:
    if dev:
        return OpenSearch(
            hosts=[{"host": "localhost", "port": "9200"}],
            http_compress=True,
            use_ssl=False,
            verify_certs=False,
            ssl_show_warn=False,
        )
    return get_opensearch_client()


def ensure_omit_words_index(dev=DEV) -> None:
    """
    Crea el índice 'omit_words' si no existe.
    Guarda palabras que se deben ignorar al extraer la company del dominio.
    """
    client = __get_client(dev)

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
                    active: bool = True,
                    dev = DEV) -> None:
    """
    Crea o actualiza una palabra omitible.
    Usa la propia palabra como _id para no duplicar.
    """
    client = __get_client(dev)

    doc_id = word.lower().strip()
    payload = {
        "word": doc_id,
        "lang": lang or "mixed",
        "scope": scope or "domain",
        "active": active,
    }

    client.index(index=INDEX_OMIT_WORDS, id=doc_id, body=payload)


def bulk_seed_omit_words(words: List[str], dev=DEV) -> None:
    """
    Carga inicial masiva de palabras omitibles.
    """
    if not words:
        return

    client = __get_client(dev)
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


def get_all_omit_words(active_only: bool = True, dev = DEV) -> List[str]:
    """
    Devuelve todas las palabras omitibles (por defecto solo las activas).
    """

    client = __get_client(dev)

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


def activate_all_omit_words():
    client = __get_client(DEV)
    index_name = "omit_words"

    # Definimos la actualización masiva
    update_body = {
        "script": {
            "source": "ctx._source.active = true",
            "lang": "painless"
        },
        "query": {
            "match_all": {}
        }
    }

    print(f"Actualizando documentos en el índice '{index_name}'...")
    
    try:
        response = client.update_by_query(
            index=index_name, 
            body=update_body,
            wait_for_completion=True # Esperamos a que termine para ver el resultado
        )
        
        updated = response.get("updated", 0)
        batches = response.get("batches", 0)
        
        print(f"Se han activado {updated} palabras en {batches} lotes.")
        
    except Exception as e:
        print(f"Error al actualizar: {str(e)}")


#upsert_omit_word("mail", dev=True)