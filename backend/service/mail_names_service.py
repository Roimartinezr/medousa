# app/services/domain_sanitizer_service/mail_names_service.py

from typing import List, Optional, Dict

from opensearchpy import OpenSearch, helpers
from ..opensearch_client import get_opensearch_client

INDEX_MAIL_NAMES = "mail_names"


def ensure_mail_names_index() -> None:
    """
    Crea el índice 'mail_names' si no existe.
    Guarda proveedores personales tipo gmail.com, outlook.com, etc.
    """
    client: OpenSearch = get_opensearch_client()
    if client.indices.exists(INDEX_MAIL_NAMES):
        return

    body = {
        "mappings": {
            "properties": {
                "domain": {      # "gmail.com"
                    "type": "keyword"
                },
                "base_name": {   # "gmail"
                    "type": "keyword"
                },
                "tags": {        # ["general-supplier", "personal-mail"]
                    "type": "keyword"
                }
            }
        }
    }

    client.indices.create(index=INDEX_MAIL_NAMES, body=body)


def upsert_mail_name(domain: str,
                     base_name: Optional[str] = None,
                     tags: Optional[List[str]] = None) -> None:
    """
    Crea o actualiza un mail_name.
    Puedes usarlo para meter tus proveedores personales iniciales.
    """
    client = get_opensearch_client()
    base_name = base_name or domain.split(".")[0]
    tags = tags or ["general-supplier", "personal-mail"]

    # Usamos el propio domain como _id para no duplicar
    doc_id = domain

    payload = {
        "domain": domain,
        "base_name": base_name,
        "tags": tags,
    }

    client.index(index=INDEX_MAIL_NAMES, id=doc_id, body=payload)


def bulk_seed_mail_names(domains: List[str]) -> None:
    """
    Opcional: para cargar de golpe tus MAIL_NAMES iniciales.
    """
    client = get_opensearch_client()
    actions = []

    for domain in domains:
        base_name = domain.split(".")[0]
        actions.append({
            "_index": INDEX_MAIL_NAMES,
            "_id": domain,
            "_source": {
                "domain": domain,
                "base_name": base_name,
                "tags": ["general-supplier", "personal-mail"]
            }
        })

    if actions:
        helpers.bulk(client, actions)


def get_mail_name(domain: str) -> Optional[Dict]:
    """
    Devuelve el documento de mail_names para ese dominio (si existe).
    """
    client = get_opensearch_client()
    resp = client.search(
        index=INDEX_MAIL_NAMES,
        body={
            "size": 1,
            "query": {
                "term": {"domain": domain}
            }
        }
    )
    hits = resp.get("hits", {}).get("hits", [])
    return hits[0] if hits else None


def is_personal_mail_domain(domain: str) -> bool:
    """
    True si el dominio es un proveedor personal (gmail, outlook, etc.).
    """
    return get_mail_name(domain) is not None
