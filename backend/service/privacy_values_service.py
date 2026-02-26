# backend/service/privacy_values_service.py

from typing import List
from functools import lru_cache

from opensearchpy import OpenSearch, NotFoundError
from opensearch_client import get_opensearch_client

INDEX_PRIVACY_VALUES = "privacy_values"
DOC_ID_PRIVACY_VALUES = "whois_privacy_values"

# ---------------------------------------------------------
# CREACIÓN DE ÍNDICE
# ---------------------------------------------------------

def ensure_privacy_values_index() -> None:
    """
    Crea el índice 'privacy_values' si no existe.
    Este índice contiene un único documento con un array 'values'.
    """
    client: OpenSearch = get_opensearch_client()

    if client.indices.exists(index=INDEX_PRIVACY_VALUES):
        return

    body = {
        "mappings": {
            "properties": {
                "config_key": {"type": "keyword"},
                "values": {"type": "keyword"}   # array de patrones
            }
        }
    }

    client.indices.create(index=INDEX_PRIVACY_VALUES, body=body)


# ---------------------------------------------------------
# UPSERT (crear o actualizar el documento único)
# ---------------------------------------------------------

def upsert_privacy_values(values: List[str]) -> None:
    """
    Inserta o actualiza el documento único con todos los patrones
    de privacidad WHOIS.
    """
    client = get_opensearch_client()

    payload = {
        "config_key": DOC_ID_PRIVACY_VALUES,
        "values": [v.lower().strip() for v in values],
    }

    client.index(
        index=INDEX_PRIVACY_VALUES,
        id=DOC_ID_PRIVACY_VALUES,
        body=payload
    )

    # limpiar caché
    get_privacy_values.cache_clear()


# ---------------------------------------------------------
# LECTURA DEL DOCUMENTO ÚNICO
# ---------------------------------------------------------

@lru_cache(maxsize=1)
def get_privacy_values() -> List[str]:
    """
    Devuelve la lista de patrones 'values' desde el documento único.
    Cacheado para rendimiento.
    """
    client = get_opensearch_client()

    try:
        doc = client.get(index=INDEX_PRIVACY_VALUES, id=DOC_ID_PRIVACY_VALUES)
        src = doc.get("_source", {})
        arr = src.get("values", [])
        return [str(v).lower().strip() for v in arr if v]
    except NotFoundError:
        return []


# ---------------------------------------------------------
# FUNCIÓN PRINCIPAL PARA EL WHOIS
# ---------------------------------------------------------

def is_privacy_value(val: str) -> bool:
    """
    True si algún patrón aparece en el valor WHOIS.
    """
    if not val:
        return False

    v = val.lower()
    patterns = get_privacy_values()
    return any(pat in v for pat in patterns)
