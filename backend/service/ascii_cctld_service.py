#app/backend/service/ascii_cctld_service.py
from typing import List, Optional, Dict, Any
from opensearchpy import OpenSearch
from opensearchpy.exceptions import NotFoundError

INDEX_ASCII_CCTLD = "ascii_cctld"


def get_all_ascii_cctld_ids(client = None) -> List[str]:
    """
    Devuelve una lista con todos los _id del índice 'ascii_cctld'.
    Se asume que el _id es el propio TLD (ej: 'es', 'fr').
    """
    if not client:
        from ..opensearch_client import get_opensearch_client
        client: OpenSearch = get_opensearch_client()

    # Verificamos existencia para evitar error 404 si el índice aún no se creó
    if not client.indices.exists(index=INDEX_ASCII_CCTLD):
        return []

    resp = client.search(
        index=INDEX_ASCII_CCTLD,
        body={
            "size": 1000,       # Suficiente para todos los ccTLDs ASCII existentes (son < 300)
            "_source": False,   # Optimización: No traemos el cuerpo, solo metadatos (_id)
            "query": {
                "match_all": {}
            }
        }
    )

    hits = resp.get("hits", {}).get("hits", [])
    return [h["_id"] for h in hits]

def get_ascii_cctld_by_id(tld: str, client = None) -> Optional[Dict[str, Any]]:
    """
    Obtiene los datos (_source) de un TLD específico buscando por su _id.
    Retorna None si el TLD no existe.
    """
    if not client:
        from ..opensearch_client import get_opensearch_client
        client: OpenSearch = get_opensearch_client()

    try:
        doc = client.get(index=INDEX_ASCII_CCTLD, id=tld)
        return doc.get("_source")
    except NotFoundError:
        return None

if __name__ == "__main__":
    def __get_client() -> OpenSearch:
        return OpenSearch(
            hosts=[{"host": "localhost", "port": "9200"}],
            http_compress=True,
            use_ssl=False,
            verify_certs=False,
            ssl_show_warn=False,
        )
    print(get_all_ascii_cctld_ids(__get_client()))

def get_fallback_by_id(tld: str, client = None) -> List[str]:
    """
    Devuelve la lista 'fallback' de un TLD específico dado su _id.
    Retorna una lista vacía [] si el TLD no existe o no tiene campo fallback.
    """
    if not client:
        from ..opensearch_client import get_opensearch_client
        client: OpenSearch = get_opensearch_client()

    try:
        # Usamos _source_includes para traer SOLO el campo fallback
        doc = client.get(
            index=INDEX_ASCII_CCTLD, 
            id=tld, 
            _source_includes=["fallback"]
        )
        # Obtenemos el source y luego el campo, por defecto lista vacía
        return doc.get("_source", {}).get("fallback", None)
    except NotFoundError:
        # Si el ID no existe, devolvemos lista vacía para evitar errores al iterar
        return None