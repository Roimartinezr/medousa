#app/backend/service/idn_cctld_service.py
from typing import List, Optional, Dict, Any
from opensearchpy import OpenSearch
from opensearchpy.exceptions import NotFoundError

INDEX_IDN_CCTLD = "idn_cctld"


def get_all_idn_cctld_ids(dev = False) -> List[str]:
    """
    Devuelve una lista con todos los _id del índice 'idn_cctld'.
    Se asume que el _id es el TLD en formato punycode o nativo (ej: 'xn--p1ai').
    """
    if dev:
        client = __get_client()
    else:
        from ..opensearch_client import get_opensearch_client
        client: OpenSearch = get_opensearch_client()

    # Verificamos existencia para evitar error 404 si el índice aún no se creó
    if not client.indices.exists(index=INDEX_IDN_CCTLD):
        return []

    resp = client.search(
        index=INDEX_IDN_CCTLD,
        body={
            "size": 1000,       # Suficiente para cubrir los ccTLDs IDN actuales
            "_source": False,   # Optimización: No traemos el cuerpo, solo metadatos (_id)
            "query": {
                "match_all": {}
            }
        }
    )

    hits = resp.get("hits", {}).get("hits", [])
    return [h["_id"] for h in hits]


def get_idn_cctld_by_id(tld: str, dev = False) -> Optional[Dict[str, Any]]:
    """
    Obtiene los datos (_source) de un IDN ccTLD específico buscando por su _id.
    Retorna None si el TLD no existe.
    """
    if dev:
        client = __get_client()
    else:
        from ..opensearch_client import get_opensearch_client
        client: OpenSearch = get_opensearch_client()

    try:
        doc = client.get(index=INDEX_IDN_CCTLD, id=tld)
        return doc.get("_source")
    except NotFoundError:
        return None


def __get_client() -> OpenSearch:
        return OpenSearch(
            hosts=[{"host": "localhost", "port": "9200"}],
            http_compress=True,
            use_ssl=False,
            verify_certs=False,
            ssl_show_warn=False,
        )

"""if __name__ == "__main__":
    print(get_all_idn_cctld_ids(dev=True))"""