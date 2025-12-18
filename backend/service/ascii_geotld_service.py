# app/backend/service/ascii_geotld_service.py
from typing import List, Optional, Dict, Any
from opensearchpy import OpenSearch
from opensearchpy.exceptions import NotFoundError

INDEX_ASCII_GEOTLD = "ascii_geotld"


def get_all_ascii_geotld_ids(dev = False) -> List[str]:
    """
    Devuelve una lista con todos los _id del índice 'ascii_geotld'.
    Se asume que el _id es el propio GeoTLD (ej: 'cat', 'eus', 'madrid').
    """
    if dev:
        client = __get_client()
    else:
        from opensearch_client import get_opensearch_client
        client: OpenSearch = get_opensearch_client()

    # Verificamos existencia para evitar error 404
    if not client.indices.exists(index=INDEX_ASCII_GEOTLD):
        return []

    resp = client.search(
        index=INDEX_ASCII_GEOTLD,
        body={
            "size": 1000,       # Suficiente para los GeoTLDs actuales
            "_source": False,   # Optimización: Solo traemos metadatos (_id)
            "query": {
                "match_all": {}
            }
        }
    )

    hits = resp.get("hits", {}).get("hits", [])
    return [h["_id"] for h in hits]


def get_ascii_geotld_by_id(tld: str, dev = False) -> Optional[Dict[str, Any]]:
    """
    Obtiene los datos (_source) de un GeoTLD específico buscando por su _id.
    Retorna None si el TLD no existe.
    """
    if dev:
        client = __get_client()
    else:
        from opensearch_client import get_opensearch_client
        client: OpenSearch = get_opensearch_client()

    try:
        doc = client.get(index=INDEX_ASCII_GEOTLD, id=tld)
        return doc.get("_source")
    except NotFoundError:
        return None


def get_country_by_id(tld: str, dev = False) -> Optional[str]:
    """
    Devuelve el campo 'country' (ej: 'es') de un GeoTLD específico dado su _id.
    Sustituye a la antigua función 'get_fallback_by_id'.
    Retorna None si el TLD no existe o el campo es nulo.
    """
    if dev:
        client = __get_client()
    else:
        from opensearch_client import get_opensearch_client
        client: OpenSearch = get_opensearch_client()

    try:
        # Usamos _source_includes para traer SOLO el campo country
        doc = client.get(
            index=INDEX_ASCII_GEOTLD, 
            id=tld, 
            _source_includes=["country"]
        )
        # Obtenemos el source y luego el campo.
        return doc.get("_source", {}).get("country")
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
    # Prueba rápida
    print("IDs encontrados:", get_all_ascii_geotld_ids(dev=True))
    print("Info de 'eus':", get_ascii_geotld_by_id('eus', dev=True))
    print("País de 'madrid':", get_country_by_id('madrid', dev=True))"""