from typing import List
from opensearchpy import OpenSearch


INDEX_IDN_CCTLD = "idn_cctld"


def get_all_idn_cctld_ids(client: None) -> List[str]:
    """
    Devuelve una lista con todos los _id del índice 'idn_cctld'.
    Se asume que el _id es el TLD en formato punycode o nativo (ej: 'xn--p1ai').
    """
    if not client:
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

if __name__ == "__main__":
    def get_client() -> OpenSearch:
        return OpenSearch(
            hosts=[{"host": "localhost", "port": "9200"}],
            http_compress=True,
            use_ssl=False,
            verify_certs=False,
            ssl_show_warn=False,
        )
    print(get_all_idn_cctld_ids(get_client()))