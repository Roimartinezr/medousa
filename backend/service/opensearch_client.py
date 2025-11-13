import os
from opensearchpy import OpenSearch

def get_opensearch_client() -> OpenSearch:
    host = os.getenv("OPENSEARCH_HOST", "opensearch")
    port = int(os.getenv("OPENSEARCH_PORT", "9200"))

    return OpenSearch(
        hosts=[{"host": host, "port": port}],
        http_compress=True,
        use_ssl=False,
        verify_certs=False,
        ssl_show_warn=False,
    )
