import os
import time
import logging
from opensearchpy import OpenSearch

logger = logging.getLogger(__name__)

def get_opensearch_client(retries: int = None, backoff_seconds: int = None) -> OpenSearch:
    """Return an OpenSearch client and wait for the cluster to be reachable.

    Retries and backoff can be configured via env vars:
      OPENSEARCH_WAIT_RETRIES (default 12)
      OPENSEARCH_WAIT_BACKOFF (default 2)
    """
    host = os.getenv("OPENSEARCH_HOST", "opensearch")
    port = int(os.getenv("OPENSEARCH_PORT", "9200"))

    retries = retries if retries is not None else int(os.getenv("OPENSEARCH_WAIT_RETRIES", "12"))
    backoff_seconds = backoff_seconds if backoff_seconds is not None else int(os.getenv("OPENSEARCH_WAIT_BACKOFF", "2"))

    client = OpenSearch(
        hosts=[{"host": host, "port": port}],
        http_compress=True,
        use_ssl=False,
        verify_certs=False,
        ssl_show_warn=False,
    )

    attempt = 0
    while True:
        try:
            attempt += 1
            logger.debug(f"Pinging OpenSearch (attempt {attempt}/{retries}) at {host}:{port}")
            if client.ping():
                logger.info("Connected to OpenSearch")
                return client
            else:
                raise RuntimeError("OpenSearch ping returned False")
        except Exception as exc:
            logger.warning(f"OpenSearch not available yet: {exc}")
            if attempt >= retries:
                logger.error(f"Could not connect to OpenSearch after {retries} attempts")
                raise
            sleep_time = backoff_seconds * attempt
            time.sleep(sleep_time)

