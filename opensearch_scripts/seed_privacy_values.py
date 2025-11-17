import os
from opensearchpy import OpenSearch

OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))
INDEX_PRIVACY_VALUES = "privacy_values"
DOC_ID_PRIVACY_VALUES = "whois_privacy_values"

PRIVACY_PATTERNS = [
    "redacted for privacy",
    "select request email form",
    "whois privacy",
    "privacy protect",
    "data protected",
    "contact privacy",
    "private registrant",
    "privacy corporation",
    "domain admin",
    "not disclosed",
]


def ensure_privacy_values_index(client: OpenSearch):
    if client.indices.exists(index=INDEX_PRIVACY_VALUES):
        print(f"[{INDEX_PRIVACY_VALUES}] Ya existe")
        return

    mapping = {
        "mappings": {
            "properties": {
                "config_key": {"type": "keyword"},
                "values": {"type": "keyword"}
            }
        }
    }

    client.indices.create(index=INDEX_PRIVACY_VALUES, body=mapping)
    print(f"[{INDEX_PRIVACY_VALUES}] Índice creado")


def upsert_privacy_values_doc(client: OpenSearch):
    doc = {
        "config_key": DOC_ID_PRIVACY_VALUES,
        "values": [p.lower().strip() for p in PRIVACY_PATTERNS]
    }

    client.index(
        index=INDEX_PRIVACY_VALUES,
        id=DOC_ID_PRIVACY_VALUES,
        body=doc
    )
    print(f"[+] Documento insertado en {INDEX_PRIVACY_VALUES}")


def main():
    print("Conectando a OpenSearch...")
    client = OpenSearch(
        hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
        http_compress=True
    )

    ensure_privacy_values_index(client)
    upsert_privacy_values_doc(client)

    print("\n✅ Seed de privacy_values completado.")


if __name__ == "__main__":
    main()
