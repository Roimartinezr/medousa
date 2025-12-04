# -*- coding: utf-8 -*-
# seed_idn_cctld.py

from opensearchpy import OpenSearch
from opensearchpy.exceptions import NotFoundError

OPENSEARCH_HOST = "localhost"
OPENSEARCH_PORT = 9200
INDEX_NAME = "idn_cctld"


def get_client() -> OpenSearch:
    return OpenSearch(
        hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
        http_compress=True,
        timeout=30,
    )


IDN_CCTLD = {
    "xn--54b7fta0cc": {
        "punycode": "বাংলা",
        "country": "Bangladesh",
    },
    "xn--fiqs8s": {
        "punycode": "中国",
        "country": "China",
    },
    "xn--fiqz9s": {
        "punycode": "中國",
        "country": "China",
    },
    "xn--j1amh": {
        "punycode": "укр",
        "country": "Ukraine",
    },
    "xn--mgba3a4f16a": {
        "punycode": " ایران",
        "country": "Iran",
    },
    "xn--mgbaam7a8h": {
        "punycode": " المغرب",
        "country": "Morocco",
    },
    "xn--mgbah1a3hjkrd": {
        "punycode": " السعودية",
        "country": "Saudi Arabia",
    },
    "xn--mgbayh7gpa": {
        "punycode": " الاردن",
        "country": "Jordan",
    },
    "xn--mgbbh1a": {
        "punycode": " بھارت",
        "country": "India",
    },
    "xn--mgbbh1a71e": {
        "punycode": " بھارت",
        "country": "India (alt)",
    },
    "xn--mgbc0a9azcg": {
        "punycode": " پاکستان",
        "country": "Pakistan",
    },
    "xn--mgbtx2b": {
        "punycode":" عمان",
        "country": "Oman",
    },
    "xn--mgbx4cd0ab": {
        "punycode": " فلسطين",
        "country": "Palestine",
    },
    "xn--node": {
        "punycode": "გე",
        "country": "Georgia",
    },
    "xn--ogbpf8fl": {
        "punycode": " مصر",
        "country": "Egypt",
    },
    "xn--p1acf": {
        "punycode": "рус",
        "country": "Russia",
    },
    "xn--p1ai": {
        "punycode": "рф",
        "country": "Russia",
    },
    "xn--qxa6a": {
        "punycode": "δοκιμή",
        "country": "Greece (test)",
    },
    "xn--qxam": {
        "punycode": "ελ",
        "country": "Greece",
    },
    "xn--wgbh1c": {
        "punycode":" قطر",
        "country": "Qatar",
    },
    "xn--yfro4i67o": {
        "punycode": "新加坡",
        "country": "Singapore",
    },
    "xn--ygbi2ammx": {
        "punycode":" فلسطين",
        "country": "Palestine (alt)",
    },
}


def main():
    client = get_client()
    print("Conectando a OpenSearch en localhost:9200")

    # Borrar índice si existe
    try:
        client.indices.delete(index=INDEX_NAME)
        print(f"Índice {INDEX_NAME} eliminado")
    except NotFoundError:
        print(f"Índice {INDEX_NAME} no existe, se creará nuevo")

    mapping = {
        "mappings": {
            "properties": {
                # ya NO hay campo tld aquí
                "punycode": {"type": "keyword"},   # ".বাংলা", ".中国", etc. (U-label)
                "country": {"type": "text"},
                "scraping_site": {"type": "keyword"},
            }
        }
    }

    client.indices.create(index=INDEX_NAME, body=mapping)
    print(f"Índice {INDEX_NAME} creado")

    # Insertar documentos: id = "xn--..." (sin el punto inicial)
    for a_label, data in IDN_CCTLD.items():
        doc_id = a_label  # ej: "xn--54b7fta0cc"
        body = {
            "punycode": data["punycode"],     # ej: ".বাংলা"
            "country": data["country"],
            "scraping_site": "",
        }
        client.index(index=INDEX_NAME, id=doc_id, body=body)

    print("Insertados todos los IDN ccTLD.")


if __name__ == "__main__":
    main()
