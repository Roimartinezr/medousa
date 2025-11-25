#app/backend/scrap/service/scrap_owner_service.py

"""
En DESARROLLO: 
probar funcionamiento de la clase con: python -m backend.scrap.service.scrap_owner_service 
client = get_client()

En PRODUCCION:
client = get_opensearch_client()
"""
from opensearchpy import OpenSearch
INDEX_ASCII_CCTLD = "ascii_cctld"
INDEX_IDN_CCTLD = "idn_cctld"
def get_client() -> OpenSearch:
    return OpenSearch(
        hosts=[{"host": "localhost", "port": "9200"}],
        http_compress=True,
        use_ssl=False,
        verify_certs=False,
        ssl_show_warn=False,
    )


import tldextract
import whois
import json
import os
from datetime import datetime
from jsonschema import validate, ValidationError
from ...opensearch_client import get_opensearch_client
from ..scrap.whois_socket import whois_query

def normalize_value(value):
    # cadenas vacías → None
    if isinstance(value, str) and value.strip() == "":
        return None
    # datetime → string ISO
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def get_whois(domain):
    # estract tld from domain
    ext = tldextract.extract(domain)
    tld = ext.suffix.split('.')[-1]

    # verify if tld is punycode
    index = INDEX_ASCII_CCTLD
    if tld.startswith('xn--'):
        index = INDEX_IDN_CCTLD

    # load tld parser
    adapter_path = os.path.join(os.path.dirname(__file__), "..", "adapters", f"{tld}.json")
    adapter_path = os.path.abspath(adapter_path)
    schema_path = os.path.join(os.path.dirname(__file__), "..", "adapters", "schema", "whois_response.schema.json")

    with open(adapter_path, "r", encoding="utf-8") as f:
        parser = json.load(f)
    fields_map = parser["fields"]

    # load schema
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    # get tld BD's data
    #client = get_opensearch_client()
    client = get_client()
    doc = client.get(index=index, id=tld)
    src = doc["_source"]
    scraping_site = src.get("scraping_site", "") or ""

    # scrap
    if scraping_site == "whois":
        w = whois.whois(domain)
    elif scraping_site.startswith("whois.nic"):
        w = whois_query(domain=domain, server=scraping_site)
    else: 
        # aqui scrap por dondominio, whois-web, etc. (tengo que jsonear la respuesta de las paginas)
        w = None

    #w = json.loads(w)

    # parse response
    fields = {}
    for target_key, source_key in fields_map.items():
        if not isinstance(source_key, str) or not source_key:
            fields[target_key] = None
            continue

        value = getattr(w, source_key, None)
        if value is None and isinstance(w, dict) and source_key in w:
            value = w[source_key]

        fields[target_key] = normalize_value(value)


    country_map = parser.get("country_map", {})
    country = {}
    for target_key, source_key in country_map.items():
        if not isinstance(source_key, str) or not source_key:
            country[target_key] = None
            continue

        value = getattr(w, source_key, None)
        if value is None and isinstance(w, dict) and source_key in w:
            value = w[source_key]

        country[target_key] = normalize_value(value)

    parsed_response = {
        "tld": parser["tld"],
        "registry": parser.get("registry"),
        "country": country if country else None,
        "fields": fields
    }

    # validate with schema
    try:
        validate(instance=parsed_response, schema=schema)
        print("✅ WHOIS response is valid")
    except ValidationError as e:
        print("❌ WHOIS response is invalid:", e.message)
    
    #return normalized whois
    print(json.dumps(parsed_response, indent=4, ensure_ascii=False))

# MAPEAR LOS CAMPOS DE DATE A UNICO SRING de los adapters que lo necesitan

if __name__ == "__main__":
    get_whois("jprs.jp")