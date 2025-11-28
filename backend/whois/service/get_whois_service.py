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
import importlib
import os
import logging
import asyncio
from datetime import datetime
from typing import Optional
from jsonschema import validate, ValidationError
from ...opensearch_client import get_opensearch_client
from ..scrap.whois_socket import whois_query

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

DATE_KEYS = {"creation_date", "expiration_date", "updated_date"}
# Reglas específicas para TLD .ua
UA_MULTI_VALUE_TLD = "ua"
UA_SENTINELS = {"n/a", "not published"}

def _ua_resolve_multi_source_field(source_key: str, w: dict) -> Optional[str]:
    """
    Para TLD .ua, permite expresiones del tipo:
        'a | b | c'
    y devuelve:
        - CSV con valores únicos
        - filtrando sentinels ('n/a', 'not published')
        - aplanando listas
        - normalizando datetime → string
    """
    if "|" not in source_key:
        return None  # no es multi-source

    candidates = [p.strip() for p in source_key.split("|") if p.strip()]
    collected = []

    for candidate in candidates:
        v = getattr(w, candidate, None)
        if v is None and isinstance(w, dict) and candidate in w:
            v = w[candidate]
        if v is None:
            continue

        # Aplana listas/tuplas/sets
        if isinstance(v, (list, tuple, set)):
            collected.extend(v)
        else:
            collected.append(v)

    cleaned = []
    seen = set()

    for v in collected:
        if v is None:
            continue

        # Normalizar datetime
        if isinstance(v, datetime):
            v = v.isoformat()

        v_str = str(v).strip()
        if not v_str:
            continue

        # Filtrar valores vacíos para Hostmaster.ua
        if v_str.lower() in UA_SENTINELS:
            continue

        if v_str in seen:
            continue

        seen.add(v_str)
        cleaned.append(v_str)

    return ", ".join(cleaned) if cleaned else None

def _normalize_date(value, mode="first"):
    """
    Convierte listas de fechas o datetime a string ISO.
    mode puede ser 'first' o 'last'.
    """
    if value is None:
        return None

    # Si es lista de fechas
    if isinstance(value, (list, tuple)):
        if not value:
            return None
        if mode == "first":
            value = value[0]
        elif mode == "last":
            value = value[-1]

    # Si es datetime → string ISO
    if isinstance(value, datetime):
        return value.isoformat()

    # Si es string → return tal cual
    if isinstance(value, str):
        return value.strip() or None

    return str(value)

def _normalize_value(value, mode="first"):
    if value is None:
        return None

    # cadenas vacías → None
    if isinstance(value, str) and value.strip() == "":
        return None
    
    # datetime → string ISO
    if isinstance(value, datetime):
        return value.isoformat()
    return value


async def get_whois(domain):
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
    elif scraping_site.startswith("whois."):
        w = whois_query(domain=domain, server=scraping_site)
    else: 
        # scrap dinámico desde scrap/<scraping_site>.py
        try:
            mod_name = f"backend.whois.scrap.{scraping_site}"
            scrap_module = importlib.import_module(mod_name)
            w = await scrap_module.main(domain)
        except Exception as e:
            logger.warning(f"[scrap fallback] error al cargar módulo '{scraping_site}': {e}")
            w = None

    # parse response
    fields = {}
    for target_key, source_key in fields_map.items():
         # Caso especial: (fechas first/last)
        if isinstance(source_key, dict):
            src = source_key.get("source")
            norm = source_key.get("normalize", "first")
            value = getattr(w, src, None)
            if value is None and isinstance(w, dict) and src in w:
                value = w[src]
            fields[target_key] = _normalize_date(value, mode=norm)
            continue

        # Caso normal: mapeo inválido → None
        if not isinstance(source_key, str) or not source_key:
            fields[target_key] = None
            continue

        # Obtención del valor (atributo o clave de dict)
        value = getattr(w, source_key, None)
        if value is None and isinstance(w, dict) and source_key in w:
            value = w[source_key]

        # --- ESPECIAL .ua: expresión multi-source "a | b | c" ---
        if tld == UA_MULTI_VALUE_TLD and isinstance(source_key, str) and "|" in source_key:
            value = _ua_resolve_multi_source_field(source_key, w)
        else:
            # comportamiento normal
            value = getattr(w, source_key, None)
            if value is None and isinstance(w, dict) and source_key in w:
                value = w[source_key]

        # Caso específico: registrant_name ← person (solo aquí concatenamos arrays) (caso .br)
        if target_key == "registrant_name" and source_key == "person":
            if isinstance(value, (list, tuple)) and all(isinstance(v, str) for v in value):
                value = ", ".join(v.strip() for v in value if v and v.strip())

        # Si es campo de fecha pero definido como string en el adapter
        if target_key in DATE_KEYS:
            # por defecto usa "first"
            fields[target_key] = _normalize_date(value, mode="first")
            continue

        fields[target_key] = _normalize_value(value)


    country_map = parser.get("country", {})
    country = {}
    for target_key, source_key in country_map.items():
        if not isinstance(source_key, str) or not source_key:
            country[target_key] = None
            continue

        value = getattr(w, source_key, None)
        if value is None and isinstance(w, dict) and source_key in w:
            value = w[source_key]

        country[target_key] = _normalize_value(value)

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
    return parsed_response

if __name__ == "__main__":
    asyncio.run(get_whois("santen.eu"))