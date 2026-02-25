# backend/service/known_brands_v3_service.py

import re
from typing import List, Dict, Optional
import Levenshtein
import tldextract
from opensearchpy import OpenSearch, NotFoundError
from opensearch_client import get_opensearch_client 

DEV = False

INDEX_KNOWN_BRANDS = "known_brands_v3"

def __get_client(dev=False) -> OpenSearch:
    if dev:
        return OpenSearch(
            hosts=[{"host": "localhost", "port": "9200"}],
            http_compress=True,
            use_ssl=False,
            verify_certs=False,
            ssl_show_warn=False,
        )
    return get_opensearch_client()

# ---------------------------------------------------------
# NORMALIZACIÓN Y UTILIDADES
# ---------------------------------------------------------

def _normalize_brand_id(s: str) -> str:
    s = (s or "").strip().lower()
    # nos quedamos solo con letras y números
    return re.sub(r"[^a-z0-9-]+", "", s)

def _normalize_visuals(text: str) -> str:
    """Sustituye caracteres visualmente similares (l33t speak) para mejorar el match."""
    replacements = {
        '4': 'a', '3': 'e', '1': 'i', '0': 'o', '5': 's', '7': 't', '8': 'b'
    }
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
    return text

def _normalize_domain_for_search(domain: str) -> str:
    """Extrae la parte principal del dominio y quita guiones para la búsqueda."""
    ext = tldextract.extract(domain)
    # Si entra 'pay-pal.es' -> devuelve 'paypal'
    # Si entra 'athetic-club' -> devuelve 'atheticclub'
    clean = ext.domain.lower().replace("-", "")
    return clean

def _tokenize_str(text: str) -> List[str]:
    if not text: return []
    text = re.sub(r"[^\w\s]", " ", text.lower())
    return [t for t in text.split() if t]

# ---------------------------------------------------------
# GESTIÓN DEL ÍNDICE (MAPPING V3)
# ---------------------------------------------------------

def ensure_known_brands_v3_index(dev=False) -> None:

    client = __get_client(dev)

    if client.indices.exists(index=INDEX_KNOWN_BRANDS):
        return

    body = {
        "settings": {
            "index": { "max_ngram_diff": 0 },
            "analysis": {
                "char_filter": {
                    "normalizacion_visual": {
                        "type": "mapping",
                        "mappings": [
                            "- => ",
                            "4 => a",
                            "3 => e",
                            "1 => i",
                            "0 => o",
                            "5 => s",
                            "7 => t",
                            "8 => b"
                        ]
                    }
                },
                "analyzer": {
                    "ana_2": { "tokenizer": "tok_2", "filter": ["lowercase"], "char_filter": ["normalizacion_visual"] },
                    "ana_3": { "tokenizer": "tok_3", "filter": ["lowercase"], "char_filter": ["normalizacion_visual"] },
                    "ana_4": { "tokenizer": "tok_4", "filter": ["lowercase"], "char_filter": ["normalizacion_visual"] }
                },
                "tokenizer": {
                    "tok_2": { "type": "ngram", "min_gram": 2, "max_gram": 2, "token_chars": ["letter", "digit"] },
                    "tok_3": { "type": "ngram", "min_gram": 3, "max_gram": 3, "token_chars": ["letter", "digit"] },
                    "tok_4": { "type": "ngram", "min_gram": 4, "max_gram": 4, "token_chars": ["letter", "digit"] }
                }
            }
        },
        "mappings": {
            "properties": {
                "sector": { "type": "keyword" },
                "known_domains": { "type": "keyword" },
                "owner_terms": { "type": "keyword" },
                "domain_search": {
                    "type": "text",
                    "fields": {
                        "2gram": { "type": "text", "analyzer": "ana_2", "norms": False, "similarity": "boolean" },
                        "3gram": { "type": "text", "analyzer": "ana_3", "norms": False, "similarity": "boolean" },
                        "4gram": { "type": "text", "analyzer": "ana_4", "norms": False, "similarity": "boolean" }
                    }
                }
            }
        }
    }
    client.indices.create(index=INDEX_KNOWN_BRANDS, body=body)

# ---------------------------------------------------------
# OPERACIONES DE ESCRITURA (UPSERT)
# ---------------------------------------------------------

def upsert_brand(
    brand_id: str,
    sector: str = "general",
    owner_terms: List[str] = "",
    known_domains: List[str] = None,
    dev=False
) -> None:
    """
    Crea o actualiza una brand completa con el NUEVO formato.
    """
    
    client = __get_client(dev)
    
    # El domain_search se nutre del brand_id automáticamente por el mapping
    payload = {
        "sector": sector,
        "owner_terms": owner_terms or [],
        "known_domains": known_domains or [],
        "domain_search": brand_id 
    }
    client.index(index=INDEX_KNOWN_BRANDS, id=brand_id, body=payload)

# ---------------------------------------------------------
# BÚSQUEDA AVANZADA (EL NÚCLEO V3)
# ---------------------------------------------------------

def _backup_fuzzy_match(client, clean_input):
    should_clauses = [
        {
            "match": {
                "domain_search": {
                    "query": clean_input,
                    "boost": 1,
                    "fuzziness": "AUTO"
                }
            }
        }
    ]
    body = {
        "size": 1,
        "query": {
            "bool": {
                "should": should_clauses,
                "minimum_should_match": 1
            }
        }
    }
    resp = client.search(index=INDEX_KNOWN_BRANDS, body=body)
    # Verificamos si hay hits antes de procesar
    hits = resp.get("hits", {}).get("hits", [])

    if not hits:
        return None
        
    match_doc = hits[0]

    distancia_real = Levenshtein.distance(clean_input, match_doc['_id'])

    return {
        **match_doc['_source'],
        "id": match_doc['_id'],
        "distancia": distancia_real,
        "match_type": "similarity"
    }

def find_brand_by_known_domain(domain: str, dev = DEV) -> Optional[Dict]:
    """
    ¿Este dominio ya pertenece a alguna brand?
    Búsqueda por coincidencia EXACTA sobre known_domains (keyword).
    """
    if dev:
        client = __get_client()
    else:
        client = get_opensearch_client()

    # normalizamos un poco el dominio de entrada
    domain = (domain or "").strip().lower().rstrip(".")

    resp = client.search(
        index=INDEX_KNOWN_BRANDS,
        body={
            "size": 1,
            "query": {
                "term": {
                    "known_domains": {
                        "value": domain
                    }
                }
            }
        }
    )

    hits = resp.get("hits", {}).get("hits", [])
    return hits[0] if hits else None

def identify_brand_by_similarity(domain_input: str, dev=False) -> Optional[Dict]:
    """
    Algoritmo de 2 capas:
    1. Filtro de n-gramas variable en OpenSearch.
    2. Refinamiento por distancia de Levenshtein.
    """

    client = __get_client(dev)
    
    # 1. Match Directo (Prioridad Máxima)
    try:
        clean_input = domain_input.split('.')[0].lower()
        res = client.get(index=INDEX_KNOWN_BRANDS, id=clean_input)
        return {**res['_source'], "id": res['_id'], "match_type": "exact"}
    except NotFoundError:
        pass

    # 2. Match por Similitud (Embudo)
    search_term_base = _normalize_domain_for_search(domain_input)
    search_term_visual = _normalize_visuals(search_term_base)

    longitud = len(search_term_visual)

    if longitud <= 5: 
        subcampo = "2gram"
        msm = "70%"
    else:
        subcampo = "3gram"
        msm = "45%"

    query = {
        "size": 30,
        "query": {
            "match": {
                f"domain_search.{subcampo}": {
                    "query": search_term_visual,
                    "minimum_should_match": msm,
                    "operator": "or"
                }
            }
        }
    }

    resp = client.search(index=INDEX_KNOWN_BRANDS, body=query)
    candidatos = resp['hits']['hits']

    # 3. CAPA 2: Refinamiento por Levenshtein
    if not candidatos:
        # 3.1: fuzzy match regular si no hay candidatos
        return _backup_fuzzy_match(client, clean_input)


    # 3.2: Refinamiento por Levenshtein (Usando la forma con guiones)
    mejor_match = None
    distancia_min = 99

    for c in candidatos:
        db_id = c['_id'] # 'athetic-club'
        dist = Levenshtein.distance(clean_input, db_id)
        
        if dist < distancia_min:
            distancia_min = dist
            mejor_match = c

    return {
        **mejor_match['_source'],
        "id": mejor_match['_id'],
        "distancia": distancia_min,
        "match_type": "similarity"
    }

# SIGUIENTE: mejorar este proceso
def guess_brand_from_whois(owner_str: str, max_results: int = 3, dev = False) -> List[Dict]:
    """
    Devuelve las marcas más probables en función del WHOIS owner.
    Pondera fuertemente 'keywords' y, si hay suficiente texto, también 'owner_terms'.
    """

    client = __get_client(dev)
    
    owner_str = (owner_str or "").strip()
    if not owner_str:
        return []

    tokens = owner_str.split()

    should_clauses = [
        {
            "match": {
                "domain_search": {
                    "query": owner_str,
                    "boost": 5,
                    "fuzziness": "AUTO"
                }
            }
        }
    ]

    if len(tokens) > 2:
        should_clauses.append({
            "match": {
                "owner_terms": {
                    "query": owner_str,
                    "boost": 1,
                    "fuzziness": "AUTO"
                }
            }
        })

    body = {
        "size": max_results,
        "query": {
            "bool": {
                "should": should_clauses,
                "minimum_should_match": 1
            }
        }
    }

    resp = client.search(index=INDEX_KNOWN_BRANDS, body=body)
    return resp["hits"]["hits"]

# ---------------------------------------------------------
# MANTENIMIENTO DE COLECCIONES
# ---------------------------------------------------------

def add_known_domain(brand_id: str, domain: str, dev = False) -> None:
    """
    Añade un dominio al array known_domains si no existe.
    """

    client = __get_client(dev)

    client.update(
        index=INDEX_KNOWN_BRANDS,
        id=brand_id,
        body={
            "script": {
                "source": """
                    if (ctx._source.known_domains == null) {
                        ctx._source.known_domains = [];
                    }
                    if (!ctx._source.known_domains.contains(params.domain)) {
                        ctx._source.known_domains.add(params.domain);
                    }
                """,
                "lang": "painless",
                "params": {"domain": domain}
            }
        }
    )

def add_owner_terms(brand_id: str, owner_str: str, dev = False) -> None:
    """
    Añade tokens de WHOIS al campo owner_terms SIN duplicados.
    owner_terms es la “bolsa de términos” que nutre el fuzzy.
    """
    
    client = __get_client(dev)

    # tokens nuevos (normalizados) que vienen del WHOIS actual
    new_tokens = _tokenize_str(owner_str)
    if not new_tokens:
        return

    try:
        doc = client.get(index=INDEX_KNOWN_BRANDS, id=brand_id)
        src = doc["_source"]
        existing_terms = src.get("owner_terms", "") or ""
    except NotFoundError:
        existing_terms = ""

    # tokens ya existentes en la brand (normalizados igual)
    if existing_terms:
        existing_tokens = _tokenize_str(existing_terms)
    else:
        existing_tokens = []

    # merge sin duplicados, preservando el orden “antiguos primero”
    seen = set()
    merged_tokens: List[str] = []
    for t in existing_tokens + new_tokens:
        if t not in seen:
            seen.add(t)
            merged_tokens.append(t)

    phrase = " ".join(merged_tokens)

    client.update(
        index=INDEX_KNOWN_BRANDS,
        id=brand_id,
        body={
            "doc": {
                "owner_terms": phrase
            }
        }
    )

def ensure_brand_for_root_domain(
    root_domain: str,
    owner_str: str,
    sector: Optional[str] = None,
    brand_id_hint: Optional[str] = None,
    dev = False
) -> str:
    """
    Garantiza que exista una brand para root_domain.
    - Si la brand NO existe → la crea (con root_domain en known_domains).
    - Si la brand YA existe → solo enriquece: known_domains + owner_terms.
    """

    client = __get_client(dev)

    ext = tldextract.extract(root_domain)

    base = brand_id_hint or ext.domain or root_domain
    brand_id = _normalize_brand_id(base)

    # ¿Ya existe la brand?
    try:
        client.get(index=INDEX_KNOWN_BRANDS, id=brand_id)
        # ➜ Brand existente: solo nutrimos
        add_known_domain(brand_id, root_domain, dev=dev)
        add_owner_terms(brand_id, owner_str, dev=dev)
        return brand_id

    except NotFoundError:
        # ➜ Brand nueva: creamos desde cero
        owner_tokens = _tokenize_str(owner_str)
        owner_terms = " ".join(owner_tokens)

        upsert_brand(
            brand_id = brand_id,
            sector = sector or None,
            owner_terms = owner_terms,
            known_domains = [root_domain],
            dev = dev
        )
        return brand_id