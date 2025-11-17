# backend/service/known_brands_service.py

from typing import List, Dict, Optional
import re

from opensearchpy import OpenSearch, NotFoundError
from ..opensearch_client import get_opensearch_client
import tldextract

INDEX_KNOWN_BRANDS = "known_brands"


# ---------------------------------------------------------
# AUX: Normalización simple para WHOIS owners
# ---------------------------------------------------------

def tokenize_owner_str(owner: str) -> List[str]:
    """
    Normaliza un owner WHOIS y lo tokeniza:
    - minúsculas
    - quitar puntuación
    - separar por espacios
    """
    if not owner:
        return []

    owner = owner.lower()
    owner = re.sub(r"[^\w\s]", " ", owner)  # quitar puntuación
    owner = re.sub(r"\s+", " ", owner).strip()

    return owner.split(" ")


# ---------------------------------------------------------
# CREACION DE ÍNDICE
# ---------------------------------------------------------

def ensure_known_brands_index() -> None:
    """
    Crea el índice 'known_brands' si no existe.
    Nuevo formato por documento:

    {
      "_id": "<brand_id>",
      "country_code": "es",
      "owner_terms": "banco bilbao vizcaya argentaria sa s a",
      "keywords": ["bbva", "bilbao", "vizcaya", "argentaria"],
      "known_domains": ["bbva.es", "bbva.com"]
    }
    """
    client: OpenSearch = get_opensearch_client()
    if client.indices.exists(INDEX_KNOWN_BRANDS):
        return

    body = {
        "settings": {
            "analysis": {
                "analyzer": {
                    "owner_analyzer": {
                        "tokenizer": "standard",
                        "filter": ["lowercase", "asciifolding"]
                    }
                }
            }
        },
        "mappings": {
            "properties": {
                # Código de país (ccTLD) cuando aplique, p.e. "es"
                "country_code": {"type": "keyword"},

                # Bolsa de palabras WHOIS (banco/bilbao/vizcaya/argentaria/sa...)
                "owner_terms": {
                    "type": "text",
                    "analyzer": "owner_analyzer"
                },

                # Palabras clave de la marca (bbva, bilbao, vizcaya...)
                "keywords": {
                    "type": "text",
                    "analyzer": "owner_analyzer"
                },

                # Lista de dominios ya detectados/validados
                "known_domains": {
                    "type": "keyword"
                }
            }
        }
    }

    client.indices.create(index=INDEX_KNOWN_BRANDS, body=body)


# ---------------------------------------------------------
# UPSERT DE MARCA (crear o actualizar)
# ---------------------------------------------------------

def upsert_brand(
    brand_id: str,
    country_code: str,
    keywords: List[str],
    owner_terms: Optional[str] = "",
    known_domains: Optional[List[str]] = None,
) -> None:
    """
    Crea o actualiza una brand completa con el NUEVO formato.
    Ideal para inicializar tus marcas base (bbva, abanca, santander...).

    _id = brand_id
    _source = {
      "country_code": "...",
      "owner_terms": "...",
      "keywords": [...],
      "known_domains": [...]
    }
    """
    client = get_opensearch_client()

    doc_id = brand_id  # usamos brand_id como _id lógico

    payload = {
        "country_code": country_code or "",
        "owner_terms": owner_terms or "",
        "keywords": keywords or [],
        "known_domains": known_domains or [],
    }

    client.index(index=INDEX_KNOWN_BRANDS, id=doc_id, body=payload)


# ---------------------------------------------------------
# Añadir dominio conocido
# ---------------------------------------------------------

def add_known_domain(brand_id: str, domain: str) -> None:
    """
    Añade un dominio al array known_domains si no existe.
    """
    client = get_opensearch_client()

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


def add_keyword(brand_id: str, keyword: str) -> None:
    """
    Añade un token al array keywords si no existe.
    """
    client = get_opensearch_client()

    client.update(
        index=INDEX_KNOWN_BRANDS,
        id=brand_id,
        body={
            "script": {
                "source": """
                    if (ctx._source.keywords == null) {
                        ctx._source.keywords = [];
                    }
                    if (!ctx._source.keywords.contains(params.keyword)) {
                        ctx._source.keywords.add(params.keyword);
                    }
                """,
                "lang": "painless",
                "params": {"keyword": keyword}
            }
        }
    )


# ---------------------------------------------------------
# Añadir owner_terms
# ---------------------------------------------------------

def add_owner_terms(brand_id: str, owner_str: str) -> None:
    """
    Añade tokens de WHOIS al campo owner_terms SIN duplicados.
    owner_terms es la “bolsa de términos” que nutre el fuzzy.
    """
    client = get_opensearch_client()

    # tokens nuevos (normalizados) que vienen del WHOIS actual
    new_tokens = tokenize_owner_str(owner_str)
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
        existing_tokens = tokenize_owner_str(existing_terms)
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


# ---------------------------------------------------------
# Fuzzy match WHOIS -> brand
# ---------------------------------------------------------

def guess_brand_from_whois(owner_str: str, max_results: int = 3) -> List[Dict]:
    """
    Devuelve las marcas más probables en función del WHOIS owner.
    Pondera fuertemente 'keywords' y, si hay suficiente texto, también 'owner_terms'.
    """
    client = get_opensearch_client()
    owner_str = (owner_str or "").strip()
    if not owner_str:
        return []

    tokens = owner_str.split()

    should_clauses = [
        {
            "match": {
                "keywords": {
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
# Consulta directa por dominio conocido
# ---------------------------------------------------------

def find_brand_by_known_domain(domain: str) -> Optional[Dict]:
    """
    ¿Este dominio ya pertenece a alguna brand?
    Búsqueda por coincidencia EXACTA sobre known_domains (keyword).
    """
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


def find_brand_by_keywords(domain: str) -> Optional[Dict]:
    """
    Busca una brand cuyo campo 'keywords' tenga similitud con el dominio.
    Devuelve el documento completo si hay coincidencias.
    """
    client = get_opensearch_client()
    resp = client.search(
        index=INDEX_KNOWN_BRANDS,
        body={
            "size": 1,
            "query": {
                "match": {
                    "keywords": {
                        "query": domain,
                        "fuzziness": "AUTO"
                    }
                }
            }
        }
    )
    hits = resp.get("hits", {}).get("hits", [])
    return hits[0] if hits else None


def _normalize_brand_id(s: str) -> str:
    s = (s or "").strip().lower()
    # nos quedamos solo con letras y números
    return re.sub(r"[^a-z0-9]+", "", s)


def ensure_brand_for_root_domain(
    root_domain: str,
    owner_str: str,
    brand_id_hint: Optional[str] = None,
) -> str:
    """
    Garantiza que exista una brand para root_domain.
    - Si la brand NO existe → la crea (con root_domain en known_domains).
    - Si la brand YA existe → solo enriquece: known_domains + owner_terms.
    """
    client = get_opensearch_client()
    ext = tldextract.extract(root_domain)

    base = brand_id_hint or ext.domain or root_domain
    brand_id = _normalize_brand_id(base)

    # ¿Ya existe la brand?
    try:
        client.get(index=INDEX_KNOWN_BRANDS, id=brand_id)
        # ➜ Brand existente: solo nutrimos, no tocamos country_code
        add_known_domain(brand_id, root_domain)
        add_owner_terms(brand_id, owner_str)
        return brand_id

    except NotFoundError:
        # ➜ Brand nueva: creamos desde cero
        suffix = ext.suffix or ""
        country_code = suffix.lower()
        # si no es un ccTLD de 2 letras, lo dejamos vacío
        if len(country_code) != 2:
            country_code = ""

        tokens = tokenize_owner_str(owner_str)
        owner_terms = " ".join(tokens)

        # Keywords por defecto: el brand_id/base
        keywords = [brand_id]

        upsert_brand(
            brand_id=brand_id,
            country_code=country_code,
            keywords=keywords,
            owner_terms=owner_terms,
            known_domains=[root_domain],
        )

        return brand_id
