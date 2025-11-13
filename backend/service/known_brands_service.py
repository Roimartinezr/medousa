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
    Index de un documento por brand.
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
                # ID lógico de la brand en tu sistema
                "brand_id": {"type": "keyword"},

                # Dominio principal canónico (bancosantander.com)
                "canonical_domain": {"type": "keyword"},
                "canonical_tld": {"type": "keyword"},

                # Palabras clave muy distintivas (alto peso)
                "brand_keywords": {
                    "type": "text",
                    "analyzer": "owner_analyzer"
                },

                # Bolsa de palabras WHOIS (banco/santander/mexico/sa...)
                "owner_terms": {
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
    canonical_domain: str,
    canonical_tld: str,
    brand_keywords: List[str],
    owner_terms: Optional[str] = "",
    known_domains: Optional[List[str]] = None,
):
    """
    Crea o actualiza una brand completa.
    Ideal para inicializar tus marcas base
    (bbva, abanca, santander...).
    """
    client = get_opensearch_client()

    doc_id = brand_id  # usamos brand_id como _id

    payload = {
        "brand_id": brand_id,
        "canonical_domain": canonical_domain,
        "canonical_tld": canonical_tld,
        "brand_keywords": " ".join(brand_keywords),
        "owner_terms": owner_terms or "",
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
    Pondera fuertemente brand_keywords.
    """
    client = get_opensearch_client()

    body = {
        "size": max_results,
        "query": {
            "multi_match": {
                "query": owner_str,
                "fields": [
                    "brand_keywords^3",  # peso alto
                    "owner_terms"        # peso normal
                ],
                "fuzziness": "AUTO"
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

def find_brand_by_canonical_domain(domain: str) -> Optional[Dict]:
    """
    Busca una brand cuyo canonical_domain sea exactamente 'domain'.
    """
    client = get_opensearch_client()
    resp = client.search(
        index=INDEX_KNOWN_BRANDS,
        body={
            "size": 1,
            "query": {
                "term": {
                    "canonical_domain": domain
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
    - Si la brand NO existe → la crea (con ese root_domain como canónico).
    - Si la brand YA existe → NO toca canonical_domain/canonical_tld,
      solo enriquece: known_domains + owner_terms.
    """
    client = get_opensearch_client()
    ext = tldextract.extract(root_domain)

    base = brand_id_hint or ext.domain or root_domain
    brand_id = _normalize_brand_id(base)

    # ¿Ya existe la brand?
    try:
        doc = client.get(index=INDEX_KNOWN_BRANDS, id=brand_id)
        # ➜ Brand existente: solo nutrimos, no pisamos el canónico
        add_known_domain(brand_id, root_domain)
        add_owner_terms(brand_id, owner_str)
        return brand_id

    except NotFoundError:
        # ➜ Brand nueva: creamos canónico desde cero
        tld = ext.suffix or ""
        tokens = tokenize_owner_str(owner_str)
        owner_terms = " ".join(tokens)

        # Keywords más potentes: por defecto el brand_id/base
        brand_keywords = [brand_id]

        upsert_brand(
            brand_id=brand_id,
            canonical_domain=root_domain,
            canonical_tld=tld,
            brand_keywords=brand_keywords,
            owner_terms=owner_terms,
            known_domains=[root_domain],
        )

        return brand_id