# app/backend/service/utils/reecognition.py

from typing import Dict
import tldextract
from service.known_brands_v3_service import identify_brand_by_similarity
from service.omit_words_service import get_all_omit_words
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

OMIT_WORDS_CACHE = set()
OMIT_WORDS_LOADED = False


def _load_omit_words_cache():
    """
    Carga las omit_words desde OpenSearch solo una vez.
    Si no se puede conectar, deja el set vacío y no rompe el arranque.
    """
    global OMIT_WORDS_CACHE, OMIT_WORDS_LOADED
    if OMIT_WORDS_LOADED:
        return

    try:
        words = get_all_omit_words()
        OMIT_WORDS_CACHE = set(words)
        OMIT_WORDS_LOADED = True
    except Exception as e:
        # Aquí podrías loguear si quieres, pero NO rompas el arranque
        # print(f"[WARN] No se pudieron cargar omit_words: {e}")
        OMIT_WORDS_CACHE = set()
        OMIT_WORDS_LOADED = True  # marcamos como "intentado" para no buclear

def _is_omit_word(word: str) -> bool:
    if not OMIT_WORDS_LOADED:
        _load_omit_words_cache()
    return word in OMIT_WORDS_CACHE

def extract_company_from_domain(domain: str) -> Dict:
    """
    Identifica una empresa filtrando primero el ruido (omit_words) 
    y luego usando la lógica de similitud V3.
    """
    ext = tldextract.extract(domain)
    subd_tokens = []
    tokens = []

    def _split_tokens(raw: str, sub=False):
        # Separar por puntos y guiones para identificar términos individuales
        for part in raw.replace("-", ".").split("."):
            p = part.strip().lower()
            if p:
                if sub:
                    subd_tokens.append(p)
                else:
                    tokens.append(p)

    # 1. Extraer partes del dominio (subdominio + dominio base)
    if ext.subdomain and ext.subdomain != "www":
        _split_tokens(ext.subdomain, sub=True)
    if ext.domain:
        _split_tokens(ext.domain)

    # 2. Filtrar omit words (mail, info, emailing, etc.)
    filtered = [t for t in tokens if not _is_omit_word(t)]
    filtered += [t for t in tokens if t not in filtered and not _is_omit_word(t)]

    # Si después de filtrar no queda nada, usamos el dominio base como fallback
    if not filtered:
        base = ext.domain or domain
        candidate_str = base.strip().lower()
    else:
        # Reconstruimos la cadena candidata sin el "ruido"
        # Ejemplo: 'mail-santander' -> 'santander'
        candidate_str = "-".join(filtered)

    # 3. Llamada al motor V3 con el candidato ya limpio
    brand_data = identify_brand_by_similarity(candidate_str)

    return brand_data or None

if __name__ == "__main__":
    #print(asyncio.run(get_domain_owner("athletic-club.eus")))
    print(extract_company_from_domain("emailing.b4ncosntand3r-mail.eus"))