# app/services/domain_sanitizer_service/email_utils.py
import re
from typing import Dict
from email_validator import validate_email, caching_resolver, EmailNotValidError
import tldextract
from ...scrap.dondominio import DonDominioAsync, get_owner_via_whois
from ..known_brands_service import guess_brand_from_whois
from ..omit_words_service import get_all_omit_words
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

# ========================= COMPANY DETECTION ==========================
# checks if mail is a real direction
def validate_mail(mail):
    try:
        resolver = caching_resolver(timeout=10)

        emailinfo = validate_email(mail, dns_resolver=resolver, check_deliverability=True)
        email = emailinfo.normalized
        return email

    except EmailNotValidError as e:
        print(f"Invalid email: {str(e)}")
        return None

def extract_domain_from_email(email):
    """
    Extracts the domain from an email.
    Example: user@example.com -> example.com
    """
    try:
        return email.split('@')[1].lower()
    except IndexError:
        return None


def extract_company_from_domain(domain: str) -> Dict:
    """
    Intenta identificar una empresa basándose en el dominio usando:
    - tokenización (incluyendo guiones)
    - eliminación de omit_words
    - fuzzy match contra brand_keywords + owner_terms en OpenSearch
    """
    ext = tldextract.extract(domain)

    tokens = []

    def _split_tokens(raw: str):
        # separamos por puntos y guiones
        for part in raw.replace("-", ".").split("."):
            p = part.strip().lower()
            if p:
                tokens.append(p)

    # extraer partes relevantes del dominio
    if ext.subdomain and ext.subdomain != "www":
        _split_tokens(ext.subdomain)

    if ext.domain:
        _split_tokens(ext.domain)

    # limpiar omit words (mail, info, emailing, etc.)
    filtered = [t for t in tokens if not _is_omit_word(t)]

    # si después de filtrar no queda nada, usamos el dominio base sin sufijos tipo "-mail"
    if not filtered:
        base = ext.domain or ""
        if "-" in base:
            base = base.split("-")[0]
        base = base.strip().lower()
        filtered = [base] if base else []

    # cadena candidata para buscar en OpenSearch
    if filtered:
        candidate_str = " ".join(filtered)
    else:
        candidate_str = ext.domain or domain

    # Fuzzy match contra las brands en OpenSearch (owner_terms + brand_keywords)
    try:
        candidates = guess_brand_from_whois(candidate_str)
    except Exception:
        candidates = []

    if candidates:
        best = candidates[0]
        brand_id = best["_id"]
        score = best["_score"]
        confidence = min(1.0, score / 10.0)   # normalización arbitraria
    else:
        # sin match en OpenSearch: usamos el último token
        if filtered:
            brand_id = filtered[-1]
        else:
            brand_id = ext.domain or domain
        confidence = 0.0

    return {
        "company": brand_id,
        "confidence": confidence,
        "candidate_text": candidate_str,
    }



# ========================= DOMAIN LEGITMACY ===========================

async def get_domain_owner(domain: str) -> str:
    logger.debug(f"Fetching owner for domain: {domain}")
    """
    Devuelve el titular del dominio (.es o .com).
    Si el dominio .com tiene privacidad (REDACTED), intenta obtener el .es equivalente.
    """
    async with DonDominioAsync(debug=False) as api:
        owner = await get_owner_via_whois(api, domain)
        return owner or "No encontrado"

