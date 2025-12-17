# app/backend/service/utils/email_utils.py
from opensearchpy import OpenSearch
import asyncio
from typing import Dict
from email_validator import validate_email, caching_resolver, EmailNotValidError
import tldextract
from ...whoare.service.service import WhoareService
from ..known_brands_service import guess_brand_from_whois
from ..omit_words_service import get_all_omit_words
from ..ascii_cctld_service import get_fallback_by_id
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

def _is_privacy_value(word: str) -> bool:
    privacy_keywords = ["redacted", "privacy", "whoisguard", "protected", "gdpr"]
    word_lower = str(word).lower()
    is_private = any(keyword in word_lower for keyword in privacy_keywords)
    if not is_private:
        return False
    return True

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
    """
    Devuelve el titular del dominio.
    """
    domain = (domain or "").strip().lower()
    logger.debug(f"Fetching owner for domain: {domain}")

    if not domain:
        return "No encontrado"

    ext = tldextract.extract(domain)

    # Dominio raíz normalizado (por si te pasan subdominios)
    if ext.domain and ext.suffix:
        root_domain = f"{ext.domain}.{ext.suffix}".lower()
    else:
        root_domain = domain

    whoare_doc = await WhoareService.whoare(root_domain)
    # DIVERSIFICACION

    # gTLDs
    if whoare_doc and whoare_doc.get("gTLD") == "true":
        # Validar privacidad del owner
        org_candidate = whoare_doc.get("org")
        name_candidate = whoare_doc.get("name")
        # Limpieza: A veces python-whois devuelve listas ['Name', 'Name']
        if isinstance(org_candidate, list):
            org_candidate = org_candidate[0]
        if isinstance(name_candidate, list):
            name_candidate = name_candidate[0]


        registrant_org = None
        if org_candidate and not _is_privacy_value(org_candidate):
            registrant_org = org_candidate
        registrant_name = None
        if name_candidate and not _is_privacy_value(name_candidate):
            registrant_name = name_candidate

        # Si no hay owner, fallback a .country_code
        if not registrant_org and not registrant_name:
            country = whoare_doc.get("country").lower()
            fallback_domain = f"{ext.domain}.{country}".lower()
            registrant = await get_domain_owner(fallback_domain)

            return registrant
        else:
            if registrant_org:
                return registrant_org
            elif registrant_name:
                return registrant_name
            else:
                return None

    # ccTLDs
    elif whoare_doc:
        fields = whoare_doc.get("fields")

        registrant_candidate = fields.get("registrant")
        registrant_name_candidate = fields.get("registrant_name")

        registrant = None
        if registrant_candidate and not _is_privacy_value(registrant_candidate):
            registrant = registrant_candidate
        registrant_name = None
        if registrant_name_candidate and not _is_privacy_value(registrant_name_candidate):
            registrant_name = registrant_name_candidate

        # fallback
        if not registrant and not registrant_name:
            tld = ext.suffix.split('.')[-1]

            # pseudo gTLD 1st fallback
            country = whoare_doc.get("country")
            if country:
                code, state, city = country
                if code:
                    fallback_domain = f"{ext.domain}.{code.strip()}".lower()

                    registrant = await get_domain_owner(fallback_domain)
                    if registrant:
                        return registrant

            # DESAROLLO:
            # fallback = get_fallback_by_id(tld, _get_client())
            fallback = get_fallback_by_id(tld)
            fallback_domain = None
            if fallback:
                for cc in fallback:
                    fallback_domain = f"{ext.domain}.{cc}".lower()
                    registrant = await get_domain_owner(fallback_domain)

                    if registrant:
                        break
            else:
                return None  
            
            return registrant

        else:
            if registrant:
                return registrant
            elif registrant_name:
                return registrant_name
            else:
                return None

    return None


def _get_client() -> OpenSearch:
        return OpenSearch(
            hosts=[{"host": "localhost", "port": "9200"}],
            http_compress=True,
            use_ssl=False,
            verify_certs=False,
            ssl_show_warn=False,
        )
if __name__ == "__main__":
    print(asyncio.run(get_domain_owner("bancosantander.com")))