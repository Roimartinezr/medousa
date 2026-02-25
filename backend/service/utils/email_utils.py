# app/backend/service/utils/email_utils.py
import asyncio
import re
from typing import Dict
from email_validator import validate_email, caching_resolver, EmailNotValidError
import tldextract
from whoare.service.service import WhoareService
from service.known_brands_v3_service import identify_brand_by_similarity
from service.omit_words_service import get_all_omit_words
from service.ascii_cctld_service import get_fallback_by_id
from service.ascii_geotld_service import get_country_by_id
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

OMIT_WORDS_CACHE = set()
OMIT_WORDS_LOADED = False

# PRODUCCION / DESARROLLO
DEV = False

def _load_omit_words_cache(dev = DEV):
    """
    Carga las omit_words desde OpenSearch solo una vez.
    Si no se puede conectar, deja el set vacío y no rompe el arranque.
    """
    global OMIT_WORDS_CACHE, OMIT_WORDS_LOADED
    if OMIT_WORDS_LOADED:
        return

    try:
        words = get_all_omit_words(dev=dev)
        OMIT_WORDS_CACHE = set(words)
        OMIT_WORDS_LOADED = True
    except Exception as e:
        # Aquí podrías loguear si quieres, pero NO rompas el arranque
        # print(f"[WARN] No se pudieron cargar omit_words: {e}")
        OMIT_WORDS_CACHE = set()
        OMIT_WORDS_LOADED = True  # marcamos como "intentado" para no buclear

def _is_omit_word(word: str, dev = DEV) -> bool:
    if not OMIT_WORDS_LOADED:
        _load_omit_words_cache(dev)
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

        emailinfo = validate_email(mail, dns_resolver=resolver, check_deliverability=False)
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

def extract_company_from_domain(domain: str, dev=DEV) -> Dict:
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
    filtered = [t for t in tokens if not _is_omit_word(t, dev=dev)]
    filtered += [t for t in tokens if t not in filtered and not _is_omit_word(t, dev=dev)]

    # Si después de filtrar no queda nada, usamos el dominio base como fallback
    if not filtered:
        base = ext.domain or domain
        candidate_str = base.strip().lower()
    else:
        # Reconstruimos la cadena candidata sin el "ruido"
        # Ejemplo: 'mail-santander' -> 'santander'
        candidate_str = "-".join(filtered)

    # 3. Llamada al motor V3 con el candidato ya limpio
    brand_data = identify_brand_by_similarity(candidate_str, dev=dev)

    if brand_data:
        brand_id = brand_data["id"]
        # Confianza basada en la distancia de Levenshtein calculada en V3
        dist = brand_data.get("distancia", 0)
        print("dist: ", dist)
        
        if brand_data.get("match_type") == "exact":
            confidence = 1.0
        else:
            # Penalizamos la confianza según la distancia visual
            confidence = max(0.0, 1.0 - (dist * 0.15))
            
        sector = brand_data.get("sector", "general")
    else:
        # Si no hay match en OpenSearch, devolvemos el candidato filtrado
        brand_id = candidate_str
        confidence = 0.0
        sector = None

    return {
        "company": brand_id,
        "confidence": round(confidence, 2),
        "candidate_text": candidate_str,
        "sector": sector,
        "match_type": brand_data.get("match_type") if brand_data else "none"
    }

# ========================= DOMAIN LEGITMACY ===========================

async def get_domain_owner(domain: str, dev = DEV) -> str:
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

    whoare_doc = await WhoareService.whoare(root_domain, dev=dev)

    # DIVERSIFICACION:
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
            fallback_domain = f"{ext.domain}.{country.strip()}".lower()
            registrant = await get_domain_owner(fallback_domain, dev=dev)
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
        registrant_name = None
        if registrant_candidate and not _is_privacy_value(registrant_candidate):
            registrant = registrant_candidate
        if registrant_name_candidate and not _is_privacy_value(registrant_name_candidate):
            registrant_name = registrant_name_candidate
        
        # fallback
        if not registrant and not registrant_name:
            tld = ext.suffix.split('.')[-1]
            geoTLD = whoare_doc.get("geoTLD")

            # if it's a geoTLD
            if geoTLD:
                country = get_country_by_id(tld, dev=dev)
                if country:
                    fallback_domain = f"{ext.domain}.{country.strip()}".lower()
                    registrant = await get_domain_owner(fallback_domain, dev=dev)
                    if registrant:
                        return registrant
                return None

            else:
                # pseudo gTLD 1st fallback
                country = whoare_doc.get("country")
                if country:
                    code, state, city = country
                    if code:
                        fallback_domain = f"{ext.domain}.{code.strip()}".lower()

                        registrant = await get_domain_owner(fallback_domain, dev=dev)
                        if registrant:
                            return registrant

                fallback = get_fallback_by_id(tld, dev=dev)
                fallback_domain = None
                if fallback:
                    for cc in fallback:
                        fallback_domain = f"{ext.domain}.{cc}".lower()
                        registrant = await get_domain_owner(fallback_domain, dev=dev)

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


if __name__ == "__main__":
    #print(asyncio.run(get_domain_owner("athletic-club.eus")))
    print(extract_company_from_domain("emailing.b4ncosntand3r-mail.eus"))