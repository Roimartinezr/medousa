# app/backend/service/utils/legitmacy.py

import tldextract
from whoare.service.service import WhoareService
from service.ascii_cctld_service import get_fallback_by_id
from service.ascii_geotld_service import get_country_by_id
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def _is_privacy_value(word: str) -> bool:
    privacy_keywords = ["redacted", "privacy", "whoisguard", "protected", "gdpr"]
    word_lower = str(word).lower()
    is_private = any(keyword in word_lower for keyword in privacy_keywords)
    if not is_private:
        return False
    return True

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
                country = get_country_by_id(tld)
                if country:
                    fallback_domain = f"{ext.domain}.{country.strip()}".lower()
                    registrant = await get_domain_owner(fallback_domain)
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

                        registrant = await get_domain_owner(fallback_domain)
                        if registrant:
                            return registrant

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
