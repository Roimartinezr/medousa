# app/services/domain_sanitizer_service/sanitize_domain.py
import asyncio
from .utils.email_utils import *
from .known_brands_service import *
from .mail_names_service import is_personal_mail_domain
from .known_brands_service import *
import uuid
import re
from Levenshtein import distance

import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# ------------------ Helpers ---------------------
def _norm_owner(s: str) -> str:
    if not s:
        return ""
    s = s.lower().replace(",", "").replace(".", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return s

def _owners_token_overlap(a: str, b: str) -> float:
    """
    Similitud a nivel de tokens WHOIS/owner_terms.
    Devuelve 1.0 si todos los tokens del más corto están contenidos en el más largo.
    """
    # usamos la misma lógica que en known_brands_service
    try:
        from .known_brands_service import tokenize_owner_str
    except ImportError:
        # fallback mínimo si cambia el import
        def tokenize_owner_str(s: str) -> list[str]:
            s = (s or "").lower()
            s = re.sub(r"[,\.]", " ", s)
            s = re.sub(r"\s+", " ", s).strip()
            return s.split() if s else []

    tokens_a = set(tokenize_owner_str(a))
    tokens_b = set(tokenize_owner_str(b))

    if not tokens_a or not tokens_b:
        return 0.0

    inter = tokens_a & tokens_b
    min_len = min(len(tokens_a), len(tokens_b))
    if min_len == 0:
        return 0.0

    # si todos los tokens del más corto están contenidos en el otro → 1.0
    return len(inter) / float(min_len)


def _owners_similarity(a: str, b: str) -> float:
    """Devuelve similitud [0–1] usando Levenshtein normalizado."""
    a_n = _norm_owner(a).replace(" ", "")
    b_n = _norm_owner(b).replace(" ", "")
    if not a_n or not b_n:
        return 0.0
    sim = 1.0 - (distance(a_n, b_n) / max(len(a_n), len(b_n)))
    return max(0.0, min(1.0, sim))

def _norm_domain(d: str) -> str:
    return (d or "").strip().lower().rstrip(".")

def _is_subdomain(child: str, parent: str) -> bool:
    c = _norm_domain(child)
    p = _norm_domain(parent)
    return bool(p) and c.endswith(p) and c != p

async def sanitize_mail(email):
    # 1. Validar y normalizar el email
    v_mail = validate_mail(email.strip().lower())

    if not v_mail:
        # Permitir no-reply raros, como tenías
        if re.search(r"\bno[\-_]?reply\b", email, re.IGNORECASE):
            v_mail = email
        else:
            return {
                "request_id": str(uuid.uuid4()),
                "email": email,
                "veredict": "phishing",
                "veredict_detail": "The domain name does not exist",
                "company_impersonated": None,
                "company_detected": None,
                "confidence": 0.0,
                "labels": ["invalid-format"],
                "evidences": [],
            }
    elif v_mail != email:
        try:
            # dominio original tal y como llega en la request (punycode)
            _, orig_domain = email.rsplit("@", 1)
            # dominio normalizado (Unicode) devuelto por validate_mail
            _, norm_domain = v_mail.rsplit("@", 1)

            orig_tld = orig_domain.rsplit(".", 1)[-1].lower()
        except ValueError:
            # Por si acaso, si algo raro pasa, mantenemos el comportamiento antiguo
            return {
                "request_id": str(uuid.uuid4()),
                "email": email,
                "veredict": "phishing",
                "veredict_detail": "Ascii anomaly detected",
                "company_impersonated": None,
                "company_detected": None,
                "confidence": 0.0,
                "labels": ["invalid-format", "ascii-anomaly"],
                "evidences": [],
            }

        # Si el TLD ORIGINAL es IDN (punycode), NO lo tratamos como anomalía ASCII
        if orig_tld.startswith("xn--"):
            # aceptamos la versión normalizada y seguimos el pipeline
            aux = email
            email = v_mail
            v_mail = aux
        else:
            # comportamiento original: anomalía ASCII
            return {
                "request_id": str(uuid.uuid4()),
                "email": email,
                "veredict": "phishing",
                "veredict_detail": "Ascii anomaly detected",
                "company_impersonated": None,
                "company_detected": None,
                "confidence": 0.0,
                "labels": ["invalid-format", "ascii-anomaly"],
                "evidences": [],
            }

    # 2. Extraer dominio entrante (FQDN)
    incoming_domain = extract_domain_from_email(v_mail)
    if not incoming_domain:
        return {
            "request_id": str(uuid.uuid4()),
            "email": email,
            "veredict": "phishing",
            "veredict_detail": "Invalid email format",
            "company_impersonated": None,
            "company_detected": None,
            "confidence": 0.0,
            "labels": ["invalid-format"],
            "evidences": [],
        }

    # 2.1 Proveedor generalista (mail_names en OpenSearch)
    if is_personal_mail_domain(incoming_domain):
        return {
            "request_id": str(uuid.uuid4()),
            "email": email,
            "veredict": "valid",
            "veredict_detail": "General-supplier's domain",
            "company_impersonated": None,
            "company_detected": None,
            "confidence": 1.0,
            "labels": [incoming_domain.split(".")[0], "general-supplier"],
            "evidences": [],
        }

    # ======================================================
    # 3. DETECCIÓN DE BRAND, ROOT LÓGICO Y ROOT DNS REAL
    # ======================================================

    ext = tldextract.extract(incoming_domain)

    # root DNS real: respeta SIEMPRE el sufijo completo (com.es, com.mx, etc.)
    if ext.domain and ext.suffix:
        dns_root_domain = f"{ext.domain}.{ext.suffix}"
    else:
        dns_root_domain = incoming_domain

    # 3.1 Heurística para sacar "company base" (usa omit_words y OpenSearch)
    domain_info = extract_company_from_domain(incoming_domain)
    base_company = domain_info["company"]  # ej: "bancosantander"

    # --- NUEVO: suffix lógico para la brand ---
    logical_suffix = ext.suffix or ""
    if logical_suffix:
        # si el suffix es compuesto (com.es, net.es...), nos quedamos con la última parte (es)
        logical_suffix_parts = logical_suffix.split(".")
        logical_suffix = logical_suffix_parts[-1]

    # 3.2 Root domain LÓGICO (canonical) usando el suffix lógico
    if base_company and logical_suffix:
        # ej:
        #   incoming: bancosantander.com.es
        #   base_company: bancosantander
        #   logical_suffix: es
        #   → root_domain lógico: bancosantander.es
        root_domain = f"{base_company}.{logical_suffix}"
    else:
        root_domain = dns_root_domain

    company_detected = base_company or None
    brand_id = None
    brand_doc = None
    brand_profile = ""
    brand_known_domains = set()
    root_owner = None
    owner_terms = ""

    # 3.3 Primero: comprobar si el dominio entrante YA es conocido
    brand_doc = find_brand_by_known_domain(incoming_domain) # xxxGestionar aquí sensibilidad dominio/subdominio
    if not brand_doc and dns_root_domain != incoming_domain:
        # también probamos contra el root DNS real (bancosantander-mail.es)
        brand_doc = find_brand_by_known_domain(dns_root_domain)

    # Seguridad extra: si el dominio que buscamos NO está realmente en known_domains,
    # descartamos el brand_doc (por si OpenSearch devolviese algo raro).
    if brand_doc:
        src_tmp = brand_doc["_source"]
        kd_tmp = set(src_tmp.get("known_domains", []))
        norm_incoming = _norm_domain(incoming_domain)
        norm_dns_root = _norm_domain(dns_root_domain)
        norm_known = {_norm_domain(d) for d in kd_tmp}

        if norm_incoming not in norm_known and norm_dns_root not in norm_known:
            brand_doc = None


    new_brand = False
    if brand_doc:
        src = brand_doc["_source"]
        brand_id = brand_doc["_id"]
        root_domain = f'{brand_id}.{src.get("country_code")}'
        company_detected = brand_id or company_detected

        brand_known_domains = set(src.get("known_domains", []))
        owner_terms = src.get("owner_terms", "")
        keywords = src.get("keywords", [])
        brand_profile = " ".join(
            [
                owner_terms,
                " ".join(keywords)
            ]
        )

    else:
        # 3.4 Mirar si ya tenemos brand por keywords (root lógico)
        brand_doc = find_brand_by_keywords(ext.domain)
        if brand_doc:
            src = brand_doc["_source"]
            brand_id = brand_doc["_id"]
            root_domain = f'{brand_id}.{src.get("country_code")}'
            company_detected = brand_id or company_detected

            brand_known_domains = set(src.get("known_domains", []))
            owner_terms = src.get("owner_terms", "")
            keywords = src.get("keywords", [])
            brand_profile = " ".join(
                [
                    owner_terms,
                    " ".join(keywords)
                ]
            )
        else:
            new_brand = True
            # 3.5 No existe brand aún en OpenSearch para este root_domain lógico
            # Aquí SÍ hacemos WHOIS del root_domain lógico (bancosantander.es)
            root_owner = await get_domain_owner(root_domain)
            t = 0.5
            c = 0
            while root_owner == "No encontrado" and c < 2:
                await asyncio.sleep(1+t)
                root_owner = await get_domain_owner(root_domain)
                c += 1

            if root_owner != "No encontrado":
                brand_id = ensure_brand_for_root_domain(
                    root_domain=root_domain,
                    owner_str=root_owner,
                    brand_id_hint=base_company or None,
                )
                company_detected = brand_id or company_detected
                brand_known_domains = {root_domain}
                owner_terms = root_owner  # <-- usamos el WHOIS como owner_terms inicial
                brand_profile = " ".join(dict.fromkeys([root_owner, brand_id or ""]))
                try:
                    add_known_domain(brand_id, root_domain)
                except Exception:
                    pass
            else:
                # No hay owner del root_domain lógico; usamos solo heurística
                brand_id = base_company or None
                company_detected = brand_id or company_detected
                brand_profile = (brand_id or "")

    # ======================================================
    # 4. WHOIS DEL ROOT DNS REAL + SIMILITUD VS BRAND
    # ======================================================

    # Caso 1: el root DNS real YA está en known_domains ⇒ es oficial
    if brand_id and dns_root_domain in brand_known_domains:
        owners_match = True
        similarity = 1.0
        if root_owner:
            incoming_owner = root_owner
        else:
            incoming_owner = "Dominio Previamente Autorizado"
    else:
        # Caso 2: no está en known_domains ⇒ hacemos WHOIS del root DNS real
        incoming_owner = await get_domain_owner(dns_root_domain)
        t = 0.5
        c = 0
        while incoming_owner == "No encontrado" and c < 2:
            await asyncio.sleep(1+t)
            incoming_owner = await get_domain_owner(dns_root_domain)
            c+=1

        owners_match = False
        similarity = 0.0

        if incoming_owner != "No encontrado" and brand_id and (brand_profile or owner_terms):
            profile_for_similarity = owner_terms if owner_terms else brand_profile

            sim_lev = _owners_similarity(profile_for_similarity, incoming_owner)
            sim_tok = _owners_token_overlap(profile_for_similarity, incoming_owner)
            similarity = max(sim_lev, sim_tok)

            if similarity >= 0.7:  # umbral ajustable
                owners_match = True
                try:
                    if ext.subdomain and brand_id:
                        dns_root_subdomain = f'{ext.subdomain}.{dns_root_domain}'
                        add_known_domain(brand_id, dns_root_subdomain)
                    add_known_domain(brand_id, dns_root_domain)
                    add_owner_terms(brand_id, incoming_owner)
                    add_keyword(brand_id, ext.domain)
                    brand_known_domains.add(dns_root_domain)
                except Exception:
                    pass


    # ======================================================
    # 5. RELACIÓN ENTRE DOMINIOS (root lógico vs incoming)
    # ======================================================
    subdomain_added = False
    if ext.subdomain and brand_id:
        add_known_domain(brand_id, incoming_domain)
        subdomain_added = True

    root_dom_norm = _norm_domain(root_domain)           # bancosantander.es
    incoming_dom_norm = _norm_domain(incoming_domain)   # emailing.bancosantander-mail.es

    if incoming_dom_norm and incoming_dom_norm == root_dom_norm:
        relation = 1  # mismo dominio base
    elif incoming_dom_norm and _is_subdomain(incoming_dom_norm, root_dom_norm):
        if not subdomain_added and brand_id:
            add_known_domain(brand_id, incoming_domain)
        relation = 2  # subdominio del dominio lógico/canónico
    else:
        relation = 0  # dominio ajeno (respecto al canonical)

    # root_owner para evidencias:
    if root_owner is None:
        root_owner = "Dominio Canónico"

    evidences = [
        {
            "domain": root_domain,
            "owner": root_owner,
            "detail": "Detected Root Domain",
        },
    ]

    if relation == 1:
        evidences = [
            {
                "domain": root_domain,
                "owner": root_owner,
                "detail": "Root Domain",
            }
        ]
    elif relation == 2:
        evidences.append(
            {
                "domain": incoming_domain,
                "owner": f"Subdominio de: {dns_root_domain}",
                "detail": "Canonical Domain Subdomain",
            }
        )
        evidences.append(
            {
                "domain": incoming_domain,
                "owner": incoming_owner,
                "detail": "Incoming Domain",
            }
        )
    else:
        if ext.subdomain:
            evidences.append(
                {
                    "domain": f'{ext.domain}.{ext.suffix}',
                    "owner": incoming_owner,
                    "detail": "Incoming Superdomain",
                }
            )
        evidences.append(
            {
                "domain": incoming_domain,
                "owner": incoming_owner,
                "detail": "Incoming Domain",
            }
        )

    # ======================================================
    # 6. VEREDICTO GLOBAL (adaptado a la nueva lógica)
    # ======================================================

    if new_brand:
        # brand recién creada: veredicto neutro
        veredict = "warning"
        veredict_detail = f"Nuevo dominio detectado para {root_domain}; pendiente de verificación manual"
        labels = ["new-brand"]
        confidence = 0.5
        company_impersonated = None

    elif relation in (1, 2) and owners_match:
        veredict = "valid"
        if relation == 1:
            veredict_detail = f"Dominio legítimo y titular WHOIS compatible con el de {root_domain}"
        else:
            veredict_detail = f"Subdominio legítimo y titular WHOIS compatible con el de {root_domain}"
        labels = ["legitimate", "owner-match"]
        confidence = similarity
        company_impersonated = None
    
    elif relation in (1, 2) and not owners_match:
        veredict = "warning"
        veredict_detail = f"Inconcluencia del Sistema\nDominio legítimo, pero titular WHOIS no encaja con el de {root_domain}"
        labels = ["owner-mismatch"]
        confidence = similarity
        company_impersonated = company_detected

    elif relation == 0 and owners_match:
        # Dominio alternativo/alias cuyo WHOIS pertenece claramente a la brand
        veredict = "valid"
        veredict_detail = f"Dominio alternativo cuyo titular WHOIS coincide con el de {root_domain}"
        labels = ["legitimate-alias", "owner-match"]
        confidence = similarity
        company_impersonated = None

    else:
        veredict = "phishing"
        veredict_detail = f"Dominio y/o titular no coincide con {root_domain}"
        labels = ["suspicious", "owner-mismatch"]
        confidence = similarity
        company_impersonated = company_detected

    return {
        "request_id": str(uuid.uuid4()),
        "email": email,
        "veredict": veredict,
        "veredict_detail": veredict_detail,
        "company_impersonated": company_impersonated,
        "company_detected": company_detected,
        "confidence": confidence,
        "labels": labels,
        "evidences": evidences,
    }
