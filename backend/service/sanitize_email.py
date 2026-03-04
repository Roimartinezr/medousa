# backend/service/sanitize_email.py

import re
import uuid
import asyncio
import tldextract
import logging
from Levenshtein import distance
from .utils.email_utils import validate_mail, extract_domain_from_email
from .utils.legitmacy import get_domain_owner, identify_brand_from_registrant
from .utils.recognition import extract_company_from_domain
from known_brands_v3_service import find_brand_by_known_domain, ensure_brand_for_root_domain, add_known_domain, add_owner_terms, _tokenize_str
from .mail_names_service import is_personal_mail_domain

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# ------------------ Helpers ---------------------
def _norm_domain(s: str) -> str:
    if not s: return ""
    s = re.sub(r"\s+", "", s).strip()
    # get rid of subdomains
    s = s.split(".")[-1]
    # replace '-' and '_'
    return re.sub(r"[-_]", "", s).lower()

def _domain_token_overlap(a: str, b: str) -> float:
    """
    Calcula similitud mediante N-gramas (2 o 3) según el tamaño del string.
    Limpia espacios, guiones y guiones bajos antes de procesar.
    """
    # 1. Normalización
    clean_a = _norm_domain(a)
    clean_b = _norm_domain(b)

    if not clean_a or not clean_b:
        return 0.0

    # 2. Determinar el tamaño de N (2-gramas o 3-gramas)
    # Si la palabra más corta es de longitud 2, usamos 2-gramas.
    # Si es de 3 o más, usamos 3-gramas para mayor precisión.
    min_str_len = min(len(clean_a), len(clean_b))
    n = 2 if min_str_len < 4 else 3

    # Generador interno de n-gramas
    def get_ngrams(text: str, size: int) -> set:
        return {text[i:i+size] for i in range(len(text) - size + 1)}

    tokens_a = get_ngrams(clean_a, n)
    tokens_b = get_ngrams(clean_b, n)

    if not tokens_a or not tokens_b:
        # Caso de seguridad por si el string es más corto que el tamaño del n-grama
        return 0.0

    # 3. Intersección y cálculo de solapamiento
    inter = tokens_a & tokens_b
    min_tokens_count = min(len(tokens_a), len(tokens_b))

    # Aplicar la fórmula: Overlap = |A ∩ B| / min(|A|, |B|)
    return len(inter) / float(min_tokens_count)

def _domain_similarity(a: str, b: str) -> float:
    """Devuelve similitud [0–1] usando Levenshtein normalizado."""
    a_n = _norm_domain(a)
    b_n = _norm_domain(b)
    if not a_n or not b_n:
        return 0.0
    sim = 1.0 - (distance(a_n, b_n) / max(len(a_n), len(b_n)))
    return max(0.0, min(1.0, sim))

def _is_subdomain(sub: str, super: str) -> bool:
    return bool(super) and sub.endswith(super) and sub != super

# ----------------- Main Flow --------------------

async def sanitize_mail(email):
    # 1. Validar y normalizar el email
    v_mail = validate_mail(email.strip().lower())

    if not v_mail:
        # Permitir no-reply raros
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
    #               3. DETECCIÓN DE BRAND
    # ======================================================

    ext = tldextract.extract(incoming_domain)

    brand_doc = None
    brand_id = None
    incoming_owner = None
    detected_root_domain = None

    already_known = False
    new_brand = False

    # si el suffix es compuesto (com.es, net.es...), nos quedamos con la última parte (.es)
    logical_suffix = ext.suffix.split(".")[-1]

    # root DNS real: respeta SIEMPRE el sufijo completo (com.es, com.mx, etc.)
    if ext.domain and ext.suffix:
        incoming_root_domain = f"{ext.domain}.{ext.suffix}"
    else:
        incoming_root_domain = incoming_domain

    # 3.1 Primero: COMPROBAR si el DOMINIO ENTRANTE YA es CONOCIDO
    brand_doc = find_brand_by_known_domain(incoming_domain) # Gestionar aquí sensibilidad dominio/subdominio
    if not brand_doc and incoming_root_domain != incoming_domain:
        # también probamos contra el root DNS real (bancosantander-mail.es)
        brand_doc = find_brand_by_known_domain(incoming_root_domain)
    # Seguridad extra: si el dominio que buscamos NO está realmente en known_domains,
    # descartamos el brand_doc (por si OpenSearch devolviese algo raro).
    if brand_doc:
        src_tmp = brand_doc["_source"]
        kd_tmp = set(src_tmp.get("known_domains", []))
        norm_incoming = _norm_domain(incoming_domain)
        norm_dns_root = _norm_domain(incoming_root_domain)
        norm_known = {_norm_domain(d) for d in kd_tmp}

        if norm_incoming not in norm_known and norm_dns_root not in norm_known:
            brand_doc = None
        else:
            brand_id = brand_doc["_id"]
            detected_company = brand_id
            already_known = True

    # 3.2 SI NO ES UN DOMINIO CONOCIDO:
    if not brand_doc:
        # 3.2.1 Heurística para sacar la compañía potencialmente suplantada (usa omit_words y OpenSearch)
        brand_doc = extract_company_from_domain(incoming_root_domain)
        if brand_doc:
            detected_company = brand_doc["id"] or None  # ej: "bancosantander"
            # 3.2.2 Root domain LÓGICO (canonical) usando el suffix lógico
            detected_root_domain = f'{detected_company}.{logical_suffix}'
            
            # 3.2.3 Establecer datos faltantes
            brand_id = detected_company
            brand_owner_terms = set(brand_doc["owner_terms"])

        # 3.3 SI TAMPOCO SE RECONOCE UNA BRAND SUPLANTADA
        # Llegados a este punto se detecta como una NUEVA BRAND
        else:
            new_brand = True
            # 3.3.1 No existe brand aún en OpenSearch para este root_domain lógico
            # Se intenta el WHOARE un par de veces
            t = 0.5
            c = 0
            while not incoming_owner and c < 2:
                await asyncio.sleep(1+t)
                incoming_owner = await get_domain_owner(incoming_root_domain)
                c += 1
            # 3.3.2 Si el WHOARE ha funcionado, se crea la nueva BRAND
            if incoming_owner:
                brand_id = ensure_brand_for_root_domain(
                    root_domain=incoming_root_domain,
                    owner_str=incoming_owner,
                    brand_id_hint=detected_company or None
                )
                detected_company = brand_id or detected_company
                brand_owner_terms = _tokenize_str(incoming_owner)  # <-- usamos el WHOIS como owner_terms inicial
            #else:
                # 3.3.3 Si no se puede hacer el whois para la "nueva brand", por ahora no se hace nada

    # ======================================================
    # 4. WHOIS DEL INCOMING ROOT DOMAIN + SIMILITUD VS BRAND
    # ======================================================
    owners_match = False
    similarity = 0.0

    # Caso 4.1: el root DNS real YA está en known_domains ⇒ es oficial
    if already_known:
        owners_match = True
        similarity = 1.0
        incoming_owner = "Dominio Previamente Autorizado"
    
    # Caso 4.2: es una nueva brand
    elif new_brand:
        owners_match = False
        # Si existe brand_id ⇒ NEW BRAND
        # Si no ⇒ Error, no se pudo procesar
    
    # Caso 4.3: no es un dominio conocido, ni una nueva brand ⇒ Hay que averiguar su legitimidad
    else:
        # 4.3.1. Averiguar registrante del dominio entrante
        t = 0.5
        c = 0
        while not incoming_owner and c < 2:
            await asyncio.sleep(1+t)
            incoming_owner = await get_domain_owner(incoming_root_domain)
            c += 1
        
        if incoming_owner:
            # 4.3.2. Buscar una brand a partir del registrante
            tmp_brand_doc = identify_brand_from_registrant(incoming_owner)

            # 4.3.3: Si existe brand_doc ⇒ Se asoció una brand al dominio entrante (falta verficar legitimidad)
            # (Viene de 3.2)
            if brand_doc:
                # Si el ID detectado y el ID de la target comany coinciden: legitimo
                if tmp_brand_doc["id"] and tmp_brand_doc["id"] == brand_doc["id"]:
                    owners_match = True
                    detected_root_domain = f'{brand_doc["id"]}.{logical_suffix}'
                    # IMPORTANTE: identify_brand_from_registrant() debe devolver el nivel de confianza
                    similarity = 0.6

            # 4.3.4. Si no existe brand_doc ⇒ No se detectó target company
            else:
                # Si se ha encontrado una brand a partir del incoming registrant:
                if tmp_brand_doc:
                    # Comprobar por Levensthein / similaridad token si la brand detectada y el dominio entrante son similares
                    # Se hará la comprobacion con 'tmp_brand_id' ⇔ 'incoming_root_domain'
                    incoming_root_domain_solo = tldextract.extract(incoming_root_domain).domain
                    sim_lev = _domain_similarity(tmp_brand_doc["id"], incoming_root_domain_solo)
                    sim_tok = _domain_token_overlap(tmp_brand_doc["id"], incoming_root_domain_solo)
                    similarity = max(sim_lev, sim_tok)

                    if similarity >= 0.7:  # umbral ajustable
                        owners_match = True
                        detected_root_domain = f'{tmp_brand_doc["id"]}.{logical_suffix}'
                        try:
                            if ext.subdomain and brand_id:
                                dns_root_subdomain = f'{ext.subdomain}.{incoming_root_domain}'
                                add_known_domain(brand_id, dns_root_subdomain)
                            add_known_domain(brand_id, incoming_root_domain)
                            add_owner_terms(brand_id, incoming_owner)
                        except Exception:
                            pass

                # No se vincula con ninguna entidad
                else:
                    owners_match = False

        # Fallo al obtener incoming owner
        else:
            owners_match = False

    # ======================================================
    #             5. RELACIÓN ENTRE DOMINIOS
    # ======================================================
    subdomain_added = False
    if ext.subdomain and owners_match:
        add_known_domain(brand_id, incoming_domain)
        subdomain_added = True

    if detected_root_domain and detected_root_domain == incoming_domain:
        relation = 1  # mismo dominio base
    elif detected_root_domain and _is_subdomain(sub=incoming_domain, super=detected_root_domain):
        if not subdomain_added and brand_id:
            add_known_domain(brand_id, incoming_domain)
        relation = 2  # subdominio del dominio lógico/canónico
    else:
        relation = 0  # dominio ajeno (respecto al canonical)


    evidences = []

    if owners_match and not already_known:
        evidences = [
            {
                "domain": detected_root_domain,
                "owner": None,
                "detail": "Detected Root Domain",
            },
        ]

        if relation == 1:
            evidences = [
                {
                    "domain": incoming_root_domain,
                    "owner": incoming_owner,
                    "detail": "Root Domain",
                }
            ]
        elif relation == 2:
            evidences = [
                {
                    "domain": incoming_domain,
                    "owner": f"Subdominio de: {detected_root_domain}",
                    "detail": "Canonical Domain Subdomain",
                }
            ]
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
    
    elif already_known:
        evidences = [
            {
                "domain": incoming_domain,
                "owner": incoming_owner,
                "detail": "Canonical Domain",
            },
        ]
    
    elif not owners_match and incoming_owner:
        evidences = [
            {
                "domain": incoming_domain,
                "owner": incoming_owner,
                "detail": "No Legitimated",
            },
        ]
    
    elif not owners_match:
        evidences = [
            {
                "domain": incoming_domain,
                "owner": None,
                "detail": "No Owner Detected",
            },
        ]


    # ======================================================
    # 6. VEREDICTO GLOBAL (adaptado a la nueva lógica)
    # ======================================================

    if new_brand:
        # brand recién creada: veredicto neutro
        veredict = "warning"
        veredict_detail = f"Nuevo dominio detectado para {incoming_root_domain}; pendiente de verificación manual"
        labels = ["new-brand"]
        confidence = 0.5
        company_impersonated = None

    elif relation in (1, 2) and owners_match:
        veredict = "valid"
        if relation == 1:
            veredict_detail = f"Dominio legítimo y titular WHOIS compatible con el de {detected_root_domain}"
        else:
            veredict_detail = f"Subdominio legítimo y titular WHOIS compatible con el de {detected_root_domain}"
        labels = ["legitimate", "owner-match"]
        confidence = similarity
        company_impersonated = None
    
    elif relation in (1, 2) and not owners_match:
        veredict = "warning"
        veredict_detail = f"Inconcluencia del Sistema\nDominio legítimo, pero titular WHOIS no encaja con el de {detected_root_domain}"
        labels = ["owner-mismatch"]
        confidence = similarity
        company_impersonated = tldextract.extract(detected_root_domain).domain

    elif relation == 0 and owners_match:
        # Dominio alternativo/alias cuyo WHOIS pertenece claramente a la brand
        veredict = "valid"
        veredict_detail = f"Dominio alternativo cuyo titular WHOIS coincide con el de {detected_root_domain}"
        labels = ["legitimate-alias", "owner-match"]
        confidence = similarity
        company_impersonated = None

    else:
        veredict = "phishing"
        veredict_detail = f"Dominio y/o titular no coincide con {detected_root_domain}"
        labels = ["suspicious", "owner-mismatch"]
        confidence = similarity
        company_impersonated = detected_company

    return {
        "request_id": str(uuid.uuid4()),
        "email": email,
        "veredict": veredict,
        "veredict_detail": veredict_detail,
        "company_impersonated": company_impersonated,
        "company_detected": detected_company,
        "confidence": confidence,
        "labels": labels,
        "evidences": evidences,
    }
