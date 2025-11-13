# app/services/domain_sanitizer_service/sanitize_domain.py
from .utils.email_utils import *
from .known_brands_service import *
from .mail_names_service import is_personal_mail_domain
from .known_brands_service import *
import uuid
import re
from Levenshtein import distance

# ------------------ Helpers ---------------------
def _norm_owner(s: str) -> str:
    if not s:
        return ""
    s = s.lower().replace(",", "").replace(".", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return s

def _owners_simple_match(a: str, b: str) -> bool:
    a_n = _norm_owner(a)
    b_n = _norm_owner(b)
    if not a_n or not b_n:
        return False
    return a_n == b_n or a_n in b_n or b_n in a_n

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
        # Anomalías ASCII
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

    # 2. Extraer dominio entrante
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
    # 3. DETECCIÓN DE BRAND & ROOT DOMAIN
    # ======================================================

    # 3.1 Heurística antigua para sacar "company base" del dominio
    domain_info = extract_company_from_domain(incoming_domain)
    base_company = domain_info["company"]  # ej: "bancosantander"
    confidence = (domain_info.get("confidence") or 0) / 100.0

    # 3.2 Root domain candidato con el TLD del dominio entrante
    ext = tldextract.extract(incoming_domain)
    tld = ext.suffix
    root_domain = f"{base_company}.{tld}" if base_company and tld else incoming_domain

    company_detected = base_company or None
    brand_id = None
    brand_doc = None

    # 3.3 Primero: comprobar si el dominio entrante ya es conocido
    brand_doc = find_brand_by_known_domain(incoming_domain)
    if brand_doc:
        src = brand_doc["_source"]
        brand_id = src.get("brand_id")
        canonical_domain = src.get("canonical_domain") or root_domain
        root_domain = canonical_domain
        company_detected = brand_id or company_detected
        confidence = max(confidence, 1.0)  # dominio conocido = confianza alta
    else:
        # 3.4 Si no, mirar si ya tenemos brand por canonical_domain
        brand_doc = find_brand_by_canonical_domain(root_domain)
        if brand_doc:
            src = brand_doc["_source"]
            brand_id = src.get("brand_id")
            company_detected = brand_id or company_detected
            # aquí NO tiramos WHOIS del root_domain, usamos solo OpenSearch
        else:
            # 3.5 No existe aún brand en OpenSearch para este root_domain
            # Aquí sí está permitido hacer WHOIS del root_domain
            root_owner = await get_domain_owner(root_domain)
            if root_owner != "No encontrado":
                # Creamos brand con el saco de palabras del owner del root
                brand_id = ensure_brand_for_root_domain(
                    root_domain=root_domain,
                    owner_str=root_owner,
                    brand_id_hint=base_company or None,
                )
                company_detected = brand_id or company_detected
                # y añadimos el root_domain como conocido en esa brand
                try:
                    add_known_domain(brand_id, root_domain)
                except Exception:
                    pass
            else:
                # No hay owner del root_domain; nos quedamos solo con la heurística
                brand_id = base_company or None
                company_detected = brand_id or company_detected

    # ======================================================
    # 4. WHOIS DEL DOMINIO ENTRANTE + FUZZY VS BRAND
    # ======================================================

    incoming_owner = await get_domain_owner(incoming_domain)

    owners_match = False
    similarity = 0.0

    # Sólo tiene sentido fuzzy si tenemos algún owner entrante
    if incoming_owner != "No encontrado" and brand_id:
        # Usamos el “perfil léxico” de known_brands (brand_keywords + owner_terms)
        # para intentar mapear el incoming_owner a una brand.
        try:
            candidates = guess_brand_from_whois(incoming_owner, max_results=3)
        except Exception:
            candidates = []

        if candidates:
            best = candidates[0]
            best_src = best.get("_source", {})
            guessed_brand_id = best_src.get("brand_id")
            es_misma_brand = guessed_brand_id == brand_id

            if es_misma_brand:
                owners_match = True
                # Podrías usar best["_score"] para afinar; por ahora lo simplificamos:
                similarity = 1.0
                confidence = max(confidence, 0.8)

                # Nutrición: añadimos dominio y owner al índice de la brand
                try:
                    add_known_domain(brand_id, incoming_domain)
                    add_owner_terms(brand_id, incoming_owner)
                except Exception:
                    pass

    # ======================================================
    # 5. RELACIÓN ENTRE DOMINIOS (root vs incoming)
    # ======================================================

    # Aquí NO llamamos WHOIS del root_domain si ya existía en OpenSearch;
    # pero sí usamos root_domain como tal para ver si el incoming es subdominio.
    root_dom_norm = _norm_domain(root_domain)
    incoming_dom_norm = _norm_domain(incoming_domain)

    if incoming_dom_norm and incoming_dom_norm == root_dom_norm:
        result = 1  # mismo dominio base
    elif incoming_dom_norm and _is_subdomain(incoming_dom_norm, root_dom_norm):
        result = 2  # subdominio
    else:
        result = 0  # dominio ajeno

    # Para evidencias, como no siempre tenemos WHOIS del root_domain,
    # dejamos root_owner como "from-opensearch" cuando no lo hemos pedido.
    if "root_owner" in locals():
        root_owner = root_owner
    else:
        root_owner = f"Profiled brand: {brand_id}" if brand_id else "Not available"

    evidences = [
        {
            "type": root_domain,
            "value": root_owner,
            "score": 1.0,
        },
        {
            "type": incoming_domain,
            "value": incoming_owner,
            "score": 0.5,
        },
    ]

    # ======================================================
    # 6. VEREDICTO GLOBAL (basado en tu lógica anterior)
    # ======================================================

    if result == 1 and owners_match:
        veredict = "valid"
        veredict_detail = "Dominio legítimo y titular coincidente (perfil OpenSearch)"
        labels = ["legitimate", "owner-match"]
        confidence = max(confidence, 1.0)
        company_impersonated = None

    elif result == 2 and owners_match:
        veredict = "valid"
        veredict_detail = "Subdominio legítimo con titular coincidente (perfil OpenSearch)"
        labels = ["subdomain", "owner-match"]
        confidence = max(confidence, 0.85)
        company_impersonated = None

    elif result == 0 and owners_match:
        veredict = "valid"
        veredict_detail = "Dominio no relacionado, pero titular encaja con brand conocida"
        labels = ["suspicious", "owner-match"]
        confidence = max(confidence, 0.7)
        company_impersonated = company_detected

    elif result in (1, 2) and not owners_match:
        veredict = "warning"
        veredict_detail = "Dominio legítimo, pero titular WHOIS no encaja con la brand"
        labels = ["owner-mismatch"]
        confidence = max(confidence, 0.6)
        company_impersonated = company_detected

    else:
        veredict = "phishing"
        veredict_detail = "Dominio o titular no coincide con la empresa objetivo"
        labels = ["suspicious", "owner-mismatch"]
        confidence = min(confidence, 0.3)
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



