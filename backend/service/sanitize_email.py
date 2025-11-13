# app/services/domain_sanitizer_service/sanitize_domain.py
from .email_utils import *
import uuid
import re

MAIL_NAMES = {

    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "yahoo.com",
    "ymail.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "proton.me",
    "protonmail.com",
    "zoho.com",
    "zohomail.com",
    "aol.com",
    "gmx.com",
    "mail.com"
}

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
    # 1. Validar y limpiar el email
    v_mail = validate_mail(email.strip().lower())

    if not v_mail:
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
                "evidences": []
            }
    elif v_mail != email:
        return {
            "request_id": str(uuid.uuid4()),
            "email": email,
            "veredict": "phishing",
            "veredict_detail": "Ascii anomaly detected",
            "company_impersonated": None,
            "company_detected": None,
            "confidence": 0.0,
            "labels": ["invalid-format", "ascii-anomaly"],
            "evidences": []
        }
    
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
            "evidences": []
        }
    elif incoming_domain in MAIL_NAMES:
        return {
            "request_id": str(uuid.uuid4()),
            "email": email,
            "veredict": "valid",
            "veredict_detail": "General-supplier's domain",
            "company_impersonated": None,
            "company_detected": None,
            "confidence": 1.0,
            "labels": [incoming_domain.split('.')[0], "general-supplier"],
            "evidences": []
        }

    # 2. Detectar la empresa
    json_response = extract_company_from_domain(incoming_domain)
    target_company = json_response["company"]
    confidence = json_response["confidence"] / 100.0
    company_detected = target_company
    

    # 3. Buscar dominios legítimos
    # 3.1 Construir root domain
    tld = tldextract.extract(incoming_domain).suffix
    root_domain = f"{target_company}.{tld}"
    
    # 3.2 Obtener titulares (owners)
    root_owner = await get_domain_owner(root_domain)
    incoming_owner = await get_domain_owner(incoming_domain)

    # 3.3 Comparar titulares (fuzzy + contención)
    owners_match = False
    similarity = 0.0

    if root_owner != "No encontrado" and incoming_owner != "No encontrado":
        if _owners_simple_match(root_owner, incoming_owner):
            owners_match = True
            similarity = 1.0
        else:
            similarity = _owners_similarity(root_owner, incoming_owner)
            owners_match = similarity >= 0.90  # umbral ajustable

    # 3.4 Construcción de evidencias
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
        }
    ]

    # 3.5 Determinar relación entre dominios
    root_dom_norm = _norm_domain(root_domain)
    incoming_dom_norm = _norm_domain(incoming_domain)

    if incoming_dom_norm and incoming_dom_norm == root_dom_norm:
        result = 1
    elif incoming_dom_norm and _is_subdomain(incoming_dom_norm, root_dom_norm):
        result = 2
    else:
        result = 0

    # 3.6 Determinar veredicto global
    if result == 1 and owners_match:
        veredict = "valid"
        veredict_detail = "Dominio legítimo y titular coincidente"
        labels = ["legitimate", "owner-match"]
        confidence = 1.0
        company_impersonated = None
    elif result == 2 and owners_match:
        veredict = "valid"
        veredict_detail = "Subdominio legítimo con titular WHOIS coincidente"
        labels = ["subdomain", "owner-match"]
        confidence = 0.85
        company_impersonated = None
    elif result == 0 and owners_match:
        veredict = "valid"
        veredict_detail = "Dominio no relacionado, pero titular WHOIS coincide"
        labels = ["suspicious", "owner-match"]
        confidence = 0.7
        company_impersonated = company_detected
    elif result in (1, 2) and not owners_match:
        veredict = "warning"
        veredict_detail = "Dominio legítimo, pero titular WHOIS distinto"
        labels = ["owner-mismatch"]
        confidence = 0.6
        company_impersonated = company_detected
    else:
        veredict = "phishing"
        veredict_detail = "Dominio o titular no coincide con la empresa objetivo"
        labels = ["suspicious", "owner-mismatch"]
        confidence = 0.0
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
        "evidences": evidences
    }

