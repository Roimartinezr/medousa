# app/services/domain_sanitizer_service/sanitize_domain.py
from email_utils import *
import uuid

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

async def sanitize_mail(email):
    # 1. Validar y limpiar el email
    v_mail = validate_mail(email.strip().lower())
    if v_mail != email:
        return {
            "request_id": str(uuid.uuid4()),
            "email": email,
            "veredict": "no-fisico",
            "veredict_detail": "Invalid email format",
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
            "veredict": "no-fisico",
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
            "veredict": "fisico",
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
    legitimate_domains = await search_company_domains(target_company)
    evidences = []
    if legitimate_domains:
        for d in legitimate_domains:
            evidences.append({
                "type": "legitimate_domain",
                "value": d,
                "score": 1.0 if d == incoming_domain else 0.8
            })
    else:
        return {
            "request_id": str(uuid.uuid4()),
            "email": email,
            "veredict": "no-fisico",
            "veredict_detail": "No legitimate domains found",
            "company_impersonated": None,
            "company_detected": company_detected,
            "confidence": confidence,
            "labels": ["no-legitimate-domains"],
            "evidences": []
        }

    # 4. Validar el dominio entrante
    result = validate_incoming_domain(incoming_domain, legitimate_domains)
    if result == 1:
        veredict = "fisico"
        veredict_detail = "Legitimate domain"
        labels = ["legitimate"]
        company_impersonated = None
    elif result == 2:
        veredict = "no-fisico"
        veredict_detail = "Subdomain of legitimate domain"
        labels = ["subdomain"]
        company_impersonated = company_detected
    else:
        veredict = "no-fisico"
        veredict_detail = "Domain not in legitimate list"
        labels = ["suspicious"]
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


def validate_incoming_domain(incoming_domain, legitimate_domains_list):
    """
    Checks if the incoming domain is in the list of legitimate domains.
    """
    for d in legitimate_domains_list:
        if incoming_domain.lower() == d["value"].lower():
            return 1
        elif incoming_domain.lower() in d["value"].lower():
            return 2
        
    return 0
