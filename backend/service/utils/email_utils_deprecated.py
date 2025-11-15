import httpx
import os
from tranco import Tranco
from Levenshtein import distance
import asyncio

KNOWN_BRANDS = {
    "abanca",
    "bbva",
    "bancosantander",
    "caixabank",
    "bankia",
    "ing",
    "bankinter",
    "sabadell",
    "unicaja",
    "kutxabank",
    "openbank",
    "revolut",
    "n26",
    "monzo",
    "wise",
    "binance",
    "coinbase",
    "paypal",
    "amazon",
    "microsoft",
    "google",
    "apple",
    "facebook",
    "instagram",
    "whatsapp",
    "outlook",
    "office365",
    "netflix",
    "spotify",
    "dropbox",
    "adobe",
    "dhl",
    "fedex",
    "ups",
    "correos",
    "gls",
    "seur",
    "mrw",
    "chronopost",
    "royalmail",
    "hermes",
    "dpd",
    "posteitaliane",
    "la poste",
    "usps"
  }

OMIT_WORDS = {
    "www","mail","secure","info","login","cliente","clientes",
    "web","app","email","alerta","soporte","acceso","online",
    "account","accounts", "seguridad","support", "admin",
    "beta", "portal", "service", "services", "system", "verify", 
    "verification", "update", "updates", "user", "users"
}

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

def fuzzy_brand_match(word, brands, max_dist=2):
    """
    Devuelve la marca más cercana a 'word' usando distancia de Levenshtein.
    max_dist define la tolerancia (número de ediciones permitidas).
    """
    best_match = None
    best_dist = 99

    for b in brands:
        d = distance(word.lower(), b.lower())
        if d < best_dist:
            best_dist = d
            best_match = b

    if best_dist <= max_dist:
        return best_match, best_dist
    return None, best_dist


async def search_company_domains_crtsh(company_name):
    url = f"https://crt.sh/?q=%25{company_name}%25&output=json"
    print(f"\nSearching for legitimate domains for: '{company_name}' ...")

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=20.0)

        if response.status_code == 200:
            certificates = response.json()
            domains = set()
            for cert in certificates:
                names = cert['common_name'].split('\n')
                for name in names:
                    clean_name = name
                    if clean_name.startswith("www."):
                        clean_name = clean_name[4:]
                    if clean_name.startswith("*."):
                        clean_name = clean_name[2:]
                    clean_name = clean_name.strip()
                    domains.add(clean_name)
            return list(domains)
        else:
            print("Error: could not connect to crt.sh")
            return []
    except httpx.ReadTimeout:
        print("Timeout al consultar crt.sh")
        return []

async def search_company_domains_securitytrails(company_apex: str, api_key: str | None = None) -> list:
    """
    Consulta el endpoint /v1/query/scroll de SecurityTrails con una query SQL que
    extrae todos los hostnames cuyo apex domain coincide con company_apex.
    - Devuelve una lista de dominios/subdominios en minúsculas.
    - Requiere SECURITYTRAILS_APIKEY en entorno si no se pasa api_key.
    """
    api_key = api_key or os.getenv("SECURITYTRAILS_APIKEY")
    if not api_key:
        print("securitytrails(scroll): no API key provided (SECURITYTRAILS_APIKEY)")
        return []

    headers = {
        "apikey": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    query = f'SELECT domain.hostname FROM hosts WHERE domain.apex = "{company_apex}"'
    url = "https://api.securitytrails.com/v1/query/scroll"
    results = set()
    scroll_id = None

    print(f"\n[securitytrails/scroll] Searching hostnames for apex: '{company_apex}' ...")

    try:
        async with httpx.AsyncClient() as client:
            while True:
                payload = {"query": query}
                if scroll_id:
                    payload["scroll_id"] = scroll_id

                resp = await client.post(url, headers=headers, json=payload, timeout=30.0)

                if resp.status_code != 200:
                    print(f"securitytrails scroll: status {resp.status_code}")
                    return [company_apex.lower()]

                data = resp.json()
                scroll_id = data.get("scroll_id")
                records = data.get("records", [])

                if not records:
                    break

                for rec in records:
                    hostname = rec.get("domain", {}).get("hostname")
                    if hostname:
                        results.add(hostname.lower())

                # Si no hay scroll_id o ya no hay más páginas, salimos
                if not scroll_id or len(records) < 1000:
                    break

        return sorted(results)

    except httpx.ReadTimeout:
        print("securitytrails scroll: request timed out")
        return sorted(results) if results else [company_apex.lower()]
    except Exception as e:
        print(f"securitytrails scroll: unexpected error: {e}")
        return sorted(results) if results else [company_apex.lower()]
    
def find_tranco(src_root_domain: str):
    t = Tranco(cache=True, cache_dir='.tranco')
    latest_list = t.list(subdomains=True, full=True)

    custom_list = list()
    for d in latest_list.list:
        if d.endswith(src_root_domain):
            tup = (d, latest_list.rank(d))
            custom_list.append(tup)

    custom_list.sort(key=lambda x: x[1])  

    return custom_list

async def sanitize_mail_deprecated(email):
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

async def main():
    l = await search_company_domains_securitytrails(
        "ngabogados.es",
        api_key="hrtHSHu9FuTDkECIu34TawiHfLfYDTOc"
    )
    print(l)

if __name__ == "__main__":
    asyncio.run(main())