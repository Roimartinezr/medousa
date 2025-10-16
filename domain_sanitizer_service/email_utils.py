# app/services/domain_sanitizer_service/email_utils.py
import re
from email_validator import validate_email, caching_resolver, EmailNotValidError
from Levenshtein import distance
import tldextract
import httpx


KNOWN_BRANDS = ["bbva", "santander", "paypal", "amazon", "microsoft", "google"]

OMIT_WORDS = {
    "www","mail","secure","info","login","cliente","clientes",
    "web","app","email","alerta","soporte","acceso","online",
    "account","accounts","banco","seguridad","support"
}


async def search_company_domains(company_name):
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


def extract_company_from_domain(domain, max_dist=2):
    """
    Pipeline completa:
    1. Normaliza el dominio
    2. Extrae candidatos
    3. Pondera por posición
    4. Aplica fuzzy matching contra marcas conocidas
    5. Devuelve la compañía más probable + score de confianza
    """


    # Normalizar: minúsculas 
    clean_domain = re.sub(r"[-.]", ".", domain.lower())

    # tldextract para quitar subdominios y TLDs (busca en la Public Suffix List)
    # solo detecta separador de puntos, no guiones
    clean_domain = tldextract.extract(clean_domain).domain  # extrae solo el dominio base

    # Separar los posibles prefijos restantes
    words = re.sub(r"[-.]", " ", clean_domain).split(" ")
    # Contrastar contra la whitelist de palabras omitibles, palabra por palaba de words
    candidates = [w for w in words if w not in OMIT_WORDS and len(w) >= 2]

    # Si no hay candidatos = romper convenio de dominio antes del (.com, .org, etc) = posible fraude
    if not candidates:
        # fallback: no quedan candidatos tras limpiar
        return {"company": None, "confidence": 0, "source": "no_candidates"}

    scored = []
    n = len(candidates)

    for i, w in enumerate(candidates):
        # Elimina subcadenas que coincidan con OMIT_WORDS
        for omit in OMIT_WORDS:
            if omit in w:
                w = w.replace(omit, "")
        w_norm = w.strip()

        # Puntuación base por posición
        score = 0
        if i == 0: score += 1       # inicio
        if i == n // 2: score += 2  # centro
        if i == n - 1: score += 1   # final

        # Fuzzy matching contra marcas conocidas
        match, dist = fuzzy_brand_match(w_norm, KNOWN_BRANDS, max_dist=max_dist)
        if match:
            score += 3  # bonificación por match cercano
            scored.append((match, score, dist))
        else:
            scored.append((w_norm, score, dist))

    # Elegir la palabra/marca con mayor score, y en empate la más parecida
    scored.sort(key=lambda x: (x[1], -x[2]), reverse=True)
    best = scored[0]

    # Calcular confianza (heurística simple)
    confidence = 50 + best[1]*10 - best[2]*5
    confidence = max(0, min(100, confidence))

    return {"company": best[0], "confidence": confidence, "source": "heuristic"}
