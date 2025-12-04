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


async def main():
    l = await search_company_domains_securitytrails("ngabogados.es")
    print(l)

if __name__ == "__main__":
    asyncio.run(main())