import httpx
import os
from tranco import Tranco

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