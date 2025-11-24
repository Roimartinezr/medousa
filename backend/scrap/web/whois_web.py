import requests
from bs4 import BeautifulSoup

WHOIS_URL = "https://www.whois.com/whois/{domain}"


def _fetch_whois_html(domain: str) -> str | None:
    """
    Descarga el HTML de la página de whois.com para el dominio dado.
    Devuelve el HTML como string o None si hay error.
    """
    url = WHOIS_URL.format(domain=domain)
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
    }

    resp = requests.get(url, headers=headers, timeout=15)
    if resp.status_code != 200:
        return None
    return resp.text


def _parse_registrant_contact(html: str) -> dict[str, str]:
    """
    Busca el bloque 'Registrant Contact' y devuelve un dict
    { 'Organization': '...', 'State': '...', 'Country': '...', ... }
    """
    soup = BeautifulSoup(html, "html.parser")

    # Bloques de datos (df-block)
    blocks = soup.find_all("div", class_="df-block")

    registrant_block = None
    for block in blocks:
        heading = block.find("div", class_="df-heading")
        if heading and "Registrant Contact" in heading.get_text(strip=True):
            registrant_block = block
            break

    result: dict[str, str] = {}
    if not registrant_block:
        return result

    # Cada fila tiene df-label y df-value
    for row in registrant_block.find_all("div", class_="df-row"):
        label_el = row.find("div", class_="df-label")
        value_el = row.find("div", class_="df-value")
        if not label_el or not value_el:
            continue

        label = label_el.get_text(strip=True).rstrip(":")
        value = value_el.get_text(strip=True)
        result[label] = value

    return result


def get_registrant_country_code(domain: str) -> str | None:
    """
    Devuelve el código de país (campo 'Country' en 'Registrant Contact')
    OJO: coge el país, NO el estado. Por ejemplo, para ups.com -> 'US'.
    """
    html = _fetch_whois_html(domain)
    if not html:
        return None

    data = _parse_registrant_contact(html)
    # Aquí cogemos SOLO el country, no el State:
    country = data.get("Country")
    return country or None


def get_registrant_organization(domain: str) -> str | None:
    """
    Devuelve la 'Registrant Organization' (campo 'Organization')
    del bloque 'Registrant Contact'.
    """
    html = _fetch_whois_html(domain)
    if not html:
        return None

    data = _parse_registrant_contact(html)
    org = data.get("Organization")
    return org or None


if __name__ == "__main__":
    dominio = "ups.com"
    country = get_registrant_country_code(dominio)
    org = get_registrant_organization(dominio)

    print("Domain:", dominio)
    print("Registrant Country:", country)
    print("Registrant Organization:", org)
