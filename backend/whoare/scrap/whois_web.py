import requests
from bs4 import BeautifulSoup
from typing import Any, Dict, Optional

WHOIS_URL = "https://www.whois.com/whois/{domain}"


# ----------------------------- helpers genéricos ----------------------------- #

def _slugify(s: str) -> str:
    """
    Normaliza etiquetas a snake_case genérico:
      'Domain Name' -> 'domain_name'
      'Expires On'  -> 'expires_on'
    """
    s = (s or "").strip().lower()
    for ch in [" ", "\t", "\n", "\r", "/", "-", "."]:
        s = s.replace(ch, "_")
    while "__" in s:
        s = s.replace("__", "_")
    return s.strip("_")

def _ua_section_prefix(line: str) -> Optional[str]:
    """
    Dada una línea que empieza por '%', detecta si es cabecera de bloque .ua
    y devuelve el prefijo de clave correspondiente (con '_' al final).
    """
    ll = line.lower().lstrip("%").strip()  # quita '%' y espacios

    if ll.startswith("registrar"):
        return "registrar_"
    if ll.startswith("registrant"):
        return "registrant_"
    if ll.startswith("administrative"):
        # Para "% Administrative Contacts:"
        return "administrative_contacts_"
    if ll.startswith("technical"):
        # Para "% Technical Contacts:"
        return "technical_contacts_"

    return None

def _fetch_whois_html(domain: str) -> Optional[str]:
    """
    Descarga el HTML de whois.com para el dominio dado.
    Devuelve el HTML como string o None si hay error / status != 200.
    """
    url = WHOIS_URL.format(domain=domain)
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
    }
    try:
        resp = requests.get(url, headers=headers, timeout=15)
    except requests.RequestException:
        return None

    if resp.status_code != 200:
        return None
    return resp.text


# ----------------------------- RAW Whois Data ----------------------------- #

def _extract_raw_whois(soup: BeautifulSoup) -> Optional[str]:
    """
    Busca el bloque de 'Raw Whois Data' en el HTML y devuelve el texto del <pre>.
    No asume un único patrón, intenta varias variantes habituales.
    """
    # Caso típico: <pre id="registryData" class="df-raw">
    pre = soup.find("pre", id="registryData")
    if pre:
        return pre.get_text("\n", strip=True)

    # Variante: cualquier <pre class="df-raw">
    pre = soup.find("pre", class_="df-raw")
    if pre:
        return pre.get_text("\n", strip=True)

    # Variante: df-block cuyo heading contenga "Raw Whois Data"
    for block in soup.find_all("div", class_="df-block"):
        heading = block.find("div", class_="df-heading")
        if not heading:
            continue
        title = heading.get_text(strip=True)
        if "raw whois data" in title.lower():
            pre = block.find("pre")
            if pre:
                return pre.get_text("\n", strip=True)

    return None

def _whois_text_to_json_full(whois_text: str) -> Dict[str, Any]:
    """
    Parser genérico de texto WHOIS:
      - Cada línea 'Key: Value' -> result[key_normalizada] = value
      - Claves repetidas -> lista de valores
      - Líneas sin ':' se conservan en '__non_key_lines__'
    No se descarta ningún campo con 'clave: valor' que aparezca en el texto.
    """
    result: Dict[str, Any] = {}
    non_key_lines = []

    for raw_line in whois_text.splitlines():
        line = raw_line.rstrip("\r\n")
        stripped = line.strip()
        if not stripped:
            continue

        if ":" not in stripped:
            # No es "clave: valor" → la conservamos aparte
            non_key_lines.append(line)
            continue

        key_raw, val_raw = stripped.split(":", 1)
        key = _slugify(key_raw)
        val: Any = val_raw.strip() or None

        if key in result:
            existing = result[key]
            if isinstance(existing, list):
                existing.append(val)
            else:
                result[key] = [existing, val]
        else:
            result[key] = val

    return result

def _whois_text_to_json_full_ua(whois_text: str) -> Dict[str, Any]:
    """
    Parser especial para WHOIS RAW de dominios .ua.

    Reglas:
      - Antes de cualquier cabecera de bloque ('% Registrar:', '% Registrant:', etc.)
        se parsea normal: las keys quedan tal cual (domain, status, created, source, ...).
      - A partir de '% Registrar:' se añade un prefijo al campo:
            registrar_<key_normalizada>
        lo mismo para:
            registrant_<key>
            administrative_contacts_<key>
            technical_contacts_<key>
      - Dentro de cada prefijo, si una key se repite (p.ej. status: ok, status: linked),
        se permite lista [ok, linked], pero NUNCA se mezclan secciones distintas
        porque el prefijo ya las separa.
    """
    result: Dict[str, Any] = {}
    current_prefix = ""  # "" = datos generales; luego 'registrar_', 'registrant_', ...

    for raw_line in whois_text.splitlines():
        line = raw_line.rstrip("\r\n")
        stripped = line.strip()
        if not stripped:
            continue

        # Comentarios / encabezados que empiezan por '%'
        if stripped.startswith("%"):
            prefix = _ua_section_prefix(stripped)
            if prefix is not None:
                current_prefix = prefix
            # Resto de líneas con '%' (disclaimers, query time, etc.) se ignoran
            continue

        # Solo líneas "clave: valor"
        if ":" not in stripped:
            continue

        key_raw, val_raw = stripped.split(":", 1)
        key_base = _slugify(key_raw.strip())  # p.ej. 'status', 'source', 'organization_loc'
        if not key_base:
            continue

        # Aplica prefijo según la sección actual
        key = f"{current_prefix}{key_base}" if current_prefix else key_base
        val: Any = val_raw.strip() or None

        if key in result:
            existing = result[key]
            if isinstance(existing, list):
                existing.append(val)
            else:
                result[key] = [existing, val]
        else:
            result[key] = val

    # Marca la fuente como RAW
    result["__source__"] = "raw"
    return result


# ----------------------------- Bloques embellecidos ----------------------------- #

def _parse_blocks_to_flat(soup: BeautifulSoup) -> Dict[str, Any]:
    """
    Parsea todos los bloques .df-block de la vista embellecida.

    No filtra por tipo ni por sección:
      - Cada bloque tiene un heading (Domain Information, Registrar Information, etc.)
      - Dentro hay filas df-row con df-label / df-value.
      - Para NO perder información ni chocar claves, se usa:
          <section>__<campo>
        p.ej:
          'domain_information__domain'
          'domain_information__registered_on'
          'registrant_contact__name'
          'domain_information__name_servers'
    """
    flat: Dict[str, Any] = {}

    blocks = soup.find_all("div", class_="df-block")
    for block in blocks:
        heading_el = block.find("div", class_="df-heading")
        heading_text = heading_el.get_text(strip=True) if heading_el else ""
        section = _slugify(heading_text) or "section"

        for row in block.find_all("div", class_="df-row"):
            label_el = row.find("div", class_="df-label")
            value_el = row.find("div", class_="df-value")
            if not label_el or not value_el:
                continue

            label_raw = label_el.get_text(strip=True).rstrip(":")
            field = _slugify(label_raw) or "field"

            key = f"{section}__{field}"

            # Texto(s) del valor: si hay <br>, obtenemos varios
            texts = list(value_el.stripped_strings)
            if not texts:
                val: Any = None
            elif len(texts) == 1:
                val = texts[0]
            else:
                val = texts

            if key in flat:
                existing = flat[key]
                if isinstance(existing, list):
                    if isinstance(val, list):
                        existing.extend(val)
                    else:
                        existing.append(val)
                    flat[key] = existing
                else:
                    if isinstance(val, list):
                        flat[key] = [existing, *val]
                    else:
                        flat[key] = [existing, val]
            else:
                flat[key] = val

    return flat


# ----------------------------- API principal: parser de TODO ----------------------------- #

def parse_whois_html_to_json(html: str, domain: Optional[str] = None) -> Dict[str, Any]:
    """
    Parser genérico de HTML de whois.com a JSON.

    Lógica:
      - Si existe RAW Whois Data:
          -> se usa EXCLUSIVAMENTE ese texto como fuente
          -> se parsea TODO 'clave: valor' que aparezca
          -> se devuelven esos campos + meta '__source__' = 'raw'
          -> si el dominio termina en .ua, se añaden contactos anidados en 'contacts'
      - Si NO existe RAW Whois Data:
          -> se usan los bloques embellecidos (.df-block)
          -> se suman TODAS las filas (sección__campo) sin filtrar
          -> se devuelve ese dict + meta '__source__' = 'blocks'
    """
    soup = BeautifulSoup(html, "html.parser")

    raw_text = _extract_raw_whois(soup)
    if raw_text:
        # --- Caso especial: .ua → prefijos por bloque (registrar_, registrant_, etc.)
        if domain and domain.lower().endswith(".ua"):
            return _whois_text_to_json_full_ua(raw_text)

        parsed = _whois_text_to_json_full(raw_text)
        parsed["__source__"] = "raw"
        return parsed

    flat = _parse_blocks_to_flat(soup)
    flat["__source__"] = "blocks"
    return flat



# ----------------------------- API de alto nivel (para tu pipeline) ----------------------------- #

async def main(domain: str) -> Dict[str, Any]:
    """
    Punto de entrada pensado para scrap_owner_service:
      w = await whois_web.main(domain)

    Devuelve SIEMPRE un dict con TODOS los campos parseados de la página de whois.com:
      - Si hay RAW: claves tipo 'domain_name', 'registry_expiry_date', 'name_server', ...
                     + '__non_key_lines__' (si las hay)
                     + '__source__' = 'raw'
                     + '__raw_text__' con el WHOIS crudo
      - Si no hay RAW: claves tipo 'domain_information__domain',
                       'domain_information__expires_on',
                       'registrant_contact__name',
                       ...
                       + '__source__' = 'blocks'
    """
    html = _fetch_whois_html(domain)
    if not html:
        # En error, devolvemos dict vacío pero válido
        return {"__source__": "error", "__error__": "no_html"}

    return parse_whois_html_to_json(html, domain=domain)


"""if __name__ == "__main__":
    # Debug local rápido (síncrono)
    import json
    dom = "kyivstar.ua"
    html = _fetch_whois_html(dom)
    if html:
        data = parse_whois_html_to_json(html, domain=dom)
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        print("No se pudo descargar el HTML de whois.com")"""
