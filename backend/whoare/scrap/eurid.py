import httpx
import logging
import re
import base64
import urllib.parse
from typing import Dict, Any, Optional, List

# Configuración del logger
logger = logging.getLogger(__name__)

# --- HELPERS DE DECODIFICACIÓN ---

def decode_xor_email(encoded_email: str, key: str) -> str:
    """Descifra los emails ofuscados por EURid."""
    try:
        decoded_bytes = base64.b64decode(encoded_email)
        result_chars = []
        key_len = len(key)
        for i, byte_val in enumerate(decoded_bytes):
            key_char_code = ord(key[i % key_len])
            decoded_char = chr(byte_val ^ key_char_code)
            result_chars.append(decoded_char)
        return urllib.parse.unquote("".join(result_chars))
    except Exception:
        return ""

def clean_html_fragment(text: str) -> str:
    """Limpia etiquetas HTML, descifra datos ofuscados y formatea texto."""
    if not text: return ""
    
    # 1. BÚSQUEDA Y REEMPLAZO DE BLOQUES OFUSCADOS
    xor_pattern = re.compile(r'<(\w+)[^>]*data-xor-(?:email|text)="[^"]+"[^>]*>.*?</\1>', re.DOTALL)
    
    def replace_xor_block(match):
        block = match.group(0)
        payload_m = re.search(r'data-xor-(?:email|text)="([^"]+)"', block)
        key_m = re.search(r'data-xor-key="([^"]+)"', block)
        
        if payload_m and key_m:
            decrypted = decode_xor_email(payload_m.group(1), key_m.group(2))
            if decrypted: return decrypted
        
        mailto_m = re.search(r'href="mailto:([^"]+)"', block)
        if mailto_m: return urllib.parse.unquote(mailto_m.group(1))
        return block

    text = xor_pattern.sub(replace_xor_block, text)
    
    # 2. Limpieza estándar
    text = re.sub(r'<br\s*/?>', ' | ', text)
    text = re.sub(r'<[^>]+>', '', text)
    text = text.replace("&nbsp;", " ").replace("\t", " ").strip()
    text = re.sub(r'\s+', ' ', text)
    text = re.sub(r'^\|\s*', '', text)
    text = re.sub(r'\s*\|$', '', text)
    
    return text

# --- PARSER GENÉRICO ---

def parse_generic_section(html_chunk: str) -> Any:
    """
    Analiza un bloque HTML. Devuelve Dict si hay clave-valor, o List si hay items.
    """
    section_data = {}
    
    # 1. Pares Clave-Valor
    dl_pattern = re.compile(r'<dt[^>]*>(.*?)</dt>\s*<dd[^>]*>(.*?)</dd>', re.DOTALL | re.IGNORECASE)
    pairs = dl_pattern.findall(html_chunk)
    
    if pairs:
        for key_raw, val_raw in pairs:
            k = clean_html_fragment(key_raw).replace(":", "")
            v = clean_html_fragment(val_raw)
            
            # Agrupar Name Servers bajo una misma clave base
            if "name server" in k.lower() and "#" in k:
                k = "Name servers"
            
            if k in section_data:
                if isinstance(section_data[k], list):
                    section_data[k].append(v)
                else:
                    section_data[k] = [section_data[k], v]
            else:
                section_data[k] = v
                
    # 2. Listas simples
    li_pattern = re.compile(r'<li[^>]*>(.*?)</li>', re.DOTALL | re.IGNORECASE)
    list_items = li_pattern.findall(html_chunk)
    if list_items:
        clean_items = [clean_html_fragment(i) for i in list_items if clean_html_fragment(i)]
        if clean_items:
            if section_data:
                section_data["list_items"] = clean_items
            else:
                return clean_items 
                
    # 3. Dominios Similares
    similar_rows = re.findall(r'<div class="distance-line"[^>]*>(.*?)</div>', html_chunk, re.DOTALL)
    if similar_rows:
        section_data["similar_domains_list"] = [clean_html_fragment(row) for row in similar_rows]

    # 4. Fallback Texto
    if not section_data and not list_items and not similar_rows:
        text_content = clean_html_fragment(html_chunk)
        if len(text_content) > 3:
            return text_content

    return section_data

def parse_full_page(html: str) -> Dict[str, Any]:
    """
    Recorre el HTML y aplana la estructura: Parent_Key = Value.
    """
    flat_data = {}
    
    def process_content(title, content_html):
        # Limpiar el título para usarlo como prefijo
        prefix = clean_html_fragment(title).replace(" ", "_")
        if not prefix: prefix = "Unknown"
        
        parsed = parse_generic_section(content_html)
        
        if isinstance(parsed, dict):
            for key, val in parsed.items():
                # APLANADO: Prefijo_Clave = Valor
                flat_key = f"{prefix}_{key}"
                flat_data[flat_key] = val
        elif parsed:
            # Si devuelve lista o string directo, usamos el prefijo como clave
            flat_data[prefix] = parsed

    # PATRÓN 1: Etiquetas <section>
    section_matches = re.finditer(r'<section[^>]*>(.*?)</section>', html, re.DOTALL | re.IGNORECASE)
    for match in section_matches:
        content = match.group(1)
        title_match = re.search(r'<h2[^>]*>(.*?)</h2>', content, re.DOTALL | re.IGNORECASE)
        title = title_match.group(1) if title_match else "Unlabeled_Section"
        process_content(title, content)

    # PATRÓN 2: Tarjetas laterales (<div class="card">)
    card_matches = re.finditer(r'<div class="card[^"]*"[^>]*>(.*?)</div>\s*</div>', html, re.DOTALL | re.IGNORECASE)
    for match in card_matches:
        content = match.group(1)
        header_match = re.search(r'<div class="card-header"[^>]*>(.*?)</div>', content, re.DOTALL | re.IGNORECASE)
        
        if header_match:
            title_raw = header_match.group(1)
            h2_in_header = re.search(r'<h2[^>]*>(.*?)</h2>', title_raw, re.DOTALL | re.IGNORECASE)
            title = h2_in_header.group(1) if h2_in_header else title_raw
            
            body_match = re.search(r'<div class="card-body"[^>]*>(.*?)</div>', content, re.DOTALL | re.IGNORECASE)
            if body_match:
                process_content(title, body_match.group(1))

    return flat_data

# --- MAIN ---

async def main(domain: str) -> Optional[Dict[str, Any]]:
    url = "https://whois.eurid.eu/en/search/"
    domain = domain.strip().lower()
    tld = domain.split('.')[-1] if '.' in domain else 'eu'

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 OPR/124.0.0.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "es-ES,es;q=0.9",
        "Priority": "u=0, i",
        "Referer": "https://whois.eurid.eu/en/search/",
        "Sec-Ch-Ua": '"Chromium";v="140", "Not=A?Brand";v="24", "Opera";v="124"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1"
    }

    cookies = {
        "waap_id": "86UOuxGpRFz6TB/AHtp5QY/LGTMkVRhqMlb3AJQZTGJ2TwIiUGIIsjhAh7Ri74SfKW7FVlt842S2NNZi5K+/UBIL3uy8K6oJcFbZhbrwMhGPabyLOqKZc3JYv6oHsqunJwX8DOe4mXiNslqTOHovP+J3BZjM2amScmrkcDvE7jNNhxylusKpehknPbMRtaOsQo+uIBGmR15Ab1PVTEDAo8z7cKhA6e71SqGFDJDzlOLJ6WaOkercGdYGRuhPo93ZtxEIhxbvZmeG0IwKOG0_",
        "csrftoken": "cA8QbpgyokmlSWJh0blXNaOzzTqu0hg6RWhWCuxUaKVCx4GkCUTsyrQnJ14U8rIv",
        "persist": "!9nCmskOXy3Bp4P9woxDnRdda4ILpL4smkHiUgyqCvgQRs4tG49Nw4HnqxzKQ+TefgsrhD6nGGn5tHnUeJEUTRNaz9AWj26DDvnb2YF5E",
        "TS01e4f6b4": "012857a8cb0ce6b76bc322aebac09644a2cd7f4c67cc02cb8466837cd3d163e286b4ef7f1d8811f5544ed5105889615fc73b2d62de2ad430679db5dad1dea53e4c87c9adf0474cca93a17f1de14626ee4fd5a9c56ef6746995ede57bcaae013b3712fc7141",
        "CookieConsent": "{stamp:'4xYK3vUdB4ywTdtVOsAVkiPRd4Qon0D48kFm9wY9bJ43f4Y1yDWnkQ==',necessary:true,preferences:false,statistics:false,marketing:false,method:'explicit',ver:3,utc:1764169746346,region:'es'}"
    }

    params = {"domain": domain}

    logger.debug(f"Scraping plano EURid para: {domain}")

    async with httpx.AsyncClient(http2=True, follow_redirects=True, timeout=15.0) as client:
        try:
            response = await client.get(url, params=params, headers=headers, cookies=cookies)
            
            if response.status_code == 200:
                raw_html = response.text
                
                # Obtenemos el diccionario plano (prefijo_clave = valor)
                flat_data = parse_full_page(raw_html)
                
                # --- CAMBIO AQUÍ: MERGE AL ROOT ---
                # Creamos el resultado base
                result = {
                    "domain": domain,
                    "tld": tld
                }
                # Mezclamos los datos scrapeados directamente en la raíz
                if flat_data:
                    result.update(flat_data)
                    
                return result

            elif response.status_code == 247:
                logger.error(f"Bloqueo WAF (247). Renovar cookies.")
                return None
            else:
                logger.warning(f"Error HTTP EURid: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Excepción en eurid.py: {e}")
            return None

"""if __name__ == "__main__":
    import asyncio
    import json
    import sys

    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    async def test():
        domain = "santen.eu" 
        print(f"Probando extracción PLANA SIN PARSED para {domain}...")
        res = await main(domain)
        if res:
            print(json.dumps(res, indent=2, ensure_ascii=False))
        else:
            print("Error: No se obtuvieron datos.")

    try:
        asyncio.run(test())
    except KeyboardInterrupt:
        pass"""