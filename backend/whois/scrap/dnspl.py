import logging
import json
from typing import Optional, Dict, Any, List
from playwright.async_api import async_playwright
import httpx

# Usamos el logger del módulo
logger = logging.getLogger(__name__)

# --- HELPER: FLATTENER PERSONALIZADO ---

def flatten_response(data: Dict[str, Any], parent_key: str = '', sep: str = '_') -> Dict[str, Any]:
    """
    Aplana un diccionario JSON recursivamente.
    - Dicts: Se concatenan las claves (ej: registrant_name).
    - Listas de objetos: Se agrupan los valores bajo la misma clave (ej: nameservers_name = [ns1, ns2]).
    """
    items = {}
    for k, v in data.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        
        if isinstance(v, dict):
            # Caso 1: Diccionario anidado -> Recursión
            # (ej: registrant: {name: ...} -> registrant_name: ...)
            items.update(flatten_response(v, new_key, sep=sep))
            
        elif isinstance(v, list):
            # Caso 2: Listas
            if not v:
                continue # Lista vacía, la ignoramos o podríamos poner new_key: []
            
            # Si la lista contiene diccionarios (ej: nameservers)
            if isinstance(v[0], dict):
                # Agregamos los valores de cada objeto en listas bajo la clave aplanada
                # nameservers: [{name: a}, {name: b}] -> nameservers_name: [a, b]
                aggregated = {}
                for item in v:
                    if isinstance(item, dict):
                        # Aplanamos el item individualmente sin prefijo extra para procesarlo
                        flat_item = flatten_response(item, new_key, sep=sep)
                        for sub_k, sub_v in flat_item.items():
                            if sub_k not in aggregated:
                                aggregated[sub_k] = []
                            aggregated[sub_k].append(sub_v)
                items.update(aggregated)
            else:
                # Si es lista de strings/ints (ej: status: ["active", "ok"]), se queda tal cual
                items[new_key] = v
        else:
            # Caso 3: Valor primitivo (str, int, bool, None)
            items[new_key] = v
            
    return items

# --- SCRAPER CLASS ---

class DnsPlScraper:
    def __init__(self):
        self.api_url = "https://dns.pl/api/who-is-xml/en"
        self.site_key = "6LfS1D8pAAAAAHqAEH9owz5fcGu3hhZ2h5hRTMlV"
        
        self.api_headers = {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Origin": "https://dns.pl",
            "Referer": "https://dns.pl/en/whois",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
        }

    async def _get_real_token(self) -> tuple[Optional[str], Optional[dict]]:
        """
        Levanta un navegador headless para resolver el captcha de Google.
        """
        logger.debug("Iniciando Playwright para obtener token de dns.pl...")
        
        async with async_playwright() as p:
            try:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    user_agent=self.api_headers["User-Agent"]
                )
                page = await context.new_page()

                # 1. Cargar contexto
                await page.goto("https://dns.pl/en/whois", wait_until="networkidle")
                
                # 2. Esperar script de captcha
                try:
                    await page.wait_for_function("() => window.grecaptcha && window.grecaptcha.execute", timeout=10000)
                except Exception:
                    logger.warning("Timeout esperando carga de grecaptcha.")
                    await browser.close()
                    return None, None

                # 3. Ejecutar
                token = await page.evaluate(f"""
                    grecaptcha.execute('{self.site_key}', {{action: 'submit'}})
                """)
                
                # 4. Cookies
                cookies = await context.cookies()
                cookie_dict = {c['name']: c['value'] for c in cookies}
                
                await browser.close()
                return token, cookie_dict

            except Exception as e:
                logger.error(f"Error en Playwright (dnspl): {e}")
                return None, None

    async def scrape(self, domain: str) -> Optional[Dict[str, Any]]:
        # 1. Obtener Token
        token, cookies = await self._get_real_token()
        
        if not token:
            logger.warning(f"No se pudo generar el token captcha para {domain}")
            return None

        # 2. Consultar API
        payload = {
            "name": domain,
            "captcha": token
        }

        async with httpx.AsyncClient(http2=True, timeout=15.0) as client:
            try:
                logger.debug(f"Consultando API dns.pl para: {domain}")
                response = await client.post(
                    self.api_url, 
                    json=payload, 
                    headers=self.api_headers, 
                    cookies=cookies
                )

                if response.status_code == 200:
                    raw_data = response.json()
                    
                    if "error" in raw_data: 
                         logger.warning(f"API dns.pl error: {raw_data}")
                         return None
                    
                    # --- APLICAMOS EL APLANADO AQUÍ ---
                    flat_data = flatten_response(raw_data)
                    return flat_data
                
                elif response.status_code == 404:
                    logger.info(f"Dominio {domain} no encontrado")
                    return None
                else:
                    logger.error(f"Error HTTP dns.pl: {response.status_code}")
                    return None

            except Exception as e:
                logger.error(f"Excepción conectando a API dns.pl: {e}")
                return None

# --- PUNTO DE ENTRADA DINÁMICO ---

async def main(domain: str) -> Optional[Dict[str, Any]]:
    scraper = DnsPlScraper()
    return await scraper.scrape(domain)

# --- TEST LOCAL ---
if __name__ == "__main__":
    import asyncio
    logging.basicConfig(level=logging.INFO)

    async def test():
        domain = "allegro.pl"
        print(f"Testeando dnspl (aplanado) para: {domain}...")
        result = await main(domain)
        if result:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print("Falló o no encontrado.")

    asyncio.run(test())