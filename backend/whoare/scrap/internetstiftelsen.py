import logging
import json
import asyncio
from typing import Optional, Dict, Any
from playwright.async_api import async_playwright

# Logger del módulo backend
logger = logging.getLogger(__name__)

# --- HELPER: APLANAR JSON ---
def flatten_response(data: Dict[str, Any], parent_key: str = '', sep: str = '_') -> Dict[str, Any]:
    """Aplana el JSON para un formato de salida limpio y uniforme."""
    items = {}
    for k, v in data.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.update(flatten_response(v, new_key, sep=sep))
        elif isinstance(v, list):
            if v and isinstance(v[0], dict):
                aggregated = {}
                for item in v:
                    if isinstance(item, dict):
                        flat_item = flatten_response(item, new_key, sep=sep)
                        for sub_k, sub_v in flat_item.items():
                            if sub_k not in aggregated: aggregated[sub_k] = []
                            aggregated[sub_k].append(sub_v)
                items.update(aggregated)
            else:
                items[new_key] = v
        else:
            items[new_key] = v
    return items

# --- CLASE SCRAPER ---
class IISScraper:
    def __init__(self):
        self.url = "https://internetstiftelsen.se/en/search-domains/"

    async def scrape(self, domain: str) -> Optional[Dict[str, Any]]:
        logger.info(f"Iniciando scraper completo (internetstiftelsen) para: {domain}")
        
        async with async_playwright() as p:
            # 1. Configuración de evasión
            browser = await p.chromium.launch(
                headless=True,
                args=["--disable-blink-features=AutomationControlled", "--no-sandbox"]
            )
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                viewport={'width': 1920, 'height': 1080},
                locale='en-US'
            )
            await context.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            
            page = await context.new_page()

            # --- VARIABLES PARA ALMACENAR DATOS ---
            whois_data_parts = {
                "basic": {},   # Aquí guardaremos fechas, estado, ns...
                "contact": {}  # Aquí guardaremos email, org, address...
            }

            # --- LISTENER DE RED (La "oreja" digital) ---
            # Escuchamos todas las respuestas para cazar la info básica al vuelo
            async def handle_response(response):
                try:
                    url = response.url
                    # CAPTURA 1: Datos básicos (se obtienen al buscar)
                    if "wp-json/iis/v1/free/whois" in url and response.status == 200:
                        data = await response.json()
                        whois_data_parts["basic"] = data
                        logger.info("  -> [1/2] Datos básicos interceptados.")
                    
                    # CAPTURA 2: Datos de contacto (se obtienen tras el captcha)
                    # Nota: Lo capturamos aquí también por seguridad, aunque usamos expect_response abajo
                    elif "wp-json/iis/v1/friendlycaptcha" in url and response.status == 200:
                        data = await response.json()
                        whois_data_parts["contact"] = data
                        logger.info("  -> [2/2] Datos de contacto interceptados.")
                except:
                    pass

            # Activamos la escucha
            page.on("response", handle_response)

            try:
                # 2. Navegación
                await page.goto(self.url, wait_until="domcontentloaded")

                # 3. Cookies
                try:
                    accept_btn = page.locator("button#onetrust-accept-btn-handler")
                    if await accept_btn.is_visible(timeout=2000):
                        await accept_btn.click()
                        await page.wait_for_timeout(300)
                except: pass

                # 4. Búsqueda (Esto disparará la CAPTURA 1)
                input_selector = 'input[placeholder="Search available .se or .nu domain"]'
                await page.wait_for_selector(input_selector, state="visible")
                await page.fill(input_selector, domain)
                await page.click('button.submit-search')

                # 5. Expandir Información
                expand_btn = page.locator('button:has-text("View registration info")')
                await expand_btn.wait_for(state="visible", timeout=15000)
                await expand_btn.click()
                
                # 6. Resolver Captcha
                contact_btn = page.locator('button[data-whois-contact-details]')
                await contact_btn.wait_for(state="visible", timeout=10000)
                await contact_btn.scroll_into_view_if_needed()
                
                logger.info(f"Resolviendo captcha para {domain}...")

                # Esperamos explícitamente a la respuesta del captcha (CAPTURA 2)
                async with page.expect_response(
                    lambda response: "wp-json/iis/v1/friendlycaptcha" in response.url and response.status == 200,
                    timeout=90000 
                ) as response_info:
                    
                    await page.wait_for_timeout(500)
                    await contact_btn.click()
                    
                    # Reintento humano si se atasca
                    try:
                        async with page.expect_response(lambda r: "puzzle" in r.url, timeout=4000): pass 
                    except:
                        logger.debug("Reintentando clic...")
                        await contact_btn.click(force=True)

                # Nos aseguramos de tener la respuesta final del captcha
                final_captcha_data = await response_info.value
                whois_data_parts["contact"] = await final_captcha_data.json()

                # 7. FUSIÓN DE DATOS
                # Combinamos el diccionario básico con el de contacto
                combined_data = {**whois_data_parts["basic"], **whois_data_parts["contact"]}
                
                logger.info("Extracción completa y fusionada.")
                return flatten_response(combined_data)

            except Exception as e:
                logger.error(f"Error en scraper internetstiftelsen: {e}")
                # Si falló la parte del captcha pero tenemos la básica, devolvemos al menos eso
                if whois_data_parts["basic"]:
                    logger.warning("Devolviendo datos parciales (solo básicos).")
                    return flatten_response(whois_data_parts["basic"])
                return None
            finally:
                await browser.close()

# --- ENTRY POINT MODULAR ---
async def main(domain: str) -> Optional[Dict[str, Any]]:
    scraper = IISScraper()
    return await scraper.scrape(domain)

# --- TEST LOCAL ---
"""if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    async def test():
        # Prueba real
        res = await main("swedbank.se")
        print(json.dumps(res, indent=2, ensure_ascii=False))
    asyncio.run(test())"""