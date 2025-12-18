#app/backend/scrap/service/service.py
from pathlib import Path
import tldextract
import asyncio
from service.ascii_cctld_service import get_all_ascii_cctld_ids
from service.idn_cctld_service import get_all_idn_cctld_ids
from service.ascii_geotld_service import get_all_ascii_geotld_ids
from .get_whois_service import get_whois_cctld, get_whois_gtld

# PRODUCCION / DESARROLLO
DEV = False

class WhoareServiceError(Exception):
    """Clase base para todas las excepciones de este servicio."""
    pass
class NotSupportedTLDError(WhoareServiceError):
    """Se lanza cuando el dominio no es válido o está vacío."""
    pass

class WhoareService:

    @staticmethod
    async def whoare(domain: str, dev = DEV):
        if not domain:
            return None

        tld = tldextract.extract(domain).suffix.split('.')[-1]

        ascii_cctls = get_all_ascii_cctld_ids(dev=dev)
        idn_cctlds = get_all_idn_cctld_ids(dev=dev)
        ascii_geotlds = get_all_ascii_geotld_ids(dev=dev)

        if tld in ascii_cctls or tld in idn_cctlds or tld in ascii_geotlds:
            
            current_dir = Path(__file__).resolve().parent
            adapters_path = current_dir.parent / "adapters"

            if adapters_path.exists():
                supported_tld = [file.stem for file in adapters_path.glob("*.json")]
                
            
                if tld not in supported_tld:
                    raise NotSupportedTLDError(
                        f'El TLD: <.{tld}> no se encuentra actualmente soportado'
                    )
                else:
                    if tld in ascii_geotlds:
                        return await get_whois_cctld(domain, geoTLD=True, dev=dev)
                    return await get_whois_cctld(domain, dev=dev)

            else:
                raise WhoareServiceError(
                    f"\n[ERROR DE CARGA]\n"
                    f"No se encuentra la ruta a la carpeta de adaptadores"
                )
        else:
            return await get_whois_gtld(domain)


"""
if __name__ == "__main__":
    print(asyncio.run(WhoareService.whoare("bancosantander.com")))"""