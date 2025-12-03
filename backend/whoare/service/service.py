#app/backend/scrap/service/service.py
from pathlib import Path
import tldextract
import asyncio
from ...service.ascii_cctld_service import get_all_ascii_cctld_ids
from ...service.idn_cctld_service import get_all_idn_cctld_ids
from .get_whois_service import get_whois_cctld, get_whois_gtld
from opensearchpy import OpenSearch

class WhoareServiceError(Exception):
    """Clase base para todas las excepciones de este servicio."""
    pass
class NotSupportedTLDError(WhoareServiceError):
    """Se lanza cuando el dominio no es válido o está vacío."""
    pass

def get_client() -> OpenSearch:
        return OpenSearch(
            hosts=[{"host": "localhost", "port": "9200"}],
            http_compress=True,
            use_ssl=False,
            verify_certs=False,
            ssl_show_warn=False,
        )

class WhoareService:

    @staticmethod
    async def whoare(domain: str):
        if not domain:
            return None

        tld = tldextract.extract(domain).suffix.split('.')[-1]

        if tld in get_all_ascii_cctld_ids() or tld in get_all_idn_cctld_ids():

            current_dir = Path(__file__).resolve().parent
            adapters_path = current_dir.parent / "adapters"

            if adapters_path.exists():
                supported_tld = [file.stem for file in adapters_path.glob("*.json")]
                
            
                if tld not in supported_tld:
                    raise NotSupportedTLDError(
                        f'El TLD: <.{tld}> no se encuentra actualmente soportado'
                    )
                else:
                    return await get_whois_cctld(domain)

            else:
                raise WhoareServiceError(
                    f"\n[ERROR DE CARGA]\n"
                    f"No se encuentra la ruta a la carpeta de adaptadores"
                )
        else:
            return await get_whois_gtld(domain)


"""if __name__ == "__main__":
    print(asyncio.run(WhoareService.whoare("bancosantander.com")))"""