#app/backend/scrap/service/service.py
from pathlib import Path
import tldextract
import asyncio

class WhoareServiceError(Exception):
    """Clase base para todas las excepciones de este servicio."""
    pass
class NotSupportedTLDError(WhoareServiceError):
    """Se lanza cuando el dominio no es válido o está vacío."""
    pass

class WhoareService:

    @staticmethod
    async def whoare(dominio: str):
        if not dominio:
            return None

        current_dir = Path(__file__).resolve().parent
        adapters_path = current_dir.parent / "adapters"

        if adapters_path.exists():
            supported_tld = [file.stem for file in adapters_path.glob("*.json")]
            
            tld = tldextract.extract(dominio).suffix.split('.')[-1]
            if tld not in supported_tld:
                raise NotSupportedTLDError(
                    f'El TLD: <.{tld}> no se encuentra actualmente soportado'
                )


        else:
            raise WhoareServiceError(
                f"\n[ERROR DE CARGA]\n"
                f"No se encuentra la ruta a la carpeta de adaptadores"
            )


if __name__ == "__main__":
    asyncio.run(WhoareService.whoare("hola.ng"))