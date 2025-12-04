import httpx
import json
import asyncio
from typing import Optional, Dict, Any

class RDAPClient:
    """
    Cliente robusto para consultar información de dominios RDAP
    y normalizar la salida a un formato plano y legible.
    """
    def __init__(self):
        self.base_url = "https://rdap.nic.cx"
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Accept": "application/rdap+json, application/json, */*;q=0.8"
        }

    def _extract_vcard_field(self, vcard_array: list, field_name: str) -> Optional[str | list]:
        """Ayuda a extraer campos del formato jCard de RDAP (RFC 7095)"""
        if not vcard_array or len(vcard_array) < 2:
            return None
        
        # El vcard es ["vcard", [[prop1], [prop2]...]]
        properties = vcard_array[1]
        for prop in properties:
            # prop es ["nombre_campo", {params}, "tipo", "valor"]
            if prop[0] == field_name and len(prop) > 3:
                # Retorna el valor (índice 3, puede ser str o list)
                return prop[3]
        return None

    def normalize_data(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convierte el JSON crudo de RDAP al formato plano de un solo nivel.
        Las claves de ubicación tienen el prefijo 'country_'.
        """
        # Estructura base aplanada con valores por defecto
        normalized = {
            # Valores estáticos (gestionados externamente)
            "tld": "cx",
            "registry": "cxDA",

            # Valores de País (prefijo country_)
            "country_code": "",
            "country_state": "",
            "country_city": "",
            
            # Valores de Dominio/Contacto (keys principales)
            "domain_name": raw_data.get("ldhName", "N/A").lower(),
            "registrant": "",
            "registrant_name": "",
            "registrar": "",
            "emails": "",
            "creation_date": "",
            "expiration_date": "",
            "updated_date": "",
            "name_servers": [],
            "status": []
        }

        # 1. Parsear Fechas (Events)
        for event in raw_data.get("events", []):
            action = event.get("eventAction")
            date = event.get("eventDate")
            
            if action == "registration":
                normalized["creation_date"] = date
            elif action in ["expiration", "registrar expiration"]:
                normalized["expiration_date"] = date
            elif action in ["last changed", "last update of RDAP database"]:
                normalized["updated_date"] = date

        # 2. Parsear Nameservers
        ns_list = raw_data.get("nameservers", [])
        normalized["name_servers"] = [ns.get("ldhName") for ns in ns_list if ns.get("ldhName")]

        # 3. Parsear Status
        normalized["status"] = raw_data.get("status", [])

        # 4. Parsear Entidades (Registrar y Registrant)
        for entity in raw_data.get("entities", []):
            roles = entity.get("roles", [])
            vcard = entity.get("vcardArray")

            if "registrar" in roles:
                fn = self._extract_vcard_field(vcard, "fn")
                if fn:
                    normalized["registrar"] = fn
            
            # Buscamos Registrant o Administrative para los datos de contacto
            if "registrant" in roles or "administrative" in roles:
                fn = self._extract_vcard_field(vcard, "fn")
                org = self._extract_vcard_field(vcard, "org")
                email = self._extract_vcard_field(vcard, "email")
                adr = self._extract_vcard_field(vcard, "adr")
                
                # Para el Registrante principal (evitando reescribir si ya se encontró uno)
                if "registrant" in roles and not normalized["registrant"]:
                    normalized["registrant_name"] = fn if fn else ""
                    normalized["registrant"] = org if org else (fn if fn else "")
                    normalized["emails"] = email if email else ""

                    # Dirección (Address) - Estructura adr: ["", "", "Calle", "Ciudad", "Estado", "CP", "Pais"]
                    if isinstance(adr, list) and len(adr) >= 7:
                        normalized["country_city"] = adr[3] if adr[3] else ""
                        normalized["country_state"] = adr[4] if adr[4] else ""
                        normalized["country_code"] = adr[6] if adr[6] else ""
        
        return normalized

    async def get_and_clean_info(self, domain_name: str) -> Dict[str, Any]:
        """
        Realiza la consulta asíncrona y gestiona errores.
        Devuelve un diccionario con status, message y data.
        """
        result = {
            "status": "ERROR",
            "message": "",
            "data": None
        }
        
        target_url = f"{self.base_url}/domain/{domain_name}"

        try:
            # Usamos httpx.AsyncClient para consultas asíncronas
            async with httpx.AsyncClient(http2=True, follow_redirects=True, timeout=15.0) as client:
                response = await client.get(target_url, headers=self.headers)
                
                status_code = response.status_code
                result["status"] = str(status_code)

                if status_code == 200:
                    result["message"] = "Consulta RDAP exitosa."
                    result["data"] = self.normalize_data(response.json())
                
                elif status_code == 404:
                    result["message"] = f"Dominio '{domain_name}' no encontrado en el registro RDAP."
                
                elif status_code == 429:
                    result["message"] = "Límite de peticiones alcanzado (Rate Limit). Intenta de nuevo más tarde."
                
                else:
                    result["message"] = f"Error HTTP {status_code}: Respuesta inesperada del servidor."
                
        except httpx.RequestError as exc:
            result["message"] = f"Error de conexión o timeout: {exc}"
        except json.JSONDecodeError:
            result["message"] = "Error al decodificar la respuesta JSON (posiblemente un bloqueo o error interno)."

        return result

    async def get_domain_info(self, domain_name: str) -> Optional[Dict[str, Any]]:
        """
        Wrapper que devuelve solo el diccionario de datos limpios, o None si falla.
        """
        result = await self.get_and_clean_info(domain_name)
        return result["data"]

async def main(domain):
    scraper = RDAPClient()
    data = await scraper.get_domain_info(domain)
    return data

if __name__ == "__main__":
    # La sintaxis de ejecución asíncrona solicitada.
    data = asyncio.run(main("navi.cx"))
    
    if data:
        print(json.dumps(data, indent=2))
    else:
        # Se imprime el mensaje de error si es None
        print("No se pudieron obtener datos (consulta fallida o dominio no encontrado).")