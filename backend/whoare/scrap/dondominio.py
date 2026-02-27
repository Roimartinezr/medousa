# app/backend/whois/scrap/dondominio.py
# Cliente asíncrono para DonDominio, ampliado a WHOIS .es y .ad
# Convierte la respuesta WHOIS completa en JSON key-values (arrays para campos repetidos, disclaimer incluido)

import asyncio
from typing import Any, Dict, Optional, List
import httpx
from httpx import HTTPStatusError, TimeoutException
import base64
import re
import logging
import json

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


# ---------- helpers ----------
def _dump_short(obj: Any, n: int = 800) -> str:
    s = str(obj)
    return (s[:n] + "…") if len(s) > n else s

def _norm(text: Optional[str]) -> str:
    if text is None:
        return ""
    return text.replace("\r", "")

def _clean_text(text: str) -> str:
    """Normaliza saltos de línea, elimina códigos ANSI y etiquetas HTML"""
    if not text:
        return ""
    text = re.sub(r"\x1B\[[0-?]*[ -/]*[@-~]", "", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = text.replace("&nbsp;", " ")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text


# ---------- WHOIS parsing genérico ----------
def fix_esnic_dns_block(text: str) -> str:
    """
    Normaliza el bloque WHOIS .es de 'Servidores DNS' eliminando la línea vacía
    inmediatamente posterior y convirtiendo el resto en 'Servidores DNS: valor'.
    """
    lines = text.splitlines()
    out = []
    inside_dns_block = False
    skip_next_blank = False

    for line in lines:
        stripped = line.strip()

        if stripped.lower() == "servidores dns":
            inside_dns_block = True
            skip_next_blank = True
            continue

        if inside_dns_block:
            if skip_next_blank:
                if stripped == "":
                    skip_next_blank = False
                    continue
                else:
                    skip_next_blank = False

            if ":" in stripped:
                inside_dns_block = False
                out.append(line)
                continue

            if stripped != "":
                out.append(f"Servidores DNS: {stripped}")
                continue
            continue

        out.append(line)

    return "\n".join(out)

def enumerate_nombre_keys_esnic(text: str) -> str:
    """
    En WHOIS .es, renombra las claves 'Nombre:' como 'Nombre_1:', 'Nombre_2:', etc.,
    en el orden en que aparecen, para evitar colisiones al jsonear.
    """
    lines = text.splitlines()
    out = []
    count = 0
    pattern = re.compile(r"^(Nombre)(\s*:\s*)(.*)$")

    for line in lines:
        m = pattern.match(line.strip())
        if m:
            count += 1
            new_key = f"Nombre_{count}"
            new_line = f"{new_key}{m.group(2)}{m.group(3)}"
            out.append(new_line)
        else:
            out.append(line)

    return "\n".join(out)

def whois_to_json(whois_text: str) -> Dict[str, Any]:
    """
    Convierte un bloque WHOIS en JSON con key-values.
    """
    result: Dict[str, Any] = {}
    disclaimer_lines: List[str] = []

    for line in whois_text.splitlines():
        line = line.strip()
        if not line:
            continue

        m = re.match(r"^([^:]+):\s*(.*)$", line)
        if m:
            key = m.group(1).strip()
            val = m.group(2).strip() or None
            key_norm = key.lower().replace(" ", "_")

            if key_norm in result:
                if isinstance(result[key_norm], list):
                    result[key_norm].append(val)
                else:
                    result[key_norm] = [result[key_norm], val]
            else:
                result[key_norm] = val
        else:
            disclaimer_lines.append(line)
            
    # Añadimos el disclaimer al final del dict
    if disclaimer_lines:
        result["disclaimer"] = "\n".join(disclaimer_lines)

    return result


# ---------- cliente DonDominio ----------
class DonDominioAsync:
    BASE = "https://www.dondominio.com"

    def __init__(
        self,
        *,
        timeout: float = 15.0,
        verify_tls: bool = True,
        lang_path: str = "/es/whois/",
        debug: bool = False,
    ):
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.lang_path = lang_path
        self.debug = debug

        # Cabeceras anti-fingerprinting actualizadas
        self.headers = {
            "Accept": "*/*",
            "Accept-Language": "es-ES,es;q=0.9,en;q=0.8,ca;q=0.7",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": self.BASE,
            "Referer": f"{self.BASE}{self.lang_path}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 OPR/127.0.0.0",
            "Sec-Ch-Ua": '"Opera";v="127", "Chromium";v="143", "Not A(Brand";v="24"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "X-Dd": "v3",
            "X-Requested-With": "XMLHttpRequest",
        }
        self._c: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self._c = httpx.AsyncClient(
            base_url=self.BASE,
            timeout=self.timeout,
            headers=self.headers,
            verify=self.verify_tls,
            http2=True,
            follow_redirects=True,
        )
        return self

    async def __aexit__(self, *exc):
        if self._c:
            await self._c.aclose()
            self._c = None

    # ---------- sesión/warm-up (NUEVA LÓGICA) ----------
    async def _warm_up(self, domain: str):
        """Secuencia completa: Activa la sesión, inicia búsqueda, extrae ID y hace polling"""
        assert self._c is not None
        
        # 1. Preparar cookies
        await self._c.get(self.lang_path)
        await self._c.get("/v3/user/status/")
        
        # 2. El botón de encendido del backend
        r_recap = await self._c.post("/v3/recaptcha/", data={"section": "whois"})
        if self.debug: 
            is_valid = r_recap.json().get("system", {}).get("valid")
            logger.debug(f"[warm_up] Autorización recaptcha/: {'ÉXITO' if is_valid else 'FALLO'}")
        await asyncio.sleep(0.5)
        
        # 3. Iniciar el funnel de búsqueda
        payload_init = {"domain": domain} 
        payload_search = {"domains": domain} 
        
        r_init = await self._c.post("/v3/search/domain/initmultiple/", data=payload_init)
        await asyncio.sleep(0.3)
        
        r_search = await self._c.post("/v3/search/domain/search/", data=payload_search)
        
        # 4. Extraer el ID de búsqueda
        search_id = None
        try:
            resp_search = r_search.json()
            data_search = resp_search.get("data")
            if isinstance(data_search, dict):
                search_id = data_search.get("search", {}).get("id")
        except Exception as e:
            if self.debug: logger.error(f"[warm_up] Error JSON search: {e}")

        if not search_id:
            if self.debug: logger.warning("[warm_up] FALSO ARRANQUE: No ID.")
            return
            
        # 5. Bucle de espera (Polling)
        poll_payload = {"id": search_id}
        for i in range(5):
            await asyncio.sleep(1.0)
            r = await self._c.post("/v3/search/domain/results/", data=poll_payload)
            try:
                resp = r.json()
                data_obj = resp.get("data")
                search_status = None
                domain_status = None
                
                if isinstance(data_obj, dict):
                    search_status = data_obj.get("search", {}).get("status")
                    domains_obj = data_obj.get("domains")
                    if isinstance(domains_obj, dict):
                        domain_status = domains_obj.get(domain, {}).get("status")
                
                if search_status == "ok" or domain_status in ["transfer", "ok", "error"]:
                    break
            except Exception:
                pass
                
        await asyncio.sleep(0.5)

    # ---------- WHOIS (texto crudo) ----------
    async def domain_whois(self, domain: str) -> str:
        """Devuelve el texto WHOIS tal cual lo ves en la web, superando la seguridad."""
        assert self._c is not None

        # Preparamos la sesión y rompemos el captcha
        await self._warm_up(domain)

        phpsessid = self._c.cookies.get("PHPSESSID", "")
        recaptcha_token = base64.b64encode(phpsessid.encode()).decode() if phpsessid else ""

        payload = {
            "domain": domain,
            "recaptcha_response": recaptcha_token
        }

        try:
            r = await self._c.post("/v3/search/whois/domain/", data=payload)
            resp = r.json()
            
            data = resp.get("data") or {}
            who = data.get("whois") if isinstance(data, dict) else None
            
            if who:
                return str(who).strip()
            if (resp.get("system") or {}).get("valid"):
                return (data.get("whois") or "").strip()
        except Exception as e:
            if self.debug:
                logger.error(f"[domain_whois] excepción: {e}")
        return ""


# ---------- API pública: WHOIS completo en JSON ----------
async def get_whois_json_via_dondominio(api: DonDominioAsync, domain: str) -> Dict[str, Any]:
    """
    WHOIS del dominio (.es, .ad, etc).
    Devuelve JSON completo con todos los key-values posibles (jsoneado).
    """
    domain = domain.strip().lower()
    tld = domain.split(".")[-1] if "." in domain else None

    whois_text = await api.domain_whois(domain)
    if not whois_text:
        logger.debug("[get_whois_json_via_dondominio] WHOIS vacío para %s", domain)
        return {
            "domain": domain,
            "tld": tld,
            "parsed": {},
            "raw_text": ""
        }

    # Jsonea todo el WHOIS
    cleaned = _clean_text(_norm(whois_text))
    if tld == "es":
        cleaned = fix_esnic_dns_block(cleaned)
        cleaned = enumerate_nombre_keys_esnic(cleaned)
    parsed = whois_to_json(cleaned)

    result = {
        "domain": domain,
        "tld": tld,
        "parsed": parsed,
        "raw_text": whois_text
    }

    return result

async def main(domain):
    async with DonDominioAsync(debug=True) as api:
        info = await get_whois_json_via_dondominio(api=api, domain=domain)
        p = info['parsed']
        print(json.dumps(p, indent=2, ensure_ascii=False))
        return p

"""if __name__ == "__main__":
    # Descomenta la siguiente línea para probarlo directamente ejecutando el archivo
    asyncio.run(main("bancosantander.es"))"""