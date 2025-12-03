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

        # Detectar encabezado "Servidores DNS"
        if stripped.lower() == "servidores dns":
            inside_dns_block = True
            skip_next_blank = True   # <- ESTA ES LA CLAVE
            continue

        # Si estamos dentro del bloque DNS
        if inside_dns_block:

            # Quitar SOLO la primera línea vacía después del encabezado
            if skip_next_blank:
                if stripped == "":
                    skip_next_blank = False
                    continue
                else:
                    # No era vacía, procesarla normalmente
                    skip_next_blank = False

            # Fin del bloque: aparece una clave tipo X: Y
            if ":" in stripped:
                inside_dns_block = False
                out.append(line)
                continue

            # Línea DNS válida
            if stripped != "":
                out.append(f"Servidores DNS: {stripped}")
                continue

            # Otras líneas vacías dentro del bloque DNS se ignoran
            continue

        # Caso general fuera del bloque
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

    # Coincide exactamente líneas del tipo: Nombre: algo
    pattern = re.compile(r"^(Nombre)(\s*:\s*)(.*)$")

    for line in lines:
        m = pattern.match(line.strip())
        if m:
            count += 1
            # reconstruimos con el texto original pero cambiando la clave
            # usamos strip() en el match, así que recomponemos sin espacios extra delante
            new_key = f"Nombre_{count}"
            new_line = f"{new_key}{m.group(2)}{m.group(3)}"
            out.append(new_line)
        else:
            out.append(line)

    return "\n".join(out)


def whois_to_json(whois_text: str) -> Dict[str, Any]:
    """
    Convierte un bloque WHOIS en JSON con key-values.
    - Cada línea 'Key: Value' se convierte en {key: value}
    - Campos repetidos (ej. Name Server) se convierten en listas
    - Líneas sin valor explícito se guardan como None
    - Bloques legales o disclaimers se guardan en 'disclaimer'
    """
    result: Dict[str, Any] = {}
    disclaimer_lines: List[str] = []

    for line in whois_text.splitlines():
        line = line.strip()
        if not line:
            continue

        # Detecta pares clave: valor
        m = re.match(r"^([^:]+):\s*(.*)$", line)
        if m:
            key = m.group(1).strip()
            val = m.group(2).strip() or None

            # Normaliza clave (ej. Name Server → name_server)
            key_norm = key.lower().replace(" ", "_")

            # Si ya existe, convierte en lista
            if key_norm in result:
                if isinstance(result[key_norm], list):
                    result[key_norm].append(val)
                else:
                    result[key_norm] = [result[key_norm], val]
            else:
                result[key_norm] = val
        else:
            # Si no es key-value, lo tratamos como parte del disclaimer
            disclaimer_lines.append(line)

    return result


# ---------- cliente DonDominio ----------
class DonDominioAsync:
    BASE = "https://www.dondominio.com"

    def __init__(
        self,
        *,
        timeout: float = 15.0,
        verify_tls: bool = True,
        user_agent: str = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
        ),
        lang_path: str = "/es/whois/",  # /es/whois/ para WHOIS .es
        debug: bool = False,
    ):
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.lang_path = lang_path
        self.debug = debug

        self.headers = {
            "Accept": "*/*",
            "Accept-Language": "es-ES,es;q=0.9",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": self.BASE,
            "Referer": f"{self.BASE}{self.lang_path}",
            "User-Agent": user_agent,
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
        )
        await self.ensure_session()
        return self

    async def __aexit__(self, *exc):
        if self._c:
            await self._c.aclose()
            self._c = None

    # ---------- sesión/warm-up ----------
    async def ensure_session(self) -> None:
        """
        1) GET /es/whois/ -> recibe PHPSESSID, ddr (Set-Cookie)
        2) GET /v3/user/status/ -> warm-up para IP/idioma/flags
        """
        assert self._c is not None

        hdr_html = {
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
            ),
            "Upgrade-Insecure-Requests": "1",
            "Referer": f"{self.BASE}{self.lang_path}",
        }
        r = await self._c.get(self.lang_path, headers=hdr_html)
        r.raise_for_status()

        if "PHPSESSID" not in self._c.cookies:
            raise RuntimeError("No se recibió PHPSESSID tras /whois/; revisa Referer/UA/idioma.")

        hdr_json = {
            "Accept": "*/*",
            "Origin": self.BASE,
            "Referer": f"{self.BASE}{self.lang_path}",
        }
        r2 = await self._c.get("/v3/user/status/", headers=hdr_json)
        r2.raise_for_status()
        if self.debug:
            try:
                print("USER/STATUS:", _dump_short(r2.json()))
            except Exception:
                pass

    # ---------- HTTP con reintentos ----------
    async def _post_form(self, path: str, data: Dict[str, Any], *, retries: int = 2) -> Dict[str, Any]:
        assert self._c is not None
        attempt = 0
        last_exc: Optional[Exception] = None
        while attempt <= retries:
            try:
                r = await self._c.post(path, data=data)
                r.raise_for_status()
                return r.json()
            except (TimeoutException, HTTPStatusError) as e:
                last_exc = e
                await asyncio.sleep(0.5 * (2 ** attempt) + 0.1)
                attempt += 1
        if last_exc is not None:
            raise last_exc
        return {}

    # ---------- WHOIS (texto crudo) ----------
    async def domain_whois(self, domain: str) -> str:
        """
        Devuelve el texto WHOIS tal cual lo ves en la web.
        Mantiene el flujo de recaptcha_response con PHPSESSID en base64.
        """
        assert self._c is not None

        phpsessid = self._c.cookies.get("PHPSESSID", "")
        recaptcha_token = base64.b64encode(phpsessid.encode()).decode() if phpsessid else ""

        variants = [
            {"recaptcha_response": recaptcha_token, "domain": domain},
            {"domain": domain},
            {"recaptcha_response": "", "domain": domain},
        ]

        last: Dict[str, Any] = {}
        for v in variants:
            try:
                if self.debug:
                    print("[domain_whois] variante:", list(v.keys()))
                resp = await self._post_form("/v3/search/whois/domain/", v)
                last = resp
                data = resp.get("data") or {}
                who = data.get("whois") if isinstance(data, dict) else None
                if who:
                    return str(who).strip()
                if (resp.get("system") or {}).get("valid"):
                    return (data.get("whois") or "").strip()
            except Exception as e:
                if self.debug:
                    print("[domain_whois] excepción:", e)
        return ""


# ---------- API pública: WHOIS completo en JSON ----------
async def get_whois_json_via_dondominio(api: DonDominioAsync, domain: str) -> Dict[str, Any]:
    """
    WHOIS del dominio (.es, .ad, etc).
    Devuelve JSON completo con todos los key-values posibles (jsoneado).
    Incluye:
      - domain: dominio consultado
      - tld: TLD derivado
      - parsed: dict de key-values (arrays para claves repetidas)
      - raw_text: WHOIS crudo (para inspección y trazabilidad)
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

    # Jsonea todo el WHOIS (key-values y arrays para claves repetidas)
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

    logger.debug(
        "[get_whois_json_via_dondominio] %s -> keys(parsed)=%s",
        domain, list(parsed.keys())
    )
    return result


async def main(domain):
    async with DonDominioAsync() as api:
        info = await get_whois_json_via_dondominio(api=api, domain=domain)
        p = info['parsed']
        #print(json.dumps(p, indent=2, ensure_ascii=False))
        return p

"""if __name__ == "__main__":
    asyncio.run(main("bancosantander.es"))"""