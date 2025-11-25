# dondominio_es_only.py
# Cliente asíncrono para DonDominio, reducido SOLO a WHOIS .es
# Uso previsto: fallback externo que llama exclusivamente a get_owner_via_dondominio()
# para extraer el TITULAR (Nombre) de dominios .es

import asyncio
from typing import Any, Dict, Optional
import httpx
from httpx import HTTPStatusError, TimeoutException
import base64
import re
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


# ---------- helpers ----------
def _dump_short(obj: Any, n: int = 800) -> str:
    s = str(obj)
    return (s[:n] + "…") if len(s) > n else s


def _norm(text: str) -> str:
    if text is None:
        return ""
    return text.replace("\r", "")


def _clean_text(text: str) -> str:
    """Normaliza saltos de línea, elimina códigos ANSI y etiquetas HTML"""
    if not text:
        return ""
    # 1. Eliminar secuencias ANSI (colores de terminal)
    text = re.sub(r"\x1B\[[0-?]*[ -/]*[@-~]", "", text)
    # 2. Eliminar etiquetas HTML (href, <a>, etc.)
    text = re.sub(r"<[^>]+>", "", text)
    # 3. Reemplazar entidades HTML (opcional)
    text = text.replace("&nbsp;", " ")
    # 4. Normalizar saltos de línea
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text


def _match_domain_line_es(text: str) -> Optional[str]:
    m = re.search(r"(?im)^\s*Dominio:\s*([A-Za-z0-9\.\-]+)\s*$", text)
    return m.group(1).strip() if m else None


def _owner_from_es_block(text: str):
    """
    WHOIS .ES (ESNIC)
    Buscamos sección 'Titular' y campo 'Nombre:'.
    Devuelve (owner, source).
    """
    t = _norm(text)

    # Bloque:
    # Titular
    # Nombre: LO QUE SEA
    # [...]
    m_block = re.search(r"(?ism)^\s*Titular\s*(?:\n+)(.*?)(?:\n{2,}|\Z)", t)
    if m_block:
        bloque = m_block.group(1)
        m_nom = re.search(r"(?im)^\s*Nombre\s*:\s*(.+?)\s*$", bloque)
        if m_nom:
            owner = m_nom.group(1).strip()
            return owner, "ES:TITULAR->Nombre"

        # fallback: primera línea "limpia" del bloque
        for ln in bloque.splitlines():
            s = ln.strip()
            if not s or ":" in s:
                continue
            return s, "ES:TITULAR->FirstLine"

    # Variante compacta:
    # Titular: LO QUE SEA
    m_one = re.search(r"(?im)^\s*Titular\s*:\s*(.+?)\s*$", t)
    if m_one:
        return m_one.group(1).strip(), "ES:TitularLine"

    return None, "ES:NoMatch"


def extract_owner_es(whois_text: str) -> Dict[str, object]:
    """
    Extrae el TITULAR para TLD .es.
    Retorna dict con: owner, record_domain, source
    """
    text = _clean_text(_norm(whois_text))
    owner, src = _owner_from_es_block(text)
    record_domain = _match_domain_line_es(text)

    return {
        "owner": owner,
        "record_domain": record_domain,
        "source": src,
    }


# ---------- cliente DonDominio (solo WHOIS) ----------
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

        # Headers por defecto para XHR (los de HTML se ponen en ensure_session)
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

        # 1) HTML como navegador real
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

        # 2) Warm-up JSON
        hdr_json = {
            "Accept": "*/*",
            "Origin": self.BASE,
            "Referer": f"{self.BASE}{self.lang_path}",
        }
        r2 = await self._c.get("/v3/user/status/", headers=hdr_json)
        r2.raise_for_status()
        if self.debug:
            print("USER/STATUS:", _dump_short(r2.json()))

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

    # ---------- WHOIS .es ----------
    async def domain_whois(self, domain: str) -> str:
        """
        Devuelve el texto WHOIS tal cual lo ves en la web.
        En esta sesión, el endpoint exige 'recaptcha_response' con el PHPSESSID en base64.
        """
        assert self._c is not None

        phpsessid = self._c.cookies.get("PHPSESSID", "")
        recaptcha_token = base64.b64encode(phpsessid.encode()).decode() if phpsessid else ""

        variants = [
            {"recaptcha_response": recaptcha_token, "domain": domain},  # igual que navegador
            {"domain": domain},                                         # fallback simple
            {"recaptcha_response": "", "domain": domain},               # otro fallback
        ]

        last: Dict[str, Any] = {}
        for v in variants:
            try:
                if self.debug:
                    print("[domain_whois] variante:", v.keys())
                resp = await self._post_form("/v3/search/whois/domain/", v)
                last = resp
                data = resp.get("data") or {}
                if isinstance(data, dict):
                    who = data.get("whois")
                else:
                    who = None
                if who:
                    return str(who).strip()
                if (resp.get("system") or {}).get("valid"):
                    return (data.get("whois") or "").strip()
            except Exception as e:
                if self.debug:
                    print("[domain_whois] excepción:", e)
        return ""


# ---------- API pública para el fallback externo ----------
async def get_owner_via_dondominio(api: DonDominioAsync, domain: str) -> Optional[str]:
    """
    WHOIS del dominio .es.
    Uso previsto: el fallback externo ya decide cuándo llamar aquí (solo TLD .es).
    Devuelve solo el titular (Nombre) o None.
    """
    domain = domain.strip().lower()
    if not domain.endswith(".es"):
        logger.warning("[get_owner_via_dondominio] dominio sin .es: %s", domain)

    whois_text = await api.domain_whois(domain)
    if not whois_text:
        logger.debug("[get_owner_via_dondominio] WHOIS vacío para %s", domain)
        return None

    parsed = extract_owner_es(whois_text)
    owner = parsed.get("owner")

    if owner:
        owner_str = str(owner).strip()
        logger.debug("[get_owner_via_dondominio] %s -> %r (%s)", domain, owner_str, parsed.get("source"))
        return owner_str

    logger.debug("[get_owner_via_dondominio] sin owner para %s (source=%s)", domain, parsed.get("source"))
    return None


# ---------- prueba rápida opcional ----------
async def main():
    async with DonDominioAsync(debug=True) as api:
        for dom in ["bancosantander.es", "bbva.es"]:
            owner = await get_owner_via_dondominio(api, dom)
            print(dom, "=>", owner)


if __name__ == "__main__":
    asyncio.run(main())
