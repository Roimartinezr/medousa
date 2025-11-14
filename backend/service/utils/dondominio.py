# dondominio.py
# Cliente asíncrono para DonDominio (whois + disponibilidad).
# Flujo: GET /es/whois/ -> GET /v3/user/status/ -> initmultiple -> search -> results -> whois
# Requiere: pip install httpx

import asyncio
from typing import Any, Dict, Iterable, Optional, Sequence, List, Tuple
import httpx
from httpx import HTTPStatusError, TimeoutException
import json
import base64
import re
from opensearchpy import OpenSearch
import os
import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# ---------- OpenSearch ----------------
_OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
_OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))
_PRIVACY_INDEX = "privacy_values"
_PRIVACY_DOC_ID = "whois_privacy_values"

_privacy_cache: Optional[List[str]] = None

def load_privacy_values() -> List[str]:   # 🔵 CAMBIO
    """
    Carga desde OpenSearch el array de valores de privacidad.
    Se cachea en memoria para no recalentar OS.
    """
    global _privacy_cache
    if _privacy_cache is not None:
        return _privacy_cache

    client = OpenSearch(
        hosts=[{"host": _OPENSEARCH_HOST, "port": _OPENSEARCH_PORT}],
        http_compress=True,
    )

    try:
        resp = client.get(index=_PRIVACY_INDEX, id=_PRIVACY_DOC_ID)
        vals = resp.get("_source", {}).get("values", [])
        _privacy_cache = [v.lower().strip() for v in vals]
        logger.info(f"[privacy] cargados {len(_privacy_cache)} valores")
    except Exception as e:
        logger.error(f"[privacy] error cargando privacy_values: {e}")
        _privacy_cache = []

    return _privacy_cache


def _is_privacy_value(val: str) -> bool:   # 🔵 CAMBIO
    """
    Sustituye al antiguo _is_privacy_value() hardcodeado.
    Usa los valores del índice privacy_values.
    """
    v = (val or "").lower().strip()
    if not v:
        return False

    patterns = load_privacy_values()
    return any(p in v for p in patterns)

# ---------- helpers ----------
def _dump_short(obj: Any, n: int = 800) -> str:
    s = str(obj)
    return (s[:n] + "…") if len(s) > n else s

def _first_dict(obj: Any) -> Dict[str, Any]:
    """Si es lista, devuelve el primer dict; si es dict lo deja; si no, {}."""
    if isinstance(obj, list):
        for x in obj:
            if isinstance(x, dict):
                return x
        return {}
    return obj if isinstance(obj, dict) else {}

def _dig_safe(obj: Any, *path, default=None):
    """Acceso seguro atravesando posibles listas/dicts mezcladas."""
    cur = obj
    for key in path:
        cur = _first_dict(cur)
        if isinstance(cur, dict):
            cur = cur.get(key, default)
        else:
            return default
    return cur


# ---------- cliente ----------
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
        lang_path: str = "/es/whois/",  # puedes cambiar a /en/whois/ o /ca/whois/
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
        last_exc = None
        while attempt <= retries:
            try:
                r = await self._c.post(path, data=data)
                r.raise_for_status()
                return r.json()
            except (TimeoutException, HTTPStatusError) as e:
                last_exc = e
                await asyncio.sleep(0.5 * (2 ** attempt) + 0.1)
                attempt += 1
        raise last_exc  # type: ignore[misc]

    # ---------- endpoints ----------
    async def init_multiple(self, domains: Iterable[str]) -> Dict[str, Any]:
        """Intenta las variantes correctas; prioriza domain=...&tld=&_intse=1 (igual que navegador)."""
        doms = list(domains)
        if not doms:
            return {}
        d0 = doms[0]

        variants = [
            {"domain": d0, "tld": "", "_intse": "1"},          # navegador
            {"domain": d0},                                   # fallback simple
            {"domains": json.dumps(doms)},                    # JSON-string
            {"domains[]": doms},                              # convención antigua
            {"q": d0},                                        # posible alias
        ]

        last = {}
        for v in variants:
            try:
                if self.debug:
                    print("[init_multiple] probando variante:", v)
                resp = await self._post_form("/v3/search/domain/initmultiple/", v)
                last = resp
                sys = resp.get("system", {}) or {}
                data = resp.get("data")
                if sys.get("valid") or (data and data != []):
                    if self.debug:
                        print("[init_multiple] variante OK:", v)
                    return resp
            except Exception as e:
                last = {"error": str(e)}
                if self.debug:
                    print("[init_multiple] excepción:", e)
        return last

    async def start_search(self, domains_or_query) -> Dict[str, Any]:
        """Busca; prioriza 'domains' (sin corchetes) que envía el navegador."""
        domains = [domains_or_query] if isinstance(domains_or_query, str) else list(domains_or_query)
        if not domains:
            return {}
        d0 = domains[0]

        variants = [
            {"domains": d0},                 # EXACTO: domains=midominio.tld
            {"domains": ",".join(domains)},  # CSV
            {"domains[]": domains},          # convención antigua
            {"domain": d0},                  # posible
            {"q": d0},                       # fallback
        ]

        last = {}
        for v in variants:
            try:
                if self.debug:
                    print("[start_search] probando variante:", v)
                resp = await self._post_form("/v3/search/domain/search/", v)
                last = resp
                data = resp.get("data")
                sys = resp.get("system", {}) or {}
                has_id = False
                if isinstance(data, dict):
                    s = data.get("search") or {}
                    if isinstance(s, dict) and s.get("id"):
                        has_id = True
                if has_id or (sys.get("valid") and data and data != []):
                    if self.debug:
                        print("[start_search] variante OK:", v)
                    return resp
                if not sys.get("errors"):
                    return resp
            except Exception as e:
                last = {"error": str(e)}
                if self.debug:
                    print("[start_search] excepción:", e)
        return last

    async def poll_until_ready(
        self,
        search_id: str,
        *,
        max_wait: float = 60.0,
        initial_interval: float = 0.8,
        max_interval: float = 5.0,
        verbose: bool = False,
    ) -> Dict[str, Any]:
        """
        Poll a /v3/search/domain/results/ usando {"id": search_id} hasta:
         - data.search.status == "ok"  OR
         - data.domains tenga contenido
        Usa backoff exponencial (capped).
        """
        if not search_id:
            raise ValueError("search_id requerido")

        start = asyncio.get_event_loop().time()
        interval = initial_interval
        last = {}

        while asyncio.get_event_loop().time() - start < max_wait:
            try:
                if verbose:
                    print(f"[poll_until_ready] solicitando results/ id={search_id} (interval={interval:.2f}s)")
                last = await self._post_form("/v3/search/domain/results/", {"id": search_id})
            except Exception as e:
                last = {"error": str(e)}
                if verbose:
                    print("[poll_until_ready] excepción en POST:", e)

            data = last.get("data", {}) or {}
            if isinstance(data, list) and data:
                data = data[0]

            search_obj = data.get("search") or {}
            status = (search_obj.get("status") or "").lower() if isinstance(search_obj, dict) else ""
            domains_map = data.get("domains") or {}

            if verbose:
                print(f"[poll_until_ready] status={status!r}, domains_len={len(domains_map) if isinstance(domains_map, dict) else 'N/A'}")

            if status == "ok" or (isinstance(domains_map, dict) and domains_map):
                if verbose:
                    print("[poll_until_ready] listo.")
                return last

            sys = last.get("system") or {}
            if sys.get("errors") and any("Parámetro" in e or "required" in e.lower() for e in sys.get("errors", [])):
                if verbose:
                    print("[poll_until_ready] errores en respuesta, no continuar:", sys.get("errors"))
                return last

            await asyncio.sleep(interval)
            interval = min(interval * 1.6, max_interval)

        if verbose:
            print("[poll_until_ready] timeout esperando results.")
        return last

    async def poll_results(
        self,
        search_id: Optional[str],
        *,
        domains: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """Versión simple por si no se espera con poll_until_ready."""
        if search_id:
            try:
                return await self._post_form("/v3/search/domain/results/", {"id": search_id})
            except Exception:
                pass
        if domains:
            d0 = domains[0]
            try:
                return await self._post_form("/v3/search/domain/results/", {"domains": d0})
            except Exception:
                pass
        return {}

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
            {"domain": domain},                                         # fallback
            {"recaptcha_response": "", "domain": domain},               # otro fallback
        ]

        last = {}
        for v in variants:
            try:
                if self.debug:
                    print("[domain_whois] variante:", v.keys())
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

    async def check_domain(self, domain: str, *, wait_for_results: bool = True, max_wait: float = 60.0) -> Dict[str, Any]:
        """
        Flujo completo:
         - initmultiple
         - start_search
         - poll_until_ready (si wait_for_results True)
         - extrae bloque final y whois
        """
        raw: Dict[str, Any] = {}

        raw["init"] = await self.init_multiple([domain])
        raw["search"] = await self.start_search([domain])

        search_data = _dig_safe(raw["search"], "data") or {}
        search_obj = _dig_safe({"data": search_data}, "data", "search") or {}
        search_id = search_obj.get("id")

        if wait_for_results and search_id:
            raw["results"] = await self.poll_until_ready(search_id, max_wait=max_wait, verbose=self.debug)
        else:
            raw["results"] = await self.poll_results(search_id, domains=[domain])

        results_data = _dig_safe(raw["results"], "data") or {}
        domains_map = _dig_safe({"data": results_data}, "data", "domains") or {}
        domains_map = _first_dict(domains_map)
        dom_block = domains_map.get(domain, {}) if isinstance(domains_map, dict) else {}

        availability_status = dom_block.get("status")
        message = dom_block.get("message")

        whois_text = await self.domain_whois(domain)

        if not availability_status:
            sys_obj = _first_dict(raw.get("search", {}).get("system", {}))
            err_msg = None
            if isinstance(sys_obj, dict) and sys_obj.get("errors"):
                err_msg = "; ".join(map(str, sys_obj["errors"]))
            availability_status = "unknown"
            if not message:
                message = f"search/results sin estado{(' - ' + err_msg) if err_msg else ''}"

        return {
            "domain": domain,
            "availability_status": availability_status,
            "message": message,
            "whois": whois_text,
            "raw": raw,
        }


# ---------- PARSER (solo .es y .com) + fallback .com -> .es ----------
def _norm(text: str) -> str:
    return text.replace("\r", "")

def _split_whois_records(text: str) -> List[str]:
    """
    Divide un WHOIS grande en bloques por dominio (.com suele listar varios).
    Corta por líneas 'Domain Name: ...'. Si no hay, devuelve el texto completo.
    """
    t = _norm(text)
    parts = re.split(r"(?im)^\s*Domain Name:\s*.+\s*$", t)
    heads = re.findall(r"(?im)^\s*Domain Name:\s*(.+)\s*$", t)
    if not heads:
        return [t.strip()] if t.strip() else []
    out = []
    for i, body in enumerate(parts[1:], start=0):  # parts[0] es lo previo al primer Domain Name
        rec = f"Domain Name: {heads[i]}\n{body}".strip()
        out.append(rec)
    return out

def _kv_map(lines: List[str]) -> Dict[str, str]:
    """Extrae pares clave:valor de líneas estilo 'Key: Value'."""
    kv: Dict[str, str] = {}
    for ln in lines:
        m = re.match(r"^\s*([A-Za-z0-9\-\s_/\.]+?)\s*:\s*(.+?)\s*$", ln)
        if m:
            k = m.group(1).strip().lower()
            v = m.group(2).strip()
            kv[k] = v
    return kv

def _clean_text(text: str) -> str:
    """Normaliza saltos de línea, elimina códigos ANSI y etiquetas HTML"""
    if not text:
        return ""
    # 1. Eliminar secuencias ANSI (colores de terminal)
    text = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', text)
    # 2. Eliminar etiquetas HTML (href, <a>, etc.)
    text = re.sub(r'<[^>]+>', '', text)
    # 3. Reemplazar entidades HTML (opcional)
    text = text.replace('&nbsp;', ' ')
    # 4. Normalizar saltos de línea
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    return text

def _owner_from_es_block(text: str) -> Tuple[Optional[str], bool, str]:
    """
    .ES (ESNIC) — buscamos sección 'Titular' y campo 'Nombre:'.
    Devuelve (owner, privacy, source).
    """
    t = _norm(text)
    m_block = re.search(r"(?ism)^\s*Titular\s*(?:\n+)(.*?)(?:\n{2,}|\Z)", t)
    if m_block:
        bloque = m_block.group(1)
        m_nom = re.search(r"(?im)^\s*Nombre\s*:\s*(.+?)\s*$", bloque)
        if m_nom:
            owner = m_nom.group(1).strip()
            return (owner, False, "ES:TITULAR->Nombre")
        for ln in bloque.splitlines():
            s = ln.strip()
            if not s or ":" in s:
                continue
            return (s, False, "ES:TITULAR->FirstLine")
    m_one = re.search(r"(?im)^\s*Titular\s*:\s*(.+?)\s*$", t)
    if m_one:
        return (m_one.group(1).strip(), False, "ES:TitularLine")
    return (None, False, "ES:NoMatch")

def _owner_from_com_record(record_text: str) -> Tuple[Optional[str], bool, str]:
    record_text = _clean_text(record_text)
    lines = _norm(record_text).splitlines()
    kv = _kv_map(lines)

    def find_key(pattern: str) -> Optional[str]:
        p = re.compile(pattern, re.I | re.UNICODE)
        for k, v in kv.items():
            key_clean = k.strip().replace('\u00A0', ' ').replace('-', ' ')
            if p.fullmatch(key_clean):
                logger.debug(f"[find_key] ✅ {key_clean!r} → {v!r}")
                return v.strip() if v else None
        return None

    seen_privacy = False  # solo cuenta si es en Name/Organization

    # 1) Registrant Organization / Organisation (máxima prioridad)
    owner = find_key(r"registrant\s+organ(?:i|isa)zation")
    if owner:
        if _is_privacy_value(owner):
            logger.debug("[COM] Registrant Organization es privacidad")
            seen_privacy = True
        else:
            return (owner, False, "COM:RegistrantOrganization")

    # 2) Registrant Name
    owner = find_key(r"registrant\s+name")
    if owner:
        if _is_privacy_value(owner):
            logger.debug("[COM] Registrant Name es privacidad")
            seen_privacy = True
        else:
            return (owner, False, "COM:RegistrantName")

    # 3) Organization / Org genérico (evitando usarlo si es privacy)
    owner = find_key(r"organ(?:i|isa)zation|^org$")
    if owner:
        if _is_privacy_value(owner):
            logger.debug("[COM] Organization es privacidad")
            seen_privacy = True
        else:
            return (owner, False, "COM:Organization")

    # 4) Sin owner válido; si vimos privacidad en Name/Org → fallback
    if seen_privacy:
        logger.debug("[_owner_from_com_record] Detectado WHOIS con privacidad (privacy=True) -> fallback a .es")
        return (None, True, "COM:PrivacyDetected")

    return (None, False, "COM:NoMatch")

def _match_domain_line_com(text: str) -> Optional[str]:
    m = re.search(r"(?im)^\s*Domain Name:\s*([A-Z0-9\.\-]+)\s*$", text)
    return m.group(1).strip() if m else None

def _match_domain_line_es(text: str) -> Optional[str]:
    m = re.search(r"(?im)^\s*Dominio:\s*([A-Za-z0-9\.\-]+)\s*$", text)
    return m.group(1).strip() if m else None

def extract_owner_es_com(whois_text: str, expected_domain: Optional[str] = None) -> Dict[str, object]:
    """
    Extrae el TITULAR para TLD .es y .com.
    Retorna dict con: owner, privacy, source, record_domain, tld
    """
    t = _norm(whois_text)
    out = {"owner": None, "privacy": False, "source": "INIT", "record_domain": None, "tld": None}

    # Heurística de .es (ESNIC)
    if re.search(r"(?im)^\s*Titular\s*$", t) and re.search(r"(?im)^\s*Dominio\s*:", t):
        owner, privacy, src = _owner_from_es_block(t)
        out.update({"owner": owner, "privacy": privacy, "source": src, "record_domain": _match_domain_line_es(t), "tld": "es"})
        return out

    # .com por bloques
    records = _split_whois_records(t)
    if not records:
        owner, privacy, src = _owner_from_com_record(t)
        out.update({"owner": owner, "privacy": privacy, "source": src, "record_domain": _match_domain_line_com(t), "tld": "com" if src != "COM:NoMatch" else None})
        return out

    chosen = None
    if expected_domain:
        exp = expected_domain.strip().lower()
        for rec in records:
            rec_domain = _match_domain_line_com(rec)
            if rec_domain and rec_domain.lower() == exp:
                chosen = rec
                break
    if chosen is None:
        chosen = records[0]
    owner, privacy, src = _owner_from_com_record(chosen)
    out.update({
        "owner": owner, 
        "privacy": privacy, 
        "source": src, 
        "record_domain": _match_domain_line_com(chosen), 
        "tld": "com"})
    return out

def _switch_com_to_es(domain: str) -> Optional[str]:
    """paypal.com -> paypal.es | bancosantander.com -> bancosantander.es"""
    domain = domain.strip().lower()
    if domain.endswith(".com"):
        base = domain[:-4]
        if base and "." not in base:  # segundo nivel simple
            return base + ".es"
        # también admitimos dominios de tercer nivel, se cambia el último sufijo
        return domain.rsplit(".", 1)[0] + ".es"
    return None

async def get_owner_via_whois(api: DonDominioAsync, domain: str) -> Optional[str]:
    """
    WHOIS del dominio; si es .com y está redactado (privacy), intenta el .es equivalente.
    Devuelve solo el titular (o None).
    """
    whois_text = await api.domain_whois(domain)
    parsed = extract_owner_es_com(whois_text, expected_domain=domain)
    owner = parsed.get("owner")
    tld = parsed.get("tld")
    privacy = bool(parsed.get("privacy"))

    # Si .com y redacción de privacidad → fallback a .es
    if (tld == "com") and privacy and (owner is None):
        alt = _switch_com_to_es(domain)
        if alt:
            whois_es = await api.domain_whois(alt)
            parsed_es = extract_owner_es_com(whois_es, expected_domain=alt)
            owner_es = parsed_es.get("owner")
            if owner_es:
                return str(owner_es)
    return str(owner) if owner else None


# ---------- prueba rápida ----------
async def main():
    async with DonDominioAsync(debug=False) as api:
        # Ejemplos:
        for dom in ["paypal.com", "bancosantander.com", "bancosantander-mail.es", "bancosantander.mx"]:
            owner = await get_owner_via_whois(api, dom)
            print(dom, "=>", owner)

if __name__ == "__main__":
    asyncio.run(main())
