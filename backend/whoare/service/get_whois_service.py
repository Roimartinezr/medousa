#app/backend/scrap/service/scrap_owner_service.py
import tldextract
import whois
import json
import importlib
import os
import logging
import sys # Importar sys para el StreamHandler
import asyncio
from datetime import datetime
from typing import Optional
from jsonschema import validate, ValidationError
from ...service.ascii_cctld_service import get_ascii_cctld_by_id
from ...service.idn_cctld_service import get_idn_cctld_by_id
from ..scrap.whois_socket import whois_query

# --- Configuración Global de Logging ---
# Esto asegura que los logs de whois_socket y los scrapers dinámicos se vean en consola.
logging.basicConfig(
    level=logging.INFO, # Nivel base (INFO o DEBUG)
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

DATE_KEYS = {"creation_date", "expiration_date", "updated_date"}
UA_MULTI_VALUE_TLD = "ua"
UA_SENTINELS = {"n/a", "not published"}

# ... [Las funciones _ua_resolve_multi_source_field, _normalize_date, _normalize_value siguen igual] ...
def _ua_resolve_multi_source_field(source_key: str, w: dict) -> Optional[str]:
    # (Código omitido por brevedad, no cambia)
    if "|" not in source_key: return None
    candidates = [p.strip() for p in source_key.split("|") if p.strip()]
    collected = []
    for candidate in candidates:
        v = getattr(w, candidate, None)
        if v is None and isinstance(w, dict) and candidate in w: v = w[candidate]
        if v is None: continue
        if isinstance(v, (list, tuple, set)): collected.extend(v)
        else: collected.append(v)
    cleaned = []
    seen = set()
    for v in collected:
        if v is None: continue
        if isinstance(v, datetime): v = v.isoformat()
        v_str = str(v).strip()
        if not v_str: continue
        if v_str.lower() in UA_SENTINELS: continue
        if v_str in seen: continue
        seen.add(v_str)
        cleaned.append(v_str)
    return ", ".join(cleaned) if cleaned else None

def _normalize_date(value, mode="first"):
    if value is None: return None
    if isinstance(value, (list, tuple)):
        if not value: return None
        if mode == "first": value = value[0]
        elif mode == "last": value = value[-1]
    if isinstance(value, datetime): return value.isoformat()
    if isinstance(value, str): return value.strip() or None
    return str(value)

def _normalize_value(value):
    if value is None: return None
    if isinstance(value, str) and value.strip() == "": return None
    if isinstance(value, datetime): return value.isoformat()
    return value

async def get_whois_cctld(domain: str):
    # estract tld from domain
    ext = tldextract.extract(domain)
    tld = ext.suffix.split('.')[-1]

    # verify if tld is punycode
    idn = False
    if tld.startswith('xn--'):
        idn = True

    # load tld parser
    adapter_path = os.path.join(os.path.dirname(__file__), "..", "adapters", f"{tld}.json")
    adapter_path = os.path.abspath(adapter_path)
    schema_path = os.path.join(os.path.dirname(__file__), "..", "adapters", "schema", "whois_response.schema.json")

    with open(adapter_path, "r", encoding="utf-8") as f:
        parser = json.load(f)
    fields_map = parser["fields"]

    # load schema
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)

    # get tld BD's data
    if idn:
        src = get_idn_cctld_by_id(tld)
    else:
        src = get_ascii_cctld_by_id(tld)
    scraping_site = src.get("scraping_site", "") or ""

    logger.info(f"Scraping site detectado: {scraping_site} para dominio: {domain}")

    # --- MODIFICACIÓN 2: Lógica de scrap con logging activado ---
    if scraping_site == "whois":
        w = whois.whois(domain)
    elif scraping_site.startswith("whois."):
        # Activar logs específicamente para el socket
        logging.getLogger("backend.scrap.whois_socket").setLevel(logging.DEBUG)
        w = whois_query(domain=domain, server=scraping_site)
    else: 
        # scrap dinámico desde scrap/<scraping_site>.py
        try:
            mod_name = f"backend.whoare.scrap.{scraping_site}"
            
            # Forzar nivel DEBUG para el módulo que vamos a importar
            # Esto asegura que veamos prints/logs internos de ese script específico
            dyn_logger = logging.getLogger(mod_name)
            dyn_logger.setLevel(logging.DEBUG)
            
            # Importar y ejecutar
            scrap_module = importlib.import_module(mod_name)
            logger.info(f"Ejecutando módulo dinámico: {mod_name}")
            w = await scrap_module.main(domain)
            
        except Exception as e:
            logger.warning(f"[scrap fallback] error al cargar módulo '{scraping_site}': {e}", exc_info=True)
            w = None

    # parse response
    fields = {}
    for target_key, source_key in fields_map.items():
         # Caso especial: (fechas first/last)
        if isinstance(source_key, dict):
            src = source_key.get("source")
            norm = source_key.get("normalize", "first")
            value = getattr(w, src, None)
            if value is None and isinstance(w, dict) and src in w:
                value = w[src]
            fields[target_key] = _normalize_date(value, mode=norm)
            continue

        # Caso normal: mapeo inválido → None
        if not isinstance(source_key, str) or not source_key:
            fields[target_key] = None
            continue

        # Obtención del valor (atributo o clave de dict)
        value = getattr(w, source_key, None)
        if value is None and isinstance(w, dict) and source_key in w:
            value = w[source_key]

        # --- ESPECIAL .ua: expresión multi-source "a | b | c" ---
        if tld == UA_MULTI_VALUE_TLD and isinstance(source_key, str) and "|" in source_key:
            value = _ua_resolve_multi_source_field(source_key, w)
        else:
            # comportamiento normal
            value = getattr(w, source_key, None)
            if value is None and isinstance(w, dict) and source_key in w:
                value = w[source_key]

        # Caso específico: registrant_name ← person (solo aquí concatenamos arrays) (caso .br)
        if target_key == "registrant_name" and source_key == "person":
            if isinstance(value, (list, tuple)) and all(isinstance(v, str) for v in value):
                value = ", ".join(v.strip() for v in value if v and v.strip())

        # Si es campo de fecha pero definido como string en el adapter
        if target_key in DATE_KEYS:
            # por defecto usa "first"
            fields[target_key] = _normalize_date(value, mode="first")
            continue

        fields[target_key] = _normalize_value(value)


    country_map = parser.get("country", {})
    country = {}
    for target_key, source_key in country_map.items():
        if not isinstance(source_key, str) or not source_key:
            country[target_key] = None
            continue

        value = getattr(w, source_key, None)
        if value is None and isinstance(w, dict) and source_key in w:
            value = w[source_key]

        country[target_key] = _normalize_value(value)

    parsed_response = {
        "tld": parser["tld"],
        "registry": parser.get("registry"),
        "country": country if country else None,
        "fields": fields
    }

    # validate with schema
    try:
        validate(instance=parsed_response, schema=schema)
    except ValidationError as e:
        print("❌ WHOIS response is invalid:", e.message)
    
    #return normalized whois
    #print(json.dumps(parsed_response, indent=4, ensure_ascii=False))
    return parsed_response

async def get_whois_gtld(domain: str):
    """
    Realiza un whois simple usando la librería standard.
    Retorna la respuesta cruda (raw) convertida a dict + flag gTLD.
    """
    logger.info(f"[gTLD] Iniciando whois simple para: {domain}")
    
    try:
        # Ejecutamos en thread para no bloquear el loop asíncrono
        w = await asyncio.to_thread(whois.whois, domain)
        
        if not w:
            return None

        # Convertimos a dict
        if not isinstance(w, dict):
            try:
                response = dict(w)
            except Exception:
                # Si falla la conversión (ej: es un string de error), lo encapsulamos
                response = {"raw_text": str(w)}
        else:
            response = w

        # Añadimos el flag requerido
        response["gTLD"] = "true"
        #print(response)
        return response

    except Exception as e:
        logger.error(f"[gTLD] Error procesando {domain}: {e}")
        return None


"""if __name__ == "__main__":
    print(asyncio.run(get_whois_cctld("swedbank.se")))"""