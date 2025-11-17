from opensearchpy import OpenSearch
import time

OPENSEARCH_HOST = "localhost"
OPENSEARCH_PORT = 9200
INDEX_KNOWN_BRANDS = "known_brands"

# ============================================================
# Datos reales de bancos / marcas
# Ahora usamos canonical_domain SOLO para derivar country_code.
# El documento que se indexa ya NO incluye canonical_domain
# ni brand_id en _source.
# ============================================================

BANK_BRANDS = [
    {
        "brand_id": "abanca",
        "canonical_domain": "abanca.es",
        "owner_terms": "abanca corporacion bancaria sa",
        "keywords": ["abanca", "corporacion", "bancaria"],
        "known_domains": ["abanca.es"]
    },
    {
        "brand_id": "bbva",
        "canonical_domain": "bbva.es",
        "owner_terms": "banco bilbao vizcaya argentaria sa",
        "keywords": ["bbva", "bilbao", "vizcaya", "argentaria"],
        "known_domains": ["bbva.es", "bbva.com"]
    },
    {
        "brand_id": "bancosantander",
        "canonical_domain": "bancosantander.es",
        "owner_terms": "banco santander sa",
        "keywords": ["santander", "banco"],
        "known_domains": ["bancosantander.es", "santander.com"]
    },
    {
        "brand_id": "caixabank",
        "canonical_domain": "caixabank.es",
        "owner_terms": "caixabank sa",
        "keywords": ["caixa", "caixabank"],
        "known_domains": ["caixabank.es"]
    },
    {
        "brand_id": "bankia",
        "canonical_domain": "bankia.es",
        "owner_terms": "caixabank sa",
        "keywords": ["bankia", "caixa"],
        "known_domains": ["bankia.es"]
    },
    {
        "brand_id": "ing",
        "canonical_domain": "ing.es",
        "owner_terms": "ing bank nv sucursal espana",
        "keywords": ["ing", "bank"],
        "known_domains": ["ing.es", "ing.com"]
    },
    {
        "brand_id": "bankinter",
        "canonical_domain": "bankinter.es",
        "owner_terms": "bankinter sa",
        "keywords": ["bankinter"],
        "known_domains": ["bankinter.es"]
    },
    {
        "brand_id": "bancosabadell",
        "canonical_domain": "bancosabadell.es",
        "owner_terms": "banco de sabadell sa",
        "keywords": ["sabadell"],
        "known_domains": ["bancosabadell.es", "bancsabadell.com"]
    },
    {
        "brand_id": "unicaja",
        "canonical_domain": "unicaja.es",
        "owner_terms": "unicaja banco sa",
        "keywords": ["unicaja", "banco"],
        "known_domains": ["unicaja.es"]
    },
    {
        "brand_id": "kutxabank",
        "canonical_domain": "kutxabank.es",
        "owner_terms": "kutxabank sa",
        "keywords": ["kutxa", "kutxabank"],
        "known_domains": ["kutxabank.es"]
    },
    {
        "brand_id": "openbank",
        "canonical_domain": "openbank.es",
        "owner_terms": "open bank sa",
        "keywords": ["openbank", "open", "bank"],
        "known_domains": ["openbank.es"],
    },

    # Neobancos / fintech
    {
        "brand_id": "revolut",
        "canonical_domain": "revolut.com",
        "owner_terms": "revolut ltd",
        "keywords": ["revolut"],
        "known_domains": ["revolut.com"],
    },
    {
        "brand_id": "n26",
        "canonical_domain": "n26.com",
        "owner_terms": "n26 ag product tech gmbh",
        "keywords": ["n26"],
        "known_domains": ["n26.com", "n26.es", "n26.pt"],
    },
    {
        "brand_id": "monzo",
        "canonical_domain": "monzo.com",
        "owner_terms": "monzo bank ltd",
        "keywords": ["monzo", "bank"],
        "known_domains": ["monzo.com", "monzo.es"],
    },
    {
        "brand_id": "wise",
        "canonical_domain": "wise.com",
        "owner_terms": "wise world internet services espana",
        "keywords": ["wise"],
        "known_domains": ["wise.com", "wise.es", "transferwise.com"],
    },

    # Exchanges / crypto
    {
        "brand_id": "binance",
        "canonical_domain": "binance.com",
        "owner_terms": "binance bam technology services rudy global",
        "keywords": ["binance"],
        "known_domains": ["binance.com", "binance.us", "binance.es"],
    },
    {
        "brand_id": "coinbase",
        "canonical_domain": "coinbase.com",
        "owner_terms": "coinbase inc",
        "keywords": ["coinbase"],
        "known_domains": ["coinbase.com"],
    },
    {
        "brand_id": "paypal",
        "canonical_domain": "paypal.com",
        "owner_terms": "paypal inc",
        "keywords": ["paypal"],
        "known_domains": ["paypal.com", "paypal.es"],
    },
    {
        "brand_id": "amazon",
        "canonical_domain": "amazon.com",
        "owner_terms": "amazon technologies inc",
        "keywords": ["amazon"],
        "known_domains": ["amazon.com", "amazon.es"],
    },
    {
        "brand_id": "microsoft",
        "canonical_domain": "microsoft.com",
        "owner_terms": "microsoft corporation",
        "keywords": ["microsoft", "outlook", "office365"],
        "known_domains": ["microsoft.com", "outlook.com", "office.com"],
    },
    {
        "brand_id": "google",
        "canonical_domain": "google.com",
        "owner_terms": "google llc",
        "keywords": ["google", "gmail"],
        "known_domains": ["google.com", "gmail.com"],
    },
    {
        "brand_id": "apple",
        "canonical_domain": "apple.com",
        "owner_terms": "apple inc",
        "keywords": ["apple", "icloud"],
        "known_domains": ["apple.com", "icloud.com"],
    },
    {
        "brand_id": "facebook",
        "canonical_domain": "facebook.com",
        "owner_terms": "meta platforms inc",
        "keywords": ["facebook", "meta"],
        "known_domains": ["facebook.com", "meta.com"],
    }
]

# ============================================================
# Marcas generales (sin whois detallado)
# ============================================================

GENERAL_BRANDS = [
    "instagram", "whatsapp",
    "outlook", "office365", "netflix", "spotify",
    "dropbox", "adobe",
    "dhl", "fedex", "ups", "correos", "gls",
    "seur", "mrw", "chronopost", "royalmail",
    "hermes", "dpd", "posteitaliane", "la poste", "usps"
]


def ensure_known_brands_index(client):
    """Crea el índice con el NUEVO mapping."""
    if client.indices.exists(index=INDEX_KNOWN_BRANDS):
        print("[known_brands] Ya existe")
        return

    mapping = {
        "settings": {
            "analysis": {
                "analyzer": {
                    "brand_analyzer": {
                        "type": "standard"
                    }
                }
            }
        },
        "mappings": {
            "properties": {
                # Nuevo campo
                "country_code": {"type": "keyword"},
                # Bolsa de términos de WHOIS / owner
                "owner_terms": {"type": "text", "analyzer": "brand_analyzer"},
                # Palabras clave asociadas a la marca
                "keywords": {"type": "text", "analyzer": "brand_analyzer"},
                # Dominios validados
                "known_domains": {"type": "keyword"}
            }
        }
    }

    client.indices.create(index=INDEX_KNOWN_BRANDS, body=mapping)
    print("[known_brands] Índice creado")


def _derive_country_code_from_domain(canonical_domain: str) -> str:
    """
    A partir de 'abanca.es' -> 'es'.
    Si el sufijo no es ccTLD de 2 letras (.com, .net, ...) -> ''.
    """
    if not canonical_domain:
        return ""
    parts = canonical_domain.lower().split(".")
    if len(parts) < 2:
        return ""
    suffix = parts[-1]
    if len(suffix) == 2:
        return suffix
    return ""


def insert_brand(client, brand):
    """Inserta o actualiza una marca con el NUEVO formato."""

    canonical = brand.get("canonical_domain", "")
    derived_cc = _derive_country_code_from_domain(canonical)

    body = {
        "country_code": brand.get("country_code", derived_cc),
        "owner_terms": brand["owner_terms"],
        "keywords": brand["keywords"],
        "known_domains": brand["known_domains"]
    }

    client.index(
        index=INDEX_KNOWN_BRANDS,
        id=brand["brand_id"],
        body=body
    )
    print(f"[+] Insertado {brand['brand_id']} -> {body}")


def main():
    print("Conectando a OpenSearch...")
    client = OpenSearch(
        hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
        http_compress=True
    )

    ensure_known_brands_index(client)

    # Insertar bancos / marcas “grandes”
    for b in BANK_BRANDS:
        insert_brand(client, b)

    # Insertar marcas generales (sin owner_terms detallado, country_code = "")
    for name in GENERAL_BRANDS:
        doc = {
            "brand_id": name,
            "canonical_domain": name + ".com",  # solo para derivar cc (será "")
            "owner_terms": name,
            "keywords": [name],
            "known_domains": [name + ".com"]
        }
        insert_brand(client, doc)

    print("\n✅ Seed de known_brands completado.")


if __name__ == "__main__":
    main()
